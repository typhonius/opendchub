/*  Open DC Hub - A Linux/Unix version of the Direct Connect hub.
 *  Copyright (C) 2002,2003  Jonatan Nilsson
 *  Copyright (C) 2026  Adam Malone
 *
 *  JSON socket interface for gateway communication.
 *  Replaces the plaintext TCP admin port with a Unix domain socket
 *  speaking length-prefixed JSON.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#include "main.h"
#include "utils.h"
#include "network.h"
#include "commands.h"
#include "fileio.h"
#include "json_socket.h"
#include "cJSON.h"

/* Configuration globals */
char json_socket_path[MAX_JSON_SOCK_PATH] = "";
char json_socket_secret[MAX_JSON_SECRET_LEN] = "";
int  json_socket_enabled = 0;

/* Socket state */
int  json_listen_sock = -1;
int  json_client_sock = -1;
int  json_client_authed = 0;

/* Receive buffer for partial reads */
static char *recv_buf = NULL;
static int   recv_buf_len = 0;
static int   recv_buf_cap = 0;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/* Write exactly n bytes to a file descriptor. Returns 0 on success. */
static int write_all(int fd, const char *buf, int len)
{
   int sent = 0;
   while (sent < len) {
      int n = write(fd, buf + sent, len - sent);
      if (n < 0) {
         if (errno == EINTR) continue;
         return -1;
      }
      sent += n;
   }
   return 0;
}

/* Send a length-prefixed JSON message. Frame: 4-byte big-endian length + payload. */
static int send_json_msg(int fd, const char *json, int json_len)
{
   uint32_t net_len = htonl((uint32_t)json_len);
   if (write_all(fd, (const char *)&net_len, 4) != 0)
      return -1;
   if (write_all(fd, json, json_len) != 0)
      return -1;
   return 0;
}

/* Ensure recv_buf has at least `needed` bytes of capacity. */
static int recv_buf_ensure(int needed)
{
   if (recv_buf_cap >= needed)
      return 0;
   int new_cap = needed < 4096 ? 4096 : needed;
   if (new_cap > MAX_JSON_MSG_SIZE + 4) {
      logprintf(1, "JSON socket: message too large (%d bytes)\n", needed);
      return -1;
   }
   char *new_buf = realloc(recv_buf, new_cap);
   if (new_buf == NULL) {
      logprintf(1, "Error - json_socket recv_buf realloc failed\n");
      return -1;
   }
   recv_buf = new_buf;
   recv_buf_cap = new_cap;
   return 0;
}

/* Reset the receive buffer state (on disconnect). */
static void recv_buf_reset(void)
{
   free(recv_buf);
   recv_buf = NULL;
   recv_buf_len = 0;
   recv_buf_cap = 0;
}

/* Disconnect the current JSON client. */
static void disconnect_client(void)
{
   if (json_client_sock >= 0) {
      close(json_client_sock);
      json_client_sock = -1;
   }
   json_client_authed = 0;
   recv_buf_reset();
   logprintf(1, "JSON socket: gateway client disconnected\n");
}

/* ------------------------------------------------------------------ */
/* Command dispatch                                                    */
/* ------------------------------------------------------------------ */

/* Escape a string for NMDC (strip | and $). Returns a malloc'd string. */
static char *nmdc_sanitize(const char *input)
{
   if (input == NULL) return strdup("");
   int len = strlen(input);
   char *out = malloc(len + 1);
   if (out == NULL) return strdup("");
   int j = 0;
   for (int i = 0; i < len; i++) {
      if (input[i] != '|' && input[i] != '$')
         out[j++] = input[i];
   }
   out[j] = '\0';
   return out;
}

/* Handle a parsed JSON command from the gateway. */
static void handle_json_command(cJSON *root)
{
   cJSON *type_obj = cJSON_GetObjectItemCaseSensitive(root, "type");
   if (!cJSON_IsString(type_obj) || type_obj->valuestring == NULL)
      return;

   const char *type = type_obj->valuestring;

   /* Authentication */
   if (strcmp(type, "auth") == 0) {
      cJSON *secret = cJSON_GetObjectItemCaseSensitive(root, "secret");
      if (cJSON_IsString(secret) && secret->valuestring != NULL
          && secure_strcmp(secret->valuestring, json_socket_secret) == 0) {
         json_client_authed = 1;
         json_send_event("{\"type\":\"auth_ok\"}");
         logprintf(1, "JSON socket: gateway authenticated\n");
      } else {
         json_send_event("{\"type\":\"auth_failed\"}");
         logprintf(1, "JSON socket: gateway auth failed\n");
         disconnect_client();
      }
      return;
   }

   /* All other commands require authentication */
   if (!json_client_authed) {
      json_send_event("{\"type\":\"error\",\"message\":\"not authenticated\"}");
      return;
   }

   /* Kick user */
   if (strcmp(type, "kick") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      if (cJSON_IsString(nick) && nick->valuestring != NULL) {
         struct user_t *user = get_human_user(nick->valuestring);
         if (user != NULL) {
            user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
            logprintf(3, "JSON socket: kicked user %s\n", nick->valuestring);
         }
      }
   }

   /* Ban entry — uses ballow(buf, BAN, NULL) which adds to banlist */
   else if (strcmp(type, "ban") == 0) {
      cJSON *entry = cJSON_GetObjectItemCaseSensitive(root, "entry");
      if (cJSON_IsString(entry) && entry->valuestring != NULL) {
         char cmd[512];
         snprintf(cmd, sizeof(cmd), "%s", entry->valuestring);
         ballow(cmd, BAN, NULL);
         logprintf(3, "JSON socket: added ban entry %s\n", entry->valuestring);
      }
   }

   /* Unban — uses unballow(buf, BAN) */
   else if (strcmp(type, "unban") == 0) {
      cJSON *entry = cJSON_GetObjectItemCaseSensitive(root, "entry");
      if (cJSON_IsString(entry) && entry->valuestring != NULL) {
         char cmd[512];
         snprintf(cmd, sizeof(cmd), "%s", entry->valuestring);
         unballow(cmd, BAN);
         logprintf(3, "JSON socket: removed ban entry %s\n", entry->valuestring);
      }
   }

   /* Gag user — uses ballow(buf, GAG, NULL) */
   else if (strcmp(type, "gag") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      if (cJSON_IsString(nick) && nick->valuestring != NULL) {
         char cmd[256];
         snprintf(cmd, sizeof(cmd), "%s", nick->valuestring);
         ballow(cmd, GAG, NULL);
         struct user_t *user = get_human_user(nick->valuestring);
         if (user != NULL)
            user->gag = 1;
         logprintf(3, "JSON socket: gagged %s\n", nick->valuestring);
      }
   }

   /* Ungag user */
   else if (strcmp(type, "ungag") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      if (cJSON_IsString(nick) && nick->valuestring != NULL) {
         char cmd[256];
         snprintf(cmd, sizeof(cmd), "%s", nick->valuestring);
         unballow(cmd, GAG);
         struct user_t *user = get_human_user(nick->valuestring);
         if (user != NULL)
            user->gag = 0;
         logprintf(3, "JSON socket: ungagged %s\n", nick->valuestring);
      }
   }

   /* Send message to all human users */
   else if (strcmp(type, "send_all") == 0) {
      cJSON *msg = cJSON_GetObjectItemCaseSensitive(root, "message");
      if (cJSON_IsString(msg) && msg->valuestring != NULL) {
         char *safe = nmdc_sanitize(msg->valuestring);
         char *buf = malloc(strlen(safe) + 4);
         if (buf != NULL) {
            sprintf(buf, "%s|", safe);
            send_to_humans(buf, REGULAR | REGISTERED | OP | OP_ADMIN, NULL);
            free(buf);
         }
         free(safe);
      }
   }

   /* Send private message to specific user */
   else if (strcmp(type, "send_to") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      cJSON *msg = cJSON_GetObjectItemCaseSensitive(root, "message");
      if (cJSON_IsString(nick) && cJSON_IsString(msg)
          && nick->valuestring != NULL && msg->valuestring != NULL) {
         struct user_t *user = get_human_user(nick->valuestring);
         if (user != NULL) {
            char *safe = nmdc_sanitize(msg->valuestring);
            /* Send as hub PM: $To: nick From: Hub-Security $<Hub-Security> message| */
            int buf_len = strlen(nick->valuestring) + strlen(safe) + 100;
            char *buf = malloc(buf_len);
            if (buf != NULL) {
               snprintf(buf, buf_len,
                  "$To: %s From: Hub-Security $<Hub-Security> %s|",
                  nick->valuestring, safe);
               send_to_user(buf, user);
               free(buf);
            }
            free(safe);
         }
      }
   }

   /* Get hub status */
   else if (strcmp(type, "get_status") == 0) {
      json_send_status();
   }

   /* Get user list */
   else if (strcmp(type, "get_user_list") == 0) {
      json_send_user_list();
   }

   /* Register a user in the hub reglist.
    * add_reg_user() expects "$AddRegUser nick pass type" and a user pointer. */
   else if (strcmp(type, "register_user") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      cJSON *pass = cJSON_GetObjectItemCaseSensitive(root, "password");
      cJSON *perm = cJSON_GetObjectItemCaseSensitive(root, "permission");
      if (cJSON_IsString(nick) && cJSON_IsString(pass) && cJSON_IsNumber(perm)) {
         int ptype = perm->valueint;
         if (ptype < 0) ptype = 0;
         if (ptype > 3) ptype = 3;
         char cmd[512];
         snprintf(cmd, sizeof(cmd), "$AddRegUser %s %s %d",
                  nick->valuestring, pass->valuestring, ptype);
         add_reg_user(cmd, NULL);
         logprintf(3, "JSON socket: registered user %s (type %d)\n",
                   nick->valuestring, ptype);
      }
   }

   /* Unregister a user.
    * remove_reg_user() expects the nick string and a user pointer. */
   else if (strcmp(type, "unregister_user") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      if (cJSON_IsString(nick) && nick->valuestring != NULL) {
         remove_reg_user(nick->valuestring, NULL);
         logprintf(3, "JSON socket: unregistered user %s\n", nick->valuestring);
      }
   }

   else {
      logprintf(2, "JSON socket: unknown command type '%s'\n", type);
   }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int json_socket_init(void)
{
   struct sockaddr_un addr;
   int flags;

   if (!json_socket_enabled || json_socket_path[0] == '\0')
      return 0;

   /* Remove stale socket file */
   unlink(json_socket_path);

   json_listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
   if (json_listen_sock < 0) {
      logprintf(1, "Error - json_socket_init()/socket(): %s\n", strerror(errno));
      return -1;
   }

   memset(&addr, 0, sizeof(addr));
   addr.sun_family = AF_UNIX;
   strncpy(addr.sun_path, json_socket_path, sizeof(addr.sun_path) - 1);

   if (bind(json_listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      logprintf(1, "Error - json_socket_init()/bind(%s): %s\n",
                json_socket_path, strerror(errno));
      close(json_listen_sock);
      json_listen_sock = -1;
      return -1;
   }

   /* Restrict permissions: owner only */
   chmod(json_socket_path, 0600);

   if (listen(json_listen_sock, 1) < 0) {
      logprintf(1, "Error - json_socket_init()/listen(): %s\n", strerror(errno));
      close(json_listen_sock);
      json_listen_sock = -1;
      unlink(json_socket_path);
      return -1;
   }

   /* Set non-blocking */
   flags = fcntl(json_listen_sock, F_GETFL, 0);
   if (flags >= 0)
      fcntl(json_listen_sock, F_SETFL, flags | O_NONBLOCK);

   logprintf(1, "JSON socket listening on %s\n", json_socket_path);
   return 0;
}

void json_socket_cleanup(void)
{
   if (json_client_sock >= 0) {
      close(json_client_sock);
      json_client_sock = -1;
   }
   json_client_authed = 0;
   recv_buf_reset();

   if (json_listen_sock >= 0) {
      close(json_listen_sock);
      json_listen_sock = -1;
   }
   if (json_socket_path[0] != '\0')
      unlink(json_socket_path);
}

void json_socket_accept(void)
{
   int new_sock;
   int flags;

   new_sock = accept(json_listen_sock, NULL, NULL);
   if (new_sock < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK)
         logprintf(1, "Error - json_socket_accept(): %s\n", strerror(errno));
      return;
   }

   /* Only one gateway client at a time */
   if (json_client_sock >= 0) {
      logprintf(1, "JSON socket: rejecting second client (one already connected)\n");
      close(new_sock);
      return;
   }

   /* Set non-blocking */
   flags = fcntl(new_sock, F_GETFL, 0);
   if (flags >= 0)
      fcntl(new_sock, F_SETFL, flags | O_NONBLOCK);

   json_client_sock = new_sock;
   json_client_authed = 0;
   recv_buf_reset();
   logprintf(1, "JSON socket: gateway client connected\n");
}

int json_socket_handle_data(void)
{
   char tmp[4096];
   int n;

   if (json_client_sock < 0)
      return -1;

   n = read(json_client_sock, tmp, sizeof(tmp));
   if (n <= 0) {
      if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
         disconnect_client();
         return -1;
      }
      return 0;
   }

   /* Append to receive buffer */
   if (recv_buf_ensure(recv_buf_len + n) != 0) {
      disconnect_client();
      return -1;
   }
   memcpy(recv_buf + recv_buf_len, tmp, n);
   recv_buf_len += n;

   /* Process complete messages (4-byte length prefix + payload) */
   while (recv_buf_len >= 4) {
      uint32_t msg_len;
      memcpy(&msg_len, recv_buf, 4);
      msg_len = ntohl(msg_len);

      if (msg_len > MAX_JSON_MSG_SIZE) {
         logprintf(1, "JSON socket: message too large (%u bytes)\n", msg_len);
         disconnect_client();
         return -1;
      }

      if ((int)(4 + msg_len) > recv_buf_len)
         break; /* incomplete message, wait for more data */

      /* Extract and parse the JSON message */
      char *json_str = malloc(msg_len + 1);
      if (json_str == NULL) {
         disconnect_client();
         return -1;
      }
      memcpy(json_str, recv_buf + 4, msg_len);
      json_str[msg_len] = '\0';

      /* Shift the buffer */
      int consumed = 4 + msg_len;
      recv_buf_len -= consumed;
      if (recv_buf_len > 0)
         memmove(recv_buf, recv_buf + consumed, recv_buf_len);

      /* Parse JSON */
      cJSON *root = cJSON_Parse(json_str);
      if (root != NULL) {
         handle_json_command(root);
         cJSON_Delete(root);
      } else {
         logprintf(2, "JSON socket: failed to parse message: %.100s\n", json_str);
      }
      free(json_str);
   }

   return 0;
}

void json_send_event(const char *json_str)
{
   if (json_client_sock < 0 || !json_client_authed) {
      logprintf(4, "JSON socket: skipping event (sock=%d, authed=%d)\n",
                json_client_sock, json_client_authed);
      return;
   }

   int len = strlen(json_str);
   if (send_json_msg(json_client_sock, json_str, len) != 0) {
      logprintf(2, "JSON socket: send failed, disconnecting gateway\n");
      disconnect_client();
   }
}

/* ------------------------------------------------------------------ */
/* Event emitters                                                      */
/* ------------------------------------------------------------------ */

void json_event_chat(const char *nick, const char *message)
{
   logprintf(4, "json_event_chat called: nick=%s, sock=%d, authed=%d\n",
             nick ? nick : "(null)", json_client_sock, json_client_authed);
   if (json_client_sock < 0 || !json_client_authed)
      return;

   cJSON *root = cJSON_CreateObject();
   cJSON_AddStringToObject(root, "type", "chat");
   cJSON_AddStringToObject(root, "nick", nick ? nick : "");
   cJSON_AddStringToObject(root, "message", message ? message : "");
   cJSON_AddNumberToObject(root, "ts", (double)time(NULL));

   char *str = cJSON_PrintUnformatted(root);
   if (str != NULL) {
      json_send_event(str);
      free(str);
   }
   cJSON_Delete(root);
}

void json_event_user_join(const char *nick, const char *ip, int tls)
{
   if (json_client_sock < 0 || !json_client_authed)
      return;

   cJSON *root = cJSON_CreateObject();
   cJSON_AddStringToObject(root, "type", "user_join");
   cJSON_AddStringToObject(root, "nick", nick ? nick : "");
   cJSON_AddStringToObject(root, "ip", ip ? ip : "");
   cJSON_AddBoolToObject(root, "tls", tls);
   cJSON_AddNumberToObject(root, "ts", (double)time(NULL));

   char *str = cJSON_PrintUnformatted(root);
   if (str != NULL) {
      json_send_event(str);
      free(str);
   }
   cJSON_Delete(root);
}

void json_event_user_quit(const char *nick)
{
   if (json_client_sock < 0 || !json_client_authed)
      return;

   cJSON *root = cJSON_CreateObject();
   cJSON_AddStringToObject(root, "type", "user_quit");
   cJSON_AddStringToObject(root, "nick", nick ? nick : "");
   cJSON_AddNumberToObject(root, "ts", (double)time(NULL));

   char *str = cJSON_PrintUnformatted(root);
   if (str != NULL) {
      json_send_event(str);
      free(str);
   }
   cJSON_Delete(root);
}

void json_event_myinfo(const char *nick, const char *description,
                       const char *speed, const char *email,
                       long long share)
{
   if (json_client_sock < 0 || !json_client_authed)
      return;

   cJSON *root = cJSON_CreateObject();
   cJSON_AddStringToObject(root, "type", "myinfo");
   cJSON_AddStringToObject(root, "nick", nick ? nick : "");
   cJSON_AddStringToObject(root, "description", description ? description : "");
   cJSON_AddStringToObject(root, "speed", speed ? speed : "");
   cJSON_AddStringToObject(root, "email", email ? email : "");
   cJSON_AddNumberToObject(root, "share", (double)share);
   cJSON_AddNumberToObject(root, "ts", (double)time(NULL));

   char *str = cJSON_PrintUnformatted(root);
   if (str != NULL) {
      json_send_event(str);
      free(str);
   }
   cJSON_Delete(root);
}

void json_event_kick(const char *nick, const char *by)
{
   if (json_client_sock < 0 || !json_client_authed)
      return;

   cJSON *root = cJSON_CreateObject();
   cJSON_AddStringToObject(root, "type", "kick");
   cJSON_AddStringToObject(root, "nick", nick ? nick : "");
   cJSON_AddStringToObject(root, "by", by ? by : "");
   cJSON_AddNumberToObject(root, "ts", (double)time(NULL));

   char *str = cJSON_PrintUnformatted(root);
   if (str != NULL) {
      json_send_event(str);
      free(str);
   }
   cJSON_Delete(root);
}

void json_event_search(const char *nick, const char *query)
{
   if (json_client_sock < 0 || !json_client_authed)
      return;

   cJSON *root = cJSON_CreateObject();
   cJSON_AddStringToObject(root, "type", "search");
   cJSON_AddStringToObject(root, "nick", nick ? nick : "");
   cJSON_AddStringToObject(root, "query", query ? query : "");
   cJSON_AddNumberToObject(root, "ts", (double)time(NULL));

   char *str = cJSON_PrintUnformatted(root);
   if (str != NULL) {
      json_send_event(str);
      free(str);
   }
   cJSON_Delete(root);
}

void json_send_status(void)
{
   if (json_client_sock < 0 || !json_client_authed)
      return;

   long long share = get_total_share();

   int user_count = count_users(REGULAR | REGISTERED | OP | OP_ADMIN);
   time_t uptime = time(NULL) - hub_start_time;

   cJSON *root = cJSON_CreateObject();
   cJSON_AddStringToObject(root, "type", "status");
   cJSON_AddStringToObject(root, "hub_name", hub_name);
   cJSON_AddNumberToObject(root, "users", (double)user_count);
   cJSON_AddNumberToObject(root, "share", (double)share);
   cJSON_AddNumberToObject(root, "uptime", (double)uptime);
   cJSON_AddNumberToObject(root, "hub_port", (double)listening_port);
#ifdef HAVE_SSL
   cJSON_AddNumberToObject(root, "tls_port", (double)tls_port);
#else
   cJSON_AddNumberToObject(root, "tls_port", 0);
#endif
   cJSON_AddNumberToObject(root, "max_users", (double)max_users);

   char *str = cJSON_PrintUnformatted(root);
   if (str != NULL) {
      json_send_event(str);
      free(str);
   }
   cJSON_Delete(root);
}

void json_send_user_list(void)
{
   if (json_client_sock < 0 || !json_client_authed)
      return;

   cJSON *root = cJSON_CreateObject();
   cJSON_AddStringToObject(root, "type", "user_list");
   cJSON *users_arr = cJSON_AddArrayToObject(root, "users");

   struct sock_t *human = human_sock_list;
   while (human != NULL) {
      struct user_t *u = human->user;
      if (u != NULL && (u->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0) {
         cJSON *entry = cJSON_CreateObject();
         cJSON_AddStringToObject(entry, "nick", u->nick);

         char ip_str[INET_ADDRSTRLEN];
         struct in_addr addr;
         addr.s_addr = u->ip;
         inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
         cJSON_AddStringToObject(entry, "ip", ip_str);

         cJSON_AddNumberToObject(entry, "share", (double)u->share);

         const char *type_str = "REGULAR";
         if (u->type & OP_ADMIN) type_str = "OP_ADMIN";
         else if (u->type & OP) type_str = "OP";
         else if (u->type & REGISTERED) type_str = "REGISTERED";
         cJSON_AddStringToObject(entry, "type", type_str);

         cJSON_AddStringToObject(entry, "description",
                                 u->desc ? u->desc : "");
         cJSON_AddStringToObject(entry, "email",
                                 u->email ? u->email : "");

         /* Speed is derived from con_type */
         const char *speed = "";
         switch(u->con_type) {
            case 1: speed = "28.8Kbps"; break;
            case 2: speed = "33.6Kbps"; break;
            case 3: speed = "56Kbps"; break;
            case 4: speed = "Satellite"; break;
            case 5: speed = "ISDN"; break;
            case 6: speed = "DSL"; break;
            case 7: speed = "Cable"; break;
            case 8: speed = "LAN(T1)"; break;
            case 9: speed = "LAN(T3)"; break;
            case 10: speed = "Wireless"; break;
            case 11: speed = "Modem"; break;
            case 12: speed = "Netlimiter"; break;
            default: speed = "Unknown"; break;
         }
         cJSON_AddStringToObject(entry, "speed", speed);

#ifdef HAVE_SSL
         cJSON_AddBoolToObject(entry, "tls", u->ssl != NULL);
#else
         cJSON_AddBoolToObject(entry, "tls", 0);
#endif

         cJSON_AddItemToArray(users_arr, entry);
      }
      human = human->next;
   }

   char *str = cJSON_PrintUnformatted(root);
   if (str != NULL) {
      json_send_event(str);
      free(str);
   }
   cJSON_Delete(root);
}
