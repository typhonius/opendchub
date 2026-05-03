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
#include "userlist.h"
#include "cJSON.h"

/* Configuration globals */
char json_socket_path[MAX_JSON_SOCK_PATH] = "";
char json_socket_secret[MAX_JSON_SECRET_LEN] = "";
int  json_socket_enabled = 0;

/* Socket state */
int  json_listen_sock = -1;
int  json_client_sock = -1;
int  json_client_authed = 0;

/* Virtual user tracking — gateway-managed users with no real NMDC connection */
#define MAX_VIRTUAL_USERS 16
static struct user_t *virtual_users[MAX_VIRTUAL_USERS];
static int virtual_user_count = 0;

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

/* Disconnect the current JSON client and clean up virtual users. */
static void disconnect_client(void)
{
   if (json_client_sock >= 0) {
      close(json_client_sock);
      json_client_sock = -1;
   }
   json_client_authed = 0;
   recv_buf_reset();
   json_cleanup_virtual_users();
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

   /* Purge stale connections — remove users stuck in NMDC handshake.
    * Called periodically by the gateway's maintenance tick. */
   else if (strcmp(type, "purge_stale") == 0) {
      struct sock_t *human_user = human_sock_list;
      int purged = 0;
      while (human_user != NULL) {
         if ((human_user->user->type & (UNKEYED | NON_LOGGED)) != 0) {
            logprintf(2, "Purging stale connection at %s\n",
                      human_user->user->hostname);
            human_user->user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
            purged++;
         }
         human_user = human_user->next;
      }
      if (purged > 0)
         logprintf(3, "JSON socket: purged %d stale connection(s)\n", purged);
   }

   /* Add a hub to the in-memory linked hub list. */
   else if (strcmp(type, "add_linked_hub") == 0) {
      cJSON *ip_j = cJSON_GetObjectItemCaseSensitive(root, "ip");
      cJSON *port_j = cJSON_GetObjectItemCaseSensitive(root, "port");
      if (cJSON_IsString(ip_j) && cJSON_IsNumber(port_j)) {
         int ret = add_linked_hub_entry(ip_j->valuestring, port_j->valueint);
         if (ret == 1)
            logprintf(3, "JSON socket: added linked hub %s:%d\n",
                      ip_j->valuestring, port_j->valueint);
      }
   }

   /* Remove a hub from the in-memory linked hub list. */
   else if (strcmp(type, "remove_linked_hub") == 0) {
      cJSON *ip_j = cJSON_GetObjectItemCaseSensitive(root, "ip");
      cJSON *port_j = cJSON_GetObjectItemCaseSensitive(root, "port");
      if (cJSON_IsString(ip_j) && cJSON_IsNumber(port_j)) {
         int ret = remove_linked_hub_entry(ip_j->valuestring, port_j->valueint);
         if (ret == 1)
            logprintf(3, "JSON socket: removed linked hub %s:%d\n",
                      ip_j->valuestring, port_j->valueint);
      }
   }

   /* Send a public chat message as a specific nick (virtual user) */
   else if (strcmp(type, "send_chat_as") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      cJSON *msg = cJSON_GetObjectItemCaseSensitive(root, "message");
      if (cJSON_IsString(nick) && cJSON_IsString(msg)
          && nick->valuestring != NULL && msg->valuestring != NULL) {
         char *safe_nick = nmdc_sanitize(nick->valuestring);
         char *safe_msg = nmdc_sanitize(msg->valuestring);
         int buf_len = strlen(safe_nick) + strlen(safe_msg) + 8;
         char *buf = malloc(buf_len);
         if (buf != NULL) {
            snprintf(buf, buf_len, "<%s> %s|", safe_nick, safe_msg);
            send_to_humans(buf, REGULAR | REGISTERED | OP | OP_ADMIN, NULL);
            send_to_non_humans(buf, FORKED, NULL);
            free(buf);
         }
         json_event_chat(nick->valuestring, msg->valuestring);
         free(safe_nick);
         free(safe_msg);
      }
   }

   /* Send a PM from a virtual user to a specific real user */
   else if (strcmp(type, "send_pm_as") == 0) {
      cJSON *from = cJSON_GetObjectItemCaseSensitive(root, "from");
      cJSON *to = cJSON_GetObjectItemCaseSensitive(root, "to");
      cJSON *msg = cJSON_GetObjectItemCaseSensitive(root, "message");
      if (cJSON_IsString(from) && cJSON_IsString(to) && cJSON_IsString(msg)
          && from->valuestring != NULL && to->valuestring != NULL
          && msg->valuestring != NULL) {
         struct user_t *user = get_human_user(to->valuestring);
         if (user != NULL && user->sock >= 0) {
            char *safe_msg = nmdc_sanitize(msg->valuestring);
            int buf_len = strlen(from->valuestring) * 2
                        + strlen(to->valuestring) + strlen(safe_msg) + 32;
            char *buf = malloc(buf_len);
            if (buf != NULL) {
               snprintf(buf, buf_len,
                  "$To: %s From: %s $<%s> %s|",
                  to->valuestring, from->valuestring,
                  from->valuestring, safe_msg);
               send_to_user(buf, user);
               free(buf);
            }
            free(safe_msg);
         }
      }
   }

   /* Send a chat-style message from a nick to a specific user only (not a PM,
    * appears in their main chat window). This is PUBLIC_SINGLE in v3 terms. */
   else if (strcmp(type, "send_to_as") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      cJSON *to = cJSON_GetObjectItemCaseSensitive(root, "to");
      cJSON *msg = cJSON_GetObjectItemCaseSensitive(root, "message");
      if (cJSON_IsString(nick) && cJSON_IsString(to) && cJSON_IsString(msg)
          && nick->valuestring != NULL && to->valuestring != NULL
          && msg->valuestring != NULL) {
         struct user_t *user = get_human_user(to->valuestring);
         if (user != NULL && user->sock >= 0) {
            char *safe_nick = nmdc_sanitize(nick->valuestring);
            char *safe_msg = nmdc_sanitize(msg->valuestring);
            int buf_len = strlen(safe_nick) + strlen(safe_msg) + 8;
            char *buf = malloc(buf_len);
            if (buf != NULL) {
               snprintf(buf, buf_len, "<%s> %s|", safe_nick, safe_msg);
               send_to_user(buf, user);
               free(buf);
            }
            free(safe_nick);
            free(safe_msg);
         }
      }
   }

   /* Send a raw NMDC string to all human users verbatim.
    * No sanitization — the "data" field is the exact protocol bytes to send.
    * Used by the gateway to echo chat messages and send protocol commands. */
   else if (strcmp(type, "send_raw") == 0) {
      cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
      if (cJSON_IsString(data) && data->valuestring != NULL) {
         send_to_humans(data->valuestring, REGULAR | REGISTERED | OP | OP_ADMIN, NULL);
         send_to_non_humans(data->valuestring, FORKED, NULL);
      }
   }

   /* Send a raw NMDC string to a specific user verbatim.
    * No sanitization — the "data" field is the exact protocol bytes to send.
    * Used by the gateway to send greetings, topic, gag notifications, etc. */
   else if (strcmp(type, "send_raw_to") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
      if (cJSON_IsString(nick) && cJSON_IsString(data)
          && nick->valuestring != NULL && data->valuestring != NULL) {
         struct user_t *user = get_human_user(nick->valuestring);
         if (user != NULL) {
            send_to_user(data->valuestring, user);
         }
      }
   }

   /* Add a virtual user (gateway-managed, no real NMDC connection) */
   else if (strcmp(type, "add_virtual_user") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      if (!cJSON_IsString(nick) || nick->valuestring == NULL)
         return;

      if (virtual_user_count >= MAX_VIRTUAL_USERS) {
         logprintf(1, "JSON socket: virtual user limit reached (%d)\n",
                   MAX_VIRTUAL_USERS);
         return;
      }
      {
         struct user_t *existing = get_human_user(nick->valuestring);
         if (existing != NULL) {
            if (existing->sock == -1) {
               /* Virtual user already exists — this is a re-registration
                * (e.g. bot was killed and restarted). Remove the old one
                * so we can create a fresh entry. */
               int vi;
               for (vi = 0; vi < virtual_user_count; vi++) {
                  if (virtual_users[vi] == existing) {
                     remove_user_from_list(existing->nick);
                     remove_human_from_hash(existing->nick);
                     if (existing->desc) free(existing->desc);
                     if (existing->email) free(existing->email);
                     free(existing);
                     virtual_users[vi] = virtual_users[--virtual_user_count];
                     virtual_users[virtual_user_count] = NULL;
                     break;
                  }
               }
               logprintf(2, "JSON socket: replaced existing virtual user '%s'\n",
                         nick->valuestring);
            } else {
               logprintf(2, "JSON socket: nick '%s' already in use by a real user\n",
                         nick->valuestring);
               return;
            }
         }
      }

      cJSON *desc_obj  = cJSON_GetObjectItemCaseSensitive(root, "description");
      cJSON *email_obj = cJSON_GetObjectItemCaseSensitive(root, "email");
      cJSON *tag_obj   = cJSON_GetObjectItemCaseSensitive(root, "tag");
      cJSON *share_obj = cJSON_GetObjectItemCaseSensitive(root, "share");
      cJSON *op_obj    = cJSON_GetObjectItemCaseSensitive(root, "op");

      struct user_t *vuser = calloc(1, sizeof(struct user_t));
      if (vuser == NULL) return;

      vuser->sock = -1;
      strncpy(vuser->nick, nick->valuestring, MAX_NICK_LEN);
      vuser->nick[MAX_NICK_LEN] = '\0';
      strncpy(vuser->hostname, "gateway", MAX_HOST_LEN);

      const char *desc_str  = (cJSON_IsString(desc_obj)  && desc_obj->valuestring)
                              ? desc_obj->valuestring : "";
      const char *email_str = (cJSON_IsString(email_obj) && email_obj->valuestring)
                              ? email_obj->valuestring : "";
      const char *tag_str   = (cJSON_IsString(tag_obj)   && tag_obj->valuestring)
                              ? tag_obj->valuestring : "<gateway V:1.0.0>";

      vuser->desc  = strdup(desc_str);
      vuser->email = strdup(email_str);
      vuser->share = cJSON_IsNumber(share_obj)
                     ? (long long)share_obj->valuedouble : 0;
      vuser->con_type = 8; /* LAN(T1) */
      vuser->type = cJSON_IsTrue(op_obj) ? OP : REGULAR;
      vuser->flag = 1;

      /* Add to hash table (PM routing) and shared memory (NickList) */
      add_human_to_hash(vuser);
      add_user_to_list(vuser);

      /* Track in our virtual user list */
      virtual_users[virtual_user_count++] = vuser;

      /* Broadcast join to all connected clients */
      char buf[512];
      snprintf(buf, sizeof(buf), "$Hello %s|", vuser->nick);
      send_to_humans(buf, REGULAR | REGISTERED | OP | OP_ADMIN, NULL);

      snprintf(buf, sizeof(buf),
         "$MyINFO $ALL %s %s%s$ $LAN(T1)\x01$%s$%lld$|",
         vuser->nick, desc_str, tag_str, email_str, vuser->share);
      send_to_humans(buf, REGULAR | REGISTERED | OP | OP_ADMIN, NULL);

      logprintf(1, "JSON socket: added virtual user '%s'\n", vuser->nick);
   }

   /* Remove a virtual user */
   else if (strcmp(type, "remove_virtual_user") == 0) {
      cJSON *nick = cJSON_GetObjectItemCaseSensitive(root, "nick");
      if (!cJSON_IsString(nick) || nick->valuestring == NULL)
         return;

      int i;
      for (i = 0; i < virtual_user_count; i++) {
         if (strcmp(virtual_users[i]->nick, nick->valuestring) == 0)
            break;
      }
      if (i >= virtual_user_count) return;

      struct user_t *vuser = virtual_users[i];

      /* Broadcast quit */
      char buf[MAX_NICK_LEN + 16];
      snprintf(buf, sizeof(buf), "$Quit %s|", vuser->nick);
      send_to_humans(buf, REGULAR | REGISTERED | OP | OP_ADMIN, NULL);
      json_event_user_quit(vuser->nick);

      /* Remove from hub data structures */
      remove_user_from_list(vuser->nick);
      remove_human_from_hash(vuser->nick);

      /* Free and compact array */
      if (vuser->desc)  free(vuser->desc);
      if (vuser->email) free(vuser->email);
      free(vuser);
      virtual_users[i] = virtual_users[--virtual_user_count];
      virtual_users[virtual_user_count] = NULL;

      logprintf(1, "JSON socket: removed virtual user '%s'\n",
                nick->valuestring);
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
   if (json_client_sock < 0 || !json_client_authed)
      return;

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

void json_event_pm(const char *from_nick, const char *to_nick,
                   const char *message)
{
   if (json_client_sock < 0 || !json_client_authed)
      return;

   cJSON *root = cJSON_CreateObject();
   cJSON_AddStringToObject(root, "type", "pm");
   cJSON_AddStringToObject(root, "from", from_nick ? from_nick : "");
   cJSON_AddStringToObject(root, "to", to_nick ? to_nick : "");
   cJSON_AddStringToObject(root, "message", message ? message : "");
   cJSON_AddNumberToObject(root, "ts", (double)time(NULL));

   char *str = cJSON_PrintUnformatted(root);
   if (str != NULL) {
      json_send_event(str);
      free(str);
   }
   cJSON_Delete(root);
}

void json_cleanup_virtual_users(void)
{
   int i;
   for (i = 0; i < virtual_user_count; i++) {
      struct user_t *vuser = virtual_users[i];
      if (vuser == NULL) continue;

      char buf[MAX_NICK_LEN + 16];
      snprintf(buf, sizeof(buf), "$Quit %s|", vuser->nick);
      send_to_humans(buf, REGULAR | REGISTERED | OP | OP_ADMIN, NULL);

      remove_user_from_list(vuser->nick);
      remove_human_from_hash(vuser->nick);

      if (vuser->desc)  free(vuser->desc);
      if (vuser->email) free(vuser->email);
      free(vuser);
      virtual_users[i] = NULL;
   }
   virtual_user_count = 0;
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

   /* Include virtual users */
   {
      int vi;
      for (vi = 0; vi < virtual_user_count; vi++) {
         struct user_t *u = virtual_users[vi];
         if (u == NULL) continue;

         cJSON *entry = cJSON_CreateObject();
         cJSON_AddStringToObject(entry, "nick", u->nick);
         cJSON_AddStringToObject(entry, "ip", "127.0.0.1");
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
         cJSON_AddStringToObject(entry, "speed", "LAN(T1)");
         cJSON_AddBoolToObject(entry, "tls", 0);
         cJSON_AddBoolToObject(entry, "virtual", 1);

         cJSON_AddItemToArray(users_arr, entry);
      }
   }

   char *str = cJSON_PrintUnformatted(root);
   if (str != NULL) {
      json_send_event(str);
      free(str);
   }
   cJSON_Delete(root);
}
