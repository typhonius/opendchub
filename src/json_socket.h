/*  Open DC Hub - A Linux/Unix version of the Direct Connect hub.
 *  Copyright (C) 2002,2003  Jonatan Nilsson
 *  Copyright (C) 2026  Adam Malone
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef JSON_SOCKET_H
#define JSON_SOCKET_H

/* Maximum length of the gateway socket path */
#define MAX_JSON_SOCK_PATH 108

/* Maximum length of the shared secret */
#define MAX_JSON_SECRET_LEN 128

/* Maximum JSON message size (1MB) */
#define MAX_JSON_MSG_SIZE (1024 * 1024)

/* Configuration globals */
extern char json_socket_path[MAX_JSON_SOCK_PATH];
extern char json_socket_secret[MAX_JSON_SECRET_LEN];
extern int  json_socket_enabled;

/* File descriptor for the listening Unix socket */
extern int  json_listen_sock;

/* File descriptor for the connected gateway client (-1 if none) */
extern int  json_client_sock;

/* Whether the connected client has authenticated */
extern int  json_client_authed;

/* Initialize the JSON socket listener. Creates the Unix domain socket
 * at the configured path. Returns 0 on success, -1 on failure.
 * Should be called from the parent process only. */
int  json_socket_init(void);

/* Clean up the JSON socket. Closes connections and removes the socket file. */
void json_socket_cleanup(void);

/* Accept a new connection on the JSON listener socket.
 * Only one client is allowed at a time (the gateway). */
void json_socket_accept(void);

/* Handle incoming data on the connected JSON client socket.
 * Reads length-prefixed JSON messages and dispatches them.
 * Returns 0 on success, -1 if the client should be disconnected. */
int  json_socket_handle_data(void);

/* Send a JSON event to the connected gateway client.
 * The message is length-prefixed (4 bytes big-endian + JSON payload).
 * No-op if no authenticated client is connected. */
void json_send_event(const char *json_str);

/* Convenience functions to emit specific event types.
 * These build the JSON and call json_send_event(). */
void json_event_chat(const char *nick, const char *message);
void json_event_user_join(const char *nick, const char *ip, int tls);
void json_event_user_quit(const char *nick);
void json_event_myinfo(const char *nick, const char *description,
                       const char *speed, const char *email,
                       long long share);
void json_event_kick(const char *nick, const char *by);
void json_event_search(const char *nick, const char *query);
void json_event_pm(const char *from_nick, const char *to_nick,
                   const char *message);

/* Send hub status as a JSON event (response to get_status command). */
void json_send_status(void);

/* Send user list as a JSON event (response to get_user_list command). */
void json_send_user_list(void);

/* Clean up all virtual users (called on gateway disconnect). */
void json_cleanup_virtual_users(void);

#endif /* JSON_SOCKET_H */
