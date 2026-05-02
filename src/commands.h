/*  Open DC Hub - A Linux/Unix version of the Direct Connect hub.
 *  Copyright (C) 2002,2003  Jonatan Nilsson
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


void   sr(char *buf, struct user_t *user);
void   get_info(char *buf, struct user_t *user);
void   to_from(char *buf, struct user_t *user);
void   connect_to_me(char *buf, struct user_t *user);
void   rev_connect_to_me(char *buf, struct user_t *user);
void   chat(char *buf, struct user_t *user);
void   search(char *buf, struct user_t *user);
int    my_info(char *buf, struct user_t *user);
void   send_nick_list(struct user_t *user);
int    validate_nick(char *buf, struct user_t *user);
int    version(char *buf, struct user_t *user);
int    my_pass(char *buf, struct user_t *user);
void   kick(char *buf, struct user_t *user, int tempban);
void   forward_to_clients(char *buf, struct user_t *user);
void   quit_program(void);
void   multi_search(char *buf, struct user_t *user);
void   multi_connect_to_me(char *buf, struct user_t *user);
void   disc_user(char *buf, struct user_t *user);
