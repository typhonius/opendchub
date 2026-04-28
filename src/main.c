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



#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <signal.h>
#include <sys/un.h>
#include <errno.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif
#ifdef SWITCH_USER
# include <sys/capability.h>
# include <sys/prctl.h>
# include <pwd.h>
# include <grp.h>
#endif
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <stdarg.h>

#include "main.h"
#include "network.h"
#include "commands.h"
#include "utils.h"
#include "fileio.h"
#include "userlist.h"

#ifndef SIGCHLD
# define SIGCHLD SIGCLD
#endif

/* Global variable definitions (declared extern in main.h) */
pid_t  pid = 0;
int    users_per_fork = 0;
struct user_t *non_human_user_list = NULL;
struct user_t **human_hash_table = NULL;
struct sock_t *human_sock_list = NULL;
unsigned int listening_port = 0;
int    listening_socket = 0;
int    listening_unx_socket = 0;
int    listening_udp_socket = 0;
char   hub_name[MAX_HUB_NAME+1] = {0};
BYTE   debug = 0;
BYTE   registered_only = 0;
BYTE   hublist_upload = 0;
BYTE   ban_overrides_allow = 0;
BYTE   redir_on_min_share = 0;
BYTE   check_key = 0;
BYTE   reverse_dns = 0;
BYTE   verbosity = 0;
char   hub_description[MAX_HUB_DESC+1] = {0};
char   public_hub_host[MAX_HOST_LEN+1] = {0};
char   min_version[MAX_VERSION_LEN+1] = {0};
char   hub_hostname[MAX_HOST_LEN+1] = {0};
char   redirect_host[MAX_HOST_LEN+1] = {0};
char   *hub_full_mess = NULL;
int    max_users = 0;
int    max_sockets = 0;
long long min_share = 0;
int    total_share_shm = 0;
int    total_share_sem = 0;
int    user_list_shm_shm = 0;
int    user_list_sem = 0;
char   link_pass[MAX_ADMIN_PASS_LEN+1] = {0};
char   default_pass[MAX_ADMIN_PASS_LEN+1] = {0};
volatile sig_atomic_t   upload = 0;
volatile sig_atomic_t   quit = 0;
volatile sig_atomic_t   do_reload_conf = 0;
volatile sig_atomic_t   do_write = 0;
volatile sig_atomic_t   do_send_linked_hubs = 0;
volatile sig_atomic_t   do_purge_user_list = 0;
volatile sig_atomic_t   do_fork = 0;
volatile sig_atomic_t   do_alarm = 0;
char   config_dir[MAX_FDP_LEN+1] = {0};
char   un_sock_path[MAX_FDP_LEN+1] = {0};
char   logfile[MAX_FDP_LEN+1] = {0};
BYTE   syslog_enable = 0;
BYTE   syslog_switch = 0;
BYTE   log_format = 0;                    /* 0 = text (default), 1 = json */
char   log_file_path[MAX_HOST_LEN+1] = {0}; /* Alternative log file path */
BYTE   searchcheck_exclude_internal = 0;
BYTE   searchcheck_exclude_all = 0;
int    kick_bantime = 0;
int    searchspam_time = 0;
uid_t  dchub_user = 0;
gid_t  dchub_group = 0;
char   working_dir[MAX_FDP_LEN+1] = {0};
time_t hub_start_time = 0;
int    max_email_len = 0;
int    max_desc_len = 0;
BYTE   crypt_enable = 0;
int    current_forked = 0;

#ifdef HAVE_SSL
SSL_CTX *ssl_ctx = NULL;
unsigned int tls_port = 0;
int    tls_listening_socket = -1;
char   tls_cert_file[MAX_FDP_LEN+1] = {0};
char   tls_key_file[MAX_FDP_LEN+1] = {0};
#endif

/* Set default variables, used if config does not exist or is bad */
int set_default_vars(void)
{
   users_per_fork = 1000;
   min_share = 0;
   max_users = 1000;
   hublist_upload = 1;
   registered_only = 0;
   ban_overrides_allow = 0;
   check_key = 0;
   reverse_dns = 0;
   redirect_host[0] = '\0';
   searchcheck_exclude_internal = 1;
   searchcheck_exclude_all = 0;
   kick_bantime = 5;
   searchspam_time = 5;
   max_email_len = 50;
   max_desc_len = 100;
   crypt_enable = 1;
   printf("Enter port number to listen for connections. \nPorts below 1024 is only for root: ");
   scanf("%u", &listening_port);
   if(listening_port == 0)
     {
	printf("Bad port number\n");
	exit(EXIT_FAILURE);
     }
   printf("Listening Port set to %u\n\n", listening_port);
   snprintf(public_hub_host, sizeof(public_hub_host), "vandel405.dynip.com");
   min_version[0] = '\0';
   snprintf(hub_name, sizeof(hub_name), "Open DC Hub");
   snprintf(hub_description, sizeof(hub_description), "A Unix/Linux Direct Connect Hub");
   if((hub_full_mess = realloc(hub_full_mess, sizeof(char) * 50)) == NULL)
     {
	logprintf(1, "Error - In set_default_vars()/realloc(): ");
	logerror(1, errno);
	quit = 1;
	return 0;
     }
   snprintf(hub_full_mess, 50, "Sorry, this hub is full at the moment");
   snprintf(default_pass, sizeof(default_pass), "");
   printf("Please, supply a password for hub linking: ");
   scanf("%50s", link_pass);
   printf("Your Hub linking pass is set to %s\n\n", link_pass);
   return 1;
}

/* When all users have left a forked process, that process should be terminated */
void kill_forked_process(void)
{
   int erret;
   
   set_listening_pid(0);
   
   remove_all(0xFFFF, 1, 1);
   
   if(listening_socket != -1) 
     {	
	while(((erret =  close(listening_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In kill_forked_process()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In kill_forked_process()/close(): ");
	     logerror(1, errno);
	  }
     }
   
#ifdef HAVE_SSL
   if(tls_listening_socket != -1)
     {
	close(tls_listening_socket);
	tls_listening_socket = -1;
     }
#endif

   exit(EXIT_SUCCESS);
}


/* Accept connection from newly created forked process */
void new_forked_process(void)
{
   struct user_t *user;
   struct sockaddr_un remote_addr;
   int len, flags;
   
   memset(&remote_addr, 0, sizeof(struct sockaddr_un));
   /* Allocate space for the new user */
   if((user = malloc(sizeof(struct user_t))) == NULL)
     {	
	logprintf(1, "Error - In new_forked_process()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return;
     }      
   
   /* Get a new socket for the connected user */
   len = sizeof(struct sockaddr_un);
   while(((user->sock = accept(listening_unx_socket,
			       (struct sockaddr *)&remote_addr, &len)) < 0)
	 && (errno == EINTR))
     logprintf(1, "Error - In new_forked_process()/accept(): Interrupted system call. Trying again.\n");	
   
   if(user->sock < 0)
     {	
	logprintf(1, "Error - In new_forked_process()/accept(): ");
	logerror(1, errno);
	free(user);
	return;
     }
   
   if((flags = fcntl(user->sock, F_GETFL, 0)) < 0)
     {  
	logprintf(1, "Error - In new_forked_process()/in fcntl(): ");
	logerror(1, errno);
	close(user->sock);
	free(user);
	return;
     } 
   
   /* Non blocking mode */
   if(fcntl(user->sock, F_SETFL, flags | O_NONBLOCK) < 0)
     {
	logprintf(1, "Error - In new_forked_process()/in fcntl(): ");
	logerror(1, errno);
	close(user->sock);
	free(user);
	return;
     }
   
   
   user->type = FORKED;
   user->rem = 0;
   user->buf = NULL;
   user->outbuf = NULL;
#ifdef HAVE_SSL
   user->ssl = NULL;
   user->ssl_handshake_done = 0;
   user->ssl_handshake_start = (time_t)0;
#endif
   snprintf(user->hostname, sizeof(user->hostname), "forked_process");
   memset(user->nick, 0, MAX_NICK_LEN+1);

   /* Add the user at the first place in the list.  */
   add_non_human_to_list(user);
   
   logprintf(5, "Got new unix connection on sock %d\n", user->sock);
}
   

/* Create a new process */
void fork_process(void)
{
   int sock;
   int len;
   int erret;
   struct sockaddr_un remote_addr;
   struct user_t *user;
   int flags;

   memset(&remote_addr, 0, sizeof(struct sockaddr_un));
   if((pid = fork()) == -1)
     {
	logprintf(1, "Fork failed, exiting process\n");
	logerror(1, errno);
	quit = 1;
	return;
     }
   
   /* If we are the parent */
   if(pid > 0)
     {
	/* All users are removed from the parent */
	remove_all(UNKEYED | NON_LOGGED | REGULAR | REGISTERED | OP 
		   | OP_ADMIN, 1, 1);
	logprintf(5, "Forked new process, childs pid is %d and parents pid is %d\n", pid, getpid());
	/* And set current pid of process */
	pid = getpid();
     }
   
   /* And if we are the child */
   else
     {
	/* Close the listening sockets */
	while(((erret =  close(listening_unx_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In fork_process()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In fork_process()/close(): ");
	     logerror(1, errno);
	  }
	
	while(((erret =  close(listening_udp_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In fork_process()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In fork_process()/close(): ");
	     logerror(1, errno);
	  }
	
	/* Set the alarm */
	alarm(ALARM_TIME);
	
	/* And remove all connections to forked process. We only want 
	 * connections between parent and child, not between children. Also
	 * remove connections to other hubs, we let the parent take care of
	 * those.*/
	remove_all(LINKED | FORKED, 0, 0);
	
	/* If some other process already has opened the socket, we'll exit.  */
	if(set_listening_pid((int)getpid()) <= 0)
	  exit(EXIT_SUCCESS);
	
	/* Open the human listening sockets.  */
	if((listening_socket = get_listening_socket(listening_port, 0)) == -1)
	  {
	     logprintf(1, "Error - In fork_process(): Couldn't open listening socket\n");
	     quit = 1;
	  }
	
#ifdef HAVE_SSL
	if(tls_port != 0 && ssl_ctx != NULL)
	  {
	     if((tls_listening_socket = get_listening_socket(tls_port, 0)) == -1)
	       {
		  logprintf(1, "TLS listening socket disabled\n");
	       }
	  }
#endif

	/* And connect to parent process */
	if((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) 
	  {
	     logprintf(1, "Error - In fork_process()/socket(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }		
	
	remote_addr.sun_family = AF_UNIX;
	strncpy(remote_addr.sun_path, un_sock_path, sizeof(remote_addr.sun_path) - 1);
	remote_addr.sun_path[sizeof(remote_addr.sun_path) - 1] = '\0';
	len = strlen(remote_addr.sun_path) + sizeof(remote_addr.sun_family) + 1;
	if(connect(sock, (struct sockaddr *)&remote_addr, len) == -1)
	  {
	     logprintf(1, "Error - In fork_process()/connect(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	
	if((user = malloc(sizeof(struct user_t))) == NULL)
	  {	     
	     logprintf(1, "Error - In fork_process()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	
	user->sock = sock;
	user->type = FORKED;
	user->rem = 0;
	user->buf = NULL;
	user->outbuf = NULL;
#ifdef HAVE_SSL
	user->ssl = NULL;
	user->ssl_handshake_done = 0;
	user->ssl_handshake_start = (time_t)0;
#endif
	memset(user->nick, 0, MAX_NICK_LEN+1);
	snprintf(user->hostname, sizeof(user->hostname), "parent_process");

	if((flags = fcntl(user->sock, F_GETFL, 0)) < 0)
	  {     
	     logprintf(1, "Error - In fork_process()/in fcntl(): ");
	     logerror(1, errno);
	     close(user->sock);
	     free(user);
	     return;
	  }
	
	/* Non blocking mode */
	if(fcntl(user->sock, F_SETFL, flags | O_NONBLOCK) < 0)
	  {
	     logprintf(1, "Error - In fork_process()/in fcntl(): ");
	     logerror(1, errno);
	     close(user->sock);
	     free(user);
	     return;
	  }
	
	
	/* Add the user at the first place in the list */
	add_non_human_to_list(user);
     }
}

/* This function is used to move the listening socket to a process that has
 * room for more users. If no process have room, a new is forked.  */
void switch_listening_process(char *buf, struct user_t *user)
{
   int nbr_of_users;
   int forknbr = 0;
   struct user_t *non_human;
   int nbr_of_forked = 0;
   
   if(pid > 0)
     nbr_of_forked = count_users(FORKED);
   
   non_human = non_human_user_list;
   
   /* If a process has closed the listening sockets.  */
   if((pid > 0) && (strncmp(buf, "$ClosedListen", 13) == 0))
     {
	if(nbr_of_forked == 1)
	  {
	     do_fork = 1;
	     return;
	  }	
	current_forked = 1;
	while((non_human != NULL) 
	      && (non_human->type != FORKED)) 
	  non_human = non_human->next;
	send_to_user("$OpenListen|", non_human);
	current_forked++;
     }
   else if(strncmp(buf, "$OpenListen", 11) == 0)
     {
	/* Check if we want to accept new clients in this process.  */
	nbr_of_users = count_users(UNKEYED | NON_LOGGED | REGULAR
				   | REGISTERED | OP | OP_ADMIN | ADMIN);
	
	if((nbr_of_users < users_per_fork) 
	   && (nbr_of_users < (max_sockets-5)))
	  {
	     if(listening_socket == -1)
	       {
		  if(set_listening_pid((int)getpid()) > 0)
		    {
		       /* Open the listening sockets.  */
		       if((listening_socket = get_listening_socket(listening_port, 0)) == -1)
			 logprintf(1, "Error - In switch_listening_process(): Couldn't open listening socket\n");
		       
#ifdef HAVE_SSL
		       if(tls_port != 0 && ssl_ctx != NULL)
			 tls_listening_socket = get_listening_socket(tls_port, 0);
#endif
		    }
	       }
	  }
	else
	  send_to_user("$RejListen|", user);
     }
   
   /* If a process that couldn't take the listening sockets.  */
   else if((pid > 0) && (strncmp(buf, "$RejListen", 10) == 0))
     {
	if(current_forked > nbr_of_forked)
	  do_fork = 1;
	else
	  {	     
	     while(non_human != NULL)
	       {
		  if(non_human->type == FORKED)
		    {		       
		       forknbr++;
		       if(forknbr == current_forked)
			 {		       		   
			    send_to_user("$OpenListen|", non_human);
			    current_forked++;
			    return;
			 }		  
		    }	     
		  non_human = non_human->next;
	       }
	     /* If we get here, which we usually shouldn't, we didn't find a
	      * process to host the listening sockets, so we will have to
	      * fork.  */
	     do_fork = 1;
	  }	
     }
}


/* Create a process for uploading to public hub list */
void do_upload_to_hublist(void)
{
   int nbrusers;
   int erret;
   
   nbrusers = count_all_users();
   
   if((pid = fork()) == -1)
     {
	logprintf(1, "Error - Couldn't fork new process in do_upload_to_hublist()\n");
	logerror(1, errno);
	return;
     }
   if(pid > 0)
     pid = getpid();
   else
     {
	pid = -2;
	remove_all(0xFFFF, 0, 0);
	
	while(((erret =  close(listening_unx_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In do_upload_to_hublist()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In do_upload_to_hublist()/close(): ");
	     logerror(1, errno);
	  }
	
	while(((erret =  close(listening_udp_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In do_upload_to_hublist()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In do_upload_to_hublist()/close(): ");
	     logerror(1, errno);
	  }
	
	upload_to_hublist(nbrusers);
     }
   upload = 0;
}

 
/* Removes all users of specified type.  */
void remove_all(int type, int send_quit, int remove_from_list)
{
   struct sock_t *human_user;
   struct user_t *non_human;
   struct sock_t *next_human;
   struct user_t *next_non_human;
   
   human_user = human_sock_list;
   non_human = non_human_user_list;
   
   /* First non-humans.  */
   while(non_human != NULL)
     {
	next_non_human = non_human->next;

	if((non_human->type & type) != 0)
	  remove_user(non_human, send_quit, remove_from_list);
	
	non_human = next_non_human;
     }   
   while(human_user != NULL)
     {
	next_human = human_user->next;

	if((human_user->user->type & type) != 0)
	  remove_user(human_user->user, send_quit, remove_from_list);
	
	human_user = next_human;
     }
}

void term_signal(int z)
{
   quit = 1;
}

void sighup_signal(int z)
{
   do_reload_conf = 1;
}

/* SIGALRM handler — only sets a flag.  All actual work is done in the
 * main loop via handle_alarm() to avoid calling non-async-signal-safe
 * functions (malloc, logprintf, list traversal) from a signal context. */
void alarm_signal(int z)
{
   do_alarm = 1;
   alarm(ALARM_TIME);
}

/* Called from the main loop when do_alarm flag is set. */
void handle_alarm(void)
{
   struct user_t *non_human;
   struct sock_t *human_user;

   if((debug != 0) && (pid > 0))
     logprintf(2, "Alarm timer fired\n");

   /* Check timeouts */
   non_human = non_human_user_list;
   while(non_human != NULL)
     {
	if((non_human->timeout == 0) && (non_human->type == LINKED))
	  {
	     logprintf(2, "Linked hub at %s, port %d is offline\n", non_human->hostname, non_human->key);
	     non_human->rem = REMOVE_USER;
	  }
	non_human = non_human->next;
     }

   human_user = human_sock_list;
   while(human_user != NULL)
     {
	if((human_user->user->type &
	    (UNKEYED | NON_LOGGED)) != 0)
	  {
	     logprintf(2, "Timeout for non logged in user at %s, removing user\n", human_user->user->hostname);
	     human_user->user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	  }
	human_user = human_user->next;
     }

   /* And reset all timeout values */
   non_human = non_human_user_list;
   while(non_human != NULL)
     {
	if(non_human->type == LINKED)
	  non_human->timeout = 0;
	non_human = non_human->next;
     }

   /* And make clear for upload to public hub list */
   if(pid > 0)
     {
	if(hublist_upload != 0)
	  upload = 1;
	do_write = 1;
	do_send_linked_hubs = 1;
	do_purge_user_list = 1;
     }
   else
     {
	upload = 0;
	do_write = 0;
	do_purge_user_list = 0;
     }

   remove_expired();
}

void init_sig(void)
{  
   struct sigaction sv;  
   
   memset(&sv, 0, sizeof(struct sigaction));
   sv.sa_flags = 0;
   sigemptyset(&sv.sa_mask);
#ifdef SA_NOCLDWAIT
   sv.sa_flags |= SA_NOCLDWAIT;
#endif
#ifdef SA_NOCLDSTOP
   sv.sa_flags |= SA_NOCLDSTOP;
#endif
   
   sv.sa_handler = SIG_IGN;
   /* Don't want broken pipes to kill the hub.  */
   sigaction(SIGPIPE, &sv, NULL);
   
   /* ...or any defunct child processes.  */
   sigaction(SIGCHLD, &sv, NULL);
   
   sv.sa_handler = term_signal;
   
   /* Also, shut down properly.  */
   sigaction(SIGTERM, &sv, NULL);
   sigaction(SIGINT, &sv, NULL);
   
   sv.sa_handler = alarm_signal;

   /* And set handler for the alarm call.  */
   sigaction(SIGALRM, &sv, NULL);

   sv.sa_handler = sighup_signal;

   /* Reload configuration on SIGHUP.  */
   sigaction(SIGHUP, &sv, NULL);
}

/* Send info about one user to another. If all is 1, send to all */
void send_user_info(struct user_t *from_user, char *to_user_nick, int all)
{
   char *send_buf;
   struct user_t *to_user;
   int to_nick_len;
   size_t send_buf_size;

   (all != 0) ? (to_nick_len = 5) : (to_nick_len = strlen(to_user_nick)+1);

   send_buf_size = 9 + to_nick_len
		 + strlen(from_user->nick) + 1
	         + ((from_user->desc == NULL) ? 0 : strlen(from_user->desc)) + 4 + 10
	         + ((from_user->email == NULL) ? 0 : strlen(from_user->email)) + 20 + 1;
   if((send_buf = malloc(sizeof(char) * send_buf_size)) == NULL)
     {
	logprintf(1, "Error - In send_user_info()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return;
     }
   
   if(all != 0)
     snprintf(send_buf, send_buf_size, "$MyINFO $ALL ");
   else
     snprintf(send_buf, send_buf_size, "$MyINFO $%s ", to_user_nick);
   
   sprintfa(send_buf, send_buf_size, "%s", from_user->nick);
   sprintfa(send_buf, send_buf_size, " ");
   if(from_user->desc != NULL)
     sprintfa(send_buf, send_buf_size, "%s", from_user->desc);
   sprintfa(send_buf, send_buf_size, "$ $");
   switch(from_user->con_type)
     {
      case 1:
	sprintfa(send_buf, send_buf_size, "28.8Kbps");
	break;
      case 2:
	sprintfa(send_buf, send_buf_size, "33.6Kbps");
	break;
      case 3:
	sprintfa(send_buf, send_buf_size, "56Kbps");
	break;
      case 4:
	sprintfa(send_buf, send_buf_size, "Satellite");
	break;
      case 5:
	sprintfa(send_buf, send_buf_size, "ISDN");
	break;
      case 6:
	sprintfa(send_buf, send_buf_size, "DSL");
	break;
      case 7:
	sprintfa(send_buf, send_buf_size, "Cable");
	break;
      case 8:
	sprintfa(send_buf, send_buf_size, "LAN(T1)");
	break;
      case 9:
	sprintfa(send_buf, send_buf_size, "LAN(T3)");
	break;
// @Ciuly: added some other connection types
      case 10:
	sprintfa(send_buf, send_buf_size, "Wireless");
        break;
      case 11:
	sprintfa(send_buf, send_buf_size, "Modem");
        break;
      case 12:
	sprintfa(send_buf, send_buf_size, "Netlimiter");
        break;
// end @Ciuly
// Start fix for 1027168 by Ciuly
      default:
        sprintfa(send_buf, send_buf_size, "Unknown");
        break;
// End fix for 1027168
     }
   sprintfa(send_buf, send_buf_size, "%c", from_user->flag);
   sprintfa(send_buf, send_buf_size, "$");
   if(from_user->email != NULL)
      sprintfa(send_buf, send_buf_size, "%s", from_user->email);
   sprintfa(send_buf, send_buf_size, "$%lld", from_user->share);
   sprintfa(send_buf, send_buf_size, "$|");

   if((to_user = get_human_user(to_user_nick)) != NULL)
     send_to_user(send_buf, to_user);
   else
     send_to_non_humans(send_buf, FORKED, NULL);
   free(send_buf);
}

void hub_mess(struct user_t *user, int mess_type)
{
   char *send_string;

   send_string = NULL;
   switch(mess_type)
     {
	/* If a user just connected */
      case INIT_MESS:
	if((send_string = malloc(sizeof(char) * 110)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }

	snprintf(send_string, 110, "$HubName %s|", hub_name);
	sprintfa(send_string, 110, "<Hub-Security> This hub is running version %s of Open DC Hub.|", VERSION);
	break;
	
	/* If the hub is full, tell user */
      case HUB_FULL_MESS:
	if((send_string = malloc(sizeof(char) 
				 * (15 + strlen(hub_full_mess) + 3))) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	snprintf(send_string, 15 + strlen(hub_full_mess) + 3, "<Hub-Security> %s|",
		 hub_full_mess);
	break;
	
      case BAN_MESS:
	if((send_string = malloc(sizeof(char) * 50)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	
	snprintf(send_string, 50, "<Hub-Security> Your IP or Hostname is banned|");
	break;
	
      case GET_PASS_MESS:
	if((send_string = malloc(sizeof(char) * 100)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	
	snprintf(send_string, 100, "<Hub-Security> Your nickname is registered, please supply a password.|$GetPass|");
	break;

      case GET_PASS_MESS2:
	if((send_string = malloc(sizeof(char) * 100)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }

	snprintf(send_string, 100, "<Hub-Security> Password required to enter hub.|$GetPass|");
	break;
	
      case LOGGED_IN_MESS:
	/* Construct the reply string */
	if((send_string = malloc(sizeof(char) * (60 + strlen(user->nick)))) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	snprintf(send_string, 60 + strlen(user->nick), "<Hub-Security> Logged in.|$Hello %s|", user->nick);
	break;
	
      case OP_LOGGED_IN_MESS:
	if((send_string = malloc(sizeof(char) * (15 + strlen(user->nick)))) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	snprintf(send_string, 15 + strlen(user->nick), "$LogedIn %s|", user->nick);
	break;
	
      case BAD_PASS_MESS:
	/* Construct the reply string */
	if((send_string = malloc(sizeof(char) * 60)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	snprintf(send_string, 60, "$BadPass|<Hub-Security> That password was incorrect.|");
	break;
	
      case HELLO_MESS:
	/* Construct the reply string */
	if((send_string = malloc(sizeof(char) * (strlen(user->nick) + 12))) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	snprintf(send_string, strlen(user->nick) + 12, "$Hello %s|", user->nick);
	break;
	
     }
	
   /* Send the constructed string */
   if(send_string != NULL)
     send_to_user(send_string, user);
   free(send_string);
}

/* This function handles every command in the received packet one by one */
/* Returns 0 if user should be removed */
int handle_command(char *buf, struct user_t *user)
{
   int ret;
   char *temp;
   char tempstr[MAX_HOST_LEN+1]; 
  
   temp = NULL;
   while(buf != NULL)
     {
	/* Check if it's a '$' or a '<' first in the command string */
	if((strchr(buf, '$') != NULL) && (strchr(buf, '<') == NULL))
	  temp = strchr(buf, '$');
	else if((strchr(buf, '$') == NULL) && (strchr(buf, '<') != NULL))
	  temp = strchr(buf, '<');
	else if((strchr(buf, '$') == NULL) && (strchr(buf, '<') == NULL))
	  {
	     /* This is what happends every time a command doesn't fit in one
	      * single package. */
	     return 1;
	  }
	
	else
	  (strchr(buf, '$') < strchr(buf, '<'))
	  ? (temp = strchr(buf, '$'))  /* The '$' is first */
	    : (temp = strchr(buf, '<')); /* The '<' is first */
	
	buf = temp;
	temp = NULL;
	/* First check if it's a whole command */
	if(strchr(buf, '|') != NULL)
	  {
	     /* Copy command to temporary buf so we don't get more sent to the
	      * function than neccessary */
	     if((temp = malloc(sizeof(char) * (cut_string(buf, '|') + 3))) == NULL)
	       {
		  logprintf(1, "Error - In handle_command()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	       }
             strncpy(temp, buf, cut_string(buf, '|') + 1);
	     if(cut_string(buf, '|') > 0)
	       temp[cut_string(buf, '|')+1] = '\0';
	     
	     /* The Key command */
	     if(strncmp(temp, "$Key ", 5) == 0)
	       {
		  if(user->type == UNKEYED)
		    {
		       if(validate_key(buf, user) == 0)
			 {
			    logprintf(1, "User at %s provided bad $Key, removing user\n", user->hostname);
			    free(temp);
			    return 0;
			 }
		    }
	       }
	     
	     /* The ValidateNick command */
	     else if(strncmp(temp, "$ValidateNick ", 14) == 0)
	       {
		  /* Only for non logged in users. If client wants to change
		   * nick, it first has to disconnect.  */
		  if(user->type == NON_LOGGED)
		    {
		       if(validate_nick(temp, user) == 0)
			 {
			    free(temp);
			    return 0;
			 }
		    }
	       }
	     
	     /* The Version command */
	     else if(strncmp(temp, "$Version ", 9) == 0)
	       {
		  if(user->type != ADMIN)
		    {
		       if(version(temp, user) == 0)
			 {
			    free(temp);
			    return 0;
			 }
		    }		  
	       }
	     
	     /* The GetNickList command */
	     else if(strncasecmp(temp, "$GetNickList", 12) == 0)
	       {
		  send_nick_list(user);
	       }
	     
	     /* The MyINFO command */
	     else if(strncmp(temp, "$MyINFO $", 9) == 0)
	       {
		  if(user->type != ADMIN)
		    {
		       if(my_info(temp, user) == 0)
		       {
			    free(temp);
			    return 0;
			 }
		    }
	       }
	     
	     /* The GetINFO command */
	     else if(strncasecmp(temp, "$GetINFO ", 9) == 0)
	       {
		  /* Only for logged in users */
		  if((user->type & (UNKEYED | NON_LOGGED | LINKED)) == 0)
		    get_info(temp, user);
	       }
	     
	     /* The To: From: command */
	     else if(strncmp(temp, "$To: ", 5) == 0)
	       {
		  /* Only for logged in users */
		  if((user->type & (UNKEYED | NON_LOGGED | LINKED)) == 0)
		    to_from(temp, user);
	       }
	     
	     /* The ConnectToMe command */
	     else if(strncmp(temp, "$ConnectToMe ", 13) == 0)
	       {
		  if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN 
				   | FORKED)) != 0)
		    connect_to_me(temp, user);
	       }
	     
	     /* The RevConnectToMe command */
	     else if(strncmp(temp, "$RevConnectToMe ", 16) == 0)
	       {
		  if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN 
				   | FORKED)) != 0)
		    rev_connect_to_me(temp, user);
	       }
	     
	     /* The Search command */
	     else if(strncmp(temp, "$Search ", 8) == 0)
	       {
		  if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN
				   | FORKED)) != 0)
		    search(temp, user);
	       }
	     
	     /* The SR command */
	     else if(strncmp(temp, "$SR ", 4) == 0)
	       {
		  if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN 
				   | FORKED)) != 0)
		    sr(temp, user);
	       }
	     
	     /* The MyPass command */
	     else if(strncmp(temp, "$MyPass ", 8) == 0)
	       {
		  if(user->type == NON_LOGGED)
		    {
		       if(my_pass(temp + 8, user) == 0)
			 {
			    free(temp);
			    return 0;
			 }
		    }
	       }
	     
	     /* The kick command */
	     else if(strncasecmp(temp, "$Kick ", 6) == 0)
	       {
		  if((user->type & (OP | OP_ADMIN | ADMIN | FORKED)) != 0)
		    {
		       kick(temp, user, 1);
		    }
		  else
		    logprintf(2, "%s tried to kick without having priviledges\n", user->nick);
	       }
	     
	     /* The OpForceMove command */
	     else if(strncmp(temp, "$OpForceMove ", 13) == 0)
	       {
		  if((user->type & (OP | OP_ADMIN | ADMIN | FORKED)) != 0)
		    {
		       op_force_move(temp, user);
		    }
		  else
		    logprintf(2, "%s tried to redirect without having priviledges\n", user->nick);
	       }
	     
	     /* The chat command, starts with <nick> */
	     else if(*temp == '<')
	       {
		  if((user->type & (UNKEYED | LINKED | NON_LOGGED)) == 0)
		    chat(temp, user);
	       }
	     
	     /* Commands that should be forwarded from forked processes */
	     else if((strncmp(temp, "$Hello ", 7) == 0)
		     || (strncmp(temp, "$Quit ", 6) == 0)
		     || (strncmp(temp, "$OpList ", 8) == 0))
	       {
		  if(user->type == FORKED)
		    {
		       if(strncmp(temp, "$OpList ", 8) == 0)
			 {
			    /* The oplist ends with two '|' */
			    size_t tlen = strlen(temp);
			    if(tlen < MAX_MESS_SIZE)
			      {
				 temp[tlen] = '|';
				 temp[tlen+1] = '\0';
			      }
			 }
		       send_to_non_humans(temp, FORKED, user);
		       send_to_humans(temp, REGULAR | REGISTERED | OP
				      | OP_ADMIN, user);

		       /* Emit admin events when JOIN/QUIT forwarded from child.
			* temp is "$Hello nick|" or "$Quit nick|" - already
			* pipe-terminated, so use %s without extra pipe. */
		       if(strncmp(temp, "$Quit ", 6) == 0)
			 {
			    /* JSON event: extract nick from "$Quit nick|" */
			    {
			       char jnick[MAX_NICK_LEN+1];
			       strncpy(jnick, temp + 6, MAX_NICK_LEN);
			       jnick[MAX_NICK_LEN] = '\0';
			       char *pipe = strchr(jnick, '|');
			       if(pipe) *pipe = '\0';
			       json_event_user_quit(jnick);
			    }
			 }
		    }
	       }
	     
	     /* Internal commands for mangement through telnet port and 
	      * communication between processes */
	     else if((strncmp(temp, "$ClosedListen", 13) == 0)
		     && (user->type == FORKED) && (pid > 0))
	       {
		  switch_listening_process(temp, user);
	       }	     
	     
	     else if((strncmp(temp, "$OpenListen", 11) == 0)
		     && (user->type == FORKED) && (pid == 0))
	       {
		  switch_listening_process(temp, user);		 
	       }
	     
	     else if((strncmp(temp, "$RejListen", 10) == 0)
		     && (user->type == FORKED) && (pid > 0))
	       {
		  switch_listening_process(temp, user);
	       }
	     
	     else if((strncmp(temp, "$DiscUser", 9) == 0)
		     && (user->type == FORKED))
	       {
		  disc_user(temp, user);
	       }	     	     	    	     
	     	     	     
	     else if((strncasecmp(temp, "$ForceMove ", 11) == 0)
		     && (user->type == FORKED))
	       {		  
		  redirect_all(temp + 11, user);
	       }	     
	     
	     else if((strncasecmp(temp, "$QuitProgram", 12) == 0)
		     && ((user->type == FORKED) || (user->type == ADMIN)))
	       {
		  if(user->type == ADMIN)
		    uprintf(user, "\r\nShutting down hub...\r\n");
		  quit = 1;
	       }
	     
	     else if(strncasecmp(temp, "$Exit", 5) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       logprintf(1, "Got exit from admin at %s, hanging up\n", user->hostname);
		       free(temp);
		       return 0;
		    }
	       }
	     
	     else if((strncasecmp(temp, "$RedirectAll ", 13) == 0) && (user->type == ADMIN))
	       {
		  uprintf(user, "\r\nRedirecting all users...\r\n");
		  logprintf(1, "Admin at %s redirected all users\n", user->hostname);
		  redirect_all(temp+13, user);
	       }
	     
	     else if(strncasecmp(temp, "$Set ", 5) == 0)
	       {
		  if((user->type & (FORKED | ADMIN)) != 0)
		    set_var(temp, user);
	       }
	     
	     else if(strncasecmp(temp, "$Ban ", 5) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = ballow(temp+5, BAN, user);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      {
				 send_to_user("\r\nCouldn't add entry to ban list\r\n", user);
				 logprintf(4, "Error - Failed adding entry to ban list\n");
			      }
			    else if(ret == 0)
			      {
				 send_to_user("\r\nEntry is already on the list\r\n", user);
			      }
			    else
			      {
				 send_to_user("\r\nAdded entry to ban list\r\n", user);
				 sscanf(temp+5, "%120[^|]", tempstr);
				 logprintf(3, "Admin at %s added %s to banlist\n", user->hostname, tempstr);
			      }
			 }		       
		    }	 
	       }
	     else if(strncasecmp(temp, "$Allow ", 7) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = ballow(temp+7, ALLOW, user);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      {
				 send_to_user("\r\nCouldn't add entry to allow list\r\n", user);
				 logprintf(4, "Error - Failed adding entry to allow list\n");
			      }
			    else if(ret == 0)
			      {
				 send_to_user("\r\nEntry is already on the list\r\n", user);
			      }
			    else
			      {
				 send_to_user("\r\nAdded entry to allow list\r\n", user);
				 sscanf(temp+7, "%120[^|]", tempstr);
				 logprintf(3, "Admin at %s added %s to allow list\n", user->hostname, tempstr);
			      }
			 }		       
		    }	 
	       }
	     else if(strncasecmp(temp, "$Unban ", 7) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = unballow(temp+7, BAN);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      {
				 send_to_user("\r\nCouldn't remove entry from ban list\r\n", user);
				 logprintf(1, "Error - Failed removing entry from ban list\n");
			      }
			    else if(ret == 0)
			      {
				 send_to_user("\r\nEntry wasn't found in list\r\n", user);
			      }
			    else
			      {
				 send_to_user("\r\nRemoved entry from ban list\r\n", user);
				 sscanf(temp+7, "%120[^|]", tempstr);
				 logprintf(3, "Admin at %s removed %s from ban list\n", user->hostname, tempstr);
			      }
			 }	 
		    }		  
	       }
	     else if(strncasecmp(temp, "$Unallow ", 9) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = unballow(temp+9, ALLOW);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      {
				 send_to_user("\r\nCouldn't remove entry from allow list\r\n", user);
				 logprintf(1, "Error - Failed removing entry from allow list\n");
			      }
			    else if(ret == 0)
			      {
				 send_to_user("\r\nEntry wasn't found in list\r\n", user);
			      }
			    else
			      {
				 send_to_user("\r\nRemoved entry from allow list\r\n", user);
				 sscanf(temp+9, "%120[^|]", tempstr);
				 logprintf(3, "Admin at %s removed %s from allow list\n", user->hostname, tempstr);
			      }
			 }	 
		    }		  
	       }
	     else if(strncasecmp(temp, "$GetBanList", 11) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_user_list(BAN, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$GetAllowList", 13) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_user_list(ALLOW, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$GetRegList", 11) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_user_list(REG, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$GetConfig", 10) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_user_list(CONFIG, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$GetMotd", 8) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_motd(user);
		       send_to_user("\r\n", user);
		    }
	       }
	     else if(strncasecmp(temp, "$GetLinkList", 12) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_user_list(LINK, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$GetStatus", 10) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       int ops_count;
		       time_t now = time(NULL);
		       long uptime_secs = (long)(now - hub_start_time);
		       ops_count = count_users(OP | OP_ADMIN);
		       uprintf(user, "\r\nSTATUS hub_name|%s\r\n", hub_name);
		       uprintf(user, "STATUS users_online|%d\r\n", count_all_users());
		       uprintf(user, "STATUS total_share|%lld\r\n", get_total_share());
		       uprintf(user, "STATUS uptime|%ld\r\n", uptime_secs);
		       uprintf(user, "STATUS hub_port|%u\r\n", listening_port);
#ifdef HAVE_SSL
		       uprintf(user, "STATUS tls_port|%u\r\n", tls_port);
#endif
		       uprintf(user, "STATUS max_users|%d\r\n", max_users);
		       uprintf(user, "STATUS ops_online|%d\r\n", ops_count);
		       uprintf(user, "STATUS END|\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$GetUserList", 12) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       struct sock_t *hu;
		       hu = human_sock_list;
		       uprintf(user, "\r\n");
		       while(hu != NULL)
			 {
			    if((hu->user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
			      {
				 char *type_str;
				 if(hu->user->type == OP_ADMIN)
				   type_str = "OP_ADMIN";
				 else if(hu->user->type == OP)
				   type_str = "OP";
				 else if(hu->user->type == REGISTERED)
				   type_str = "REGISTERED";
				 else
				   type_str = "REGULAR";
				 uprintf(user, "USER %s|%s|%lld|%s|%s|%s|%d\r\n",
					 hu->user->nick,
					 hu->user->hostname,
					 hu->user->share,
					 type_str,
					 hu->user->desc ? hu->user->desc : "",
					 hu->user->email ? hu->user->email : "",
					 hu->user->con_type);
			      }
			    hu = hu->next;
			 }
		       uprintf(user, "USER END|\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$AddRegUser ", 12) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = add_reg_user(temp, user);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      send_to_user("\r\nCouldn't add user to reg list\r\n", user);
			    else if(ret == 2)
			      send_to_user("\r\nBad format for $AddRegUser. Correct format is:\r\n$AddRegUser <nickname> <password> <opstatus>|\r\n", user);
			    else if(ret == 3)
			      send_to_user("\r\nThat nickname is already registered\r\n", user);
			    else
			      {			    
				 send_to_user("\r\nAdded user to reglist\r\n", user);
				 logprintf(3, "Admin at %s added entry to reglist\n", user->hostname);
			      }		       
			 }
		    }
	       }	     
	     else if(strncasecmp(temp, "$RemoveRegUser ", 15) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = remove_reg_user(temp+15, user);
		       if(user->type == ADMIN)
			 {			     
			    if(ret == 0)
			      send_to_user("\r\nUser wasn't found in reg list\r\n", user);
			    else if(ret == -1)
			      send_to_user("\r\nCouldn't remove user from reg list\r\n", user);
			    else
			      {			    
				 send_to_user("\r\nRemoved user from reglist\r\n", user);
				 logprintf(3, "Admin at %s removed entry from reglist\n", user->hostname);
			      }		       			    
			 }
		    }
	       }		  
	     else if(strncasecmp(temp, "$AddLinkedHub ", 14) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = add_linked_hub(temp);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      send_to_user("\r\nCouldn't add hub to link list\r\n", user);
			    else if(ret == 2)
			      send_to_user("\r\nBad format for $AddLinkedHub. Correct format is:\r\n$AddLinkedHub <ip> <port>|\r\n", user);
			    else if(ret == 3)
			      send_to_user("\r\nThat hub is already in the linklist\r\n", user);
			    else
			      {			    
				 send_to_user("\r\nAdded hub to linklist\r\n", user);
				 logprintf(3, "Admin at %s added entry to linklist\n", user->hostname);
			      }
			 }		       		       
		    }
	       }
	     else if(strncasecmp(temp, "$RemoveLinkedHub ", 17) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = remove_linked_hub(temp+17);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == 0)
			      send_to_user("\r\nHub wasn't found in link list\r\n", user);
			    else if(ret == -1)
			      send_to_user("\r\nCouldn't remove hub from link list\r\n", user);
			    else if(ret == 2)
			      send_to_user("\r\nBad format for $RemoveLinkedHub. Correct format is:\r\n$RemoveLinkedHub <ip> <port>|\r\n", user);
			    else
			      {			    
				 send_to_user("\r\nRemoved hub from linklist\r\n", user);
				 logprintf(3, "Admin at %s removed entry from linklist\n", user->hostname);
			      }		       
			 }
		    }		  
	       }
	     else if(strncmp(temp, "$MultiSearch ", 13) == 0)
	       {
		  if((user->type & (FORKED | REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
		    multi_search(temp, user);
	       }
	     else if(strncmp(temp, "$MultiConnectToMe ", 18) == 0)
	       {
		  if((user->type & (FORKED | REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
		    multi_connect_to_me(temp, user);
	       }
	     else if(strncasecmp(temp, "$GetHost ", 9) == 0)
	       {
		  if(user->type == ADMIN)
		    get_host(temp, user, HOST);
	       }	     
	     else if(strncasecmp(temp, "$GetIP ", 7) == 0)
	       {
		  if(user->type == ADMIN)
		    get_host(temp, user, IP);
	       }	     
	     else if(strncasecmp(temp, "$Commands", 9) == 0)
	       {
		  if(user->type == ADMIN)
		    send_commands(user);
	       }
	     else if(strncasecmp(temp, "$MassMessage ", 13) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\nSent Mass Message\r\n");
		       send_mass_message(temp + 13, user);
		    }		  
	       }
	     else if(strncasecmp(temp, "$AddPerm ", 9) == 0)
	       {
		  if((user->type & (ADMIN | FORKED)) != 0)
		    {
		       ret = add_perm(temp, user);
		       if(user->type == ADMIN)
			 {
			    if(ret == -1)
			      uprintf(user, "\r\nCouldn't add permission to user\r\n");
			    else if(ret == 2)
			      uprintf(user, "\r\nBad format for $AaddPerm. Correct format is:\r\n$AddPerm <nick> <permission>|\r\nand permission is one of: BAN_ALLOW, USER_INFO, MASSMESSAGE, USER_ADMIN\r\n");
			    else if(ret == 3)
			      uprintf(user, "\r\nUser already has that permission.\r\n");
			    else if(ret == 4)
			      uprintf(user, "\r\nUser is not an operator.\r\n");
			    else
			      {
				 uprintf(user, "\r\nAdded permission to user.\r\n");
				 logprintf(3, "Administrator at %s added permission to user\n", user->hostname);
			      }		       
			 }		  
		    }		  
	       }
	     else if(strncasecmp(temp, "$RemovePerm ", 12) == 0)
	       {
		  if((user->type & (ADMIN | FORKED)) != 0)
		    {
		       ret = remove_perm(temp, user);
		       if(user->type == ADMIN)
			 {
			    if(ret == -1)
			      uprintf(user, "\r\nCouldn't remove permission from user.\r\n");
			    else if(ret == 2)
			      uprintf(user, "\r\nBad format for $RemovePerm. Correct format is:\r\n$RemovePerm <nick> <permission>|\r\nand permission is one of: BAN_ALLOW, USER_INFO, MASSMESSAGE, USER_ADMIN\r\n");
			    else if(ret == 3)
			      uprintf(user, "\r\nUser does not have that permission.\r\n");
			    else if(ret == 4)
			      uprintf(user, "\r\nUser is not an operator.\r\n");
			    else
			      {
				 uprintf(user, "\r\nRemoved permission from user.\r\n");
				 logprintf(3, "Administrator at %s removed permission from user\n", user->hostname);
			      }		       
			 }		  
		    }		  
	       }
	     else if(strncasecmp(temp, "$ShowPerms ", 11) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       if((ret = show_perms(user, temp)) == 2)
			 uprintf(user, "\r\nBad format for $ShowPerms. Correct format is:\r\n$ShowPerms <nick>|");
		       else if(ret == 3)
			 uprintf(user, "\r\nUser is not an operator.\r\n");		       
		    }		  
	       }
	     else if(strncasecmp(temp, "$Gag ", 5) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = ballow(temp+5, GAG, user);
		       if(user->type == ADMIN)
			 {
			    if(ret == -1)
			      {
				 uprintf(user, "\r\nCouldn't add entry to gag list\r\n");
				 logprintf(4, "Error - Failed adding entry to gag list\n");
			      }
			    else if(ret == 2)
			      uprintf(user, "\r\nEntry is already on the list\r\n");
			    else
			      {
				 uprintf(user, "\r\nAdded entry to gag list\r\n");
				 sscanf(temp+9, "%120[^|]", tempstr);
				 logprintf(3, "Administrator at %s added %s to gag list\n", user->hostname, tempstr);
			      }
			 }
		    }
	       }
	     else if(strncasecmp(temp, "$GetGagList", 11) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\nGag list:\r\n");
		       send_user_list(GAG, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$UnGag ", 7) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = unballow(temp+7, GAG);
		       if(user->type == ADMIN)
			   {
			    if(ret == -1)
			      {
				 uprintf(user, "\r\nCouldn't remove entry from nickban list\r\n");
				 logprintf(4, "Error - Failed adding entry to nickban list\n");
			      }
			    else if(ret == 2)
			      uprintf(user, "\r\nEntry wasn't found in list\r\n");
			    else
			      {
				 uprintf(user, "\r\nRemoved entry from nickban list\r\n");
				 sscanf(temp+9, "%120[^|]", tempstr);
				 logprintf(3, "Administrator at %s removed %s from nickban list\n", user->hostname, tempstr);
			      }
			 }
		    }
	       }
	     else if(strncasecmp(temp, "$NickBan ", 9) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = ballow(temp+9, NICKBAN, user);
		       if(user->type == ADMIN)
			 {		       
			    if(ret == -1)
			      {			      
				 uprintf(user, "\r\nCouldn't add entry to nickban list\r\n");
				 logprintf(4, "Error - Failed adding entry to nickban list\n");
			      }		  
			    else if(ret == 2)
			      uprintf(user, "\r\nEntry is already on the list\r\n");
			    else
			      {			      
				 uprintf(user, "\r\nAdded entry to nickban list\r\n");
				 sscanf(temp+9, "%120[^|]", tempstr);
				 logprintf(3, "Administrator at %s added %s to nickban list\n", user->hostname, tempstr);
			      }		  
			 }	
		    }		     
	       }
	     else if(strncasecmp(temp, "$GetNickBanList", 15) == 0)
	       {
		  if(user->type == ADMIN)
		    {		       
		       uprintf(user, "\r\nNickban list:\r\n");
		       send_user_list(NICKBAN, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$UnNickBan ", 11) == 0)
	       {
		  if((user->type & ADMIN) != 0)
		    {
		       ret = unballow(temp+11, NICKBAN);
		       if(user->type == ADMIN)
			 {		       
			    if(ret == -1)
			      {			      
				 uprintf(user, "\r\nCouldn't remove entry from nickban list\r\n");
				 logprintf(4, "Error - Failed adding entry to nickban list\n");
			      }		  
			    else if(ret == 2)
			      uprintf(user, "\r\nEntry wasn't found in list\r\n");
			    else
			      {			      
				 uprintf(user, "\r\nRemoved entry from nickban list\r\n");
				 sscanf(temp+9, "%120[^|]", tempstr);
				 logprintf(3, "Administrator at %s removed %s from nickban list\n", user->hostname, tempstr);
			      }		  
			 }		      	
		    }
	       }	     	     
	     else if(strncasecmp(temp, "$DataToAll ", 11) == 0)
	       {
		  if((user->type & (ADMIN | FORKED)) != 0)
		    send_to_humans(temp + 11, REGULAR | REGISTERED | OP | OP_ADMIN, user);
	       }
	  }
	
	if((buf = strchr(buf, '|')) != NULL)
	  buf++; 

	if(temp != NULL)
	  free(temp);
     } 
   return 1;
}

/* Add a user who connected */
int new_human_user(int sock)
{
   struct user_t *user;
   struct sockaddr_in client;
   int namelen;
   int yes = 1;
   int i = 0;
   int banret, allowret, gagret;
   int socknum;
   int erret;
   int flags;
   char ip_str[INET_ADDRSTRLEN];

   memset(&client, 0, sizeof(struct sockaddr_in));
   
   /* Get a socket for the connected user.  */
   namelen = sizeof(client);
   while(((socknum = accept(sock, (struct sockaddr *)&client, 
	     &namelen)) == -1) && ((errno == EAGAIN) || (errno == EINTR)))
     {
	i++;
	usleep(500);
	/* Giving up after half a second */
	if(i == 1000)
	  return -1;
     }
   
   /* Allocate space for the new user */
   if((user = malloc(sizeof(struct user_t))) == NULL)
     {	
	logprintf(1, "Error - In new_human_user()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return -1;
     }   
   
   /* Set the sock of the user.  */
   user->sock = socknum;

   /* Reset the last search time */
   user->last_search = 0;
   
   /* Avoid dead peers */
   if(setsockopt(user->sock, SOL_SOCKET, SO_KEEPALIVE, &yes,
		 sizeof(int)) == -1)
     {
	logprintf(1, "Error - In new_human_user()/set_sock_opt(): ");
	logerror(1, errno);
	close(user->sock);
	free(user);
	return -1;
     }
   
   if((flags = fcntl(user->sock, F_GETFL, 0)) < 0)
     {	
	logprintf(1, "Error - In new_human_user()/in fcntl(): ");
	logerror(1, errno);
	close(user->sock);
	free(user);
	return -1;
     }
   
   /* Non blocking mode */
   if(fcntl(user->sock, F_SETFL, flags | O_NONBLOCK) < 0)
     {
	logprintf(1, "Error - In new_human_user()/in fcntl(): ");
	logerror(1, errno);
	close(user->sock);
	free(user);
	return -1;
     }   
   
   /* Set users ip */
   user->ip = client.sin_addr.s_addr;
   
   /* Set users hostname if reverse_dns is set.  */
   if(reverse_dns != 0)
     {
	strncpy(user->hostname, hostname_from_ip(user->ip), MAX_HOST_LEN);
	user->hostname[MAX_HOST_LEN] = '\0';
     }
   else
     {
	inet_ntop(AF_INET, &client.sin_addr, user->hostname, sizeof(user->hostname));
     }
   
   /* Set user vars to 0/NULL */
   user->type = NON_LOGGED;   
   memset(user->nick, 0, MAX_NICK_LEN+1);
   memset(user->version, 0, MAX_VERSION_LEN+1);
   user->email = NULL;
   user->desc = NULL;
   user->con_type = 0;
   user->flag = 0;
   user->share = 0;
   user->timeout = 0;
   user->buf = NULL;
   user->outbuf = NULL;
   user->rem = 0;
   user->last_search = (time_t)0;
#ifdef HAVE_SSL
   user->ssl = NULL;
   user->ssl_handshake_done = 0;
   user->ssl_handshake_start = (time_t)0;
#endif

   snprintf(user->nick, sizeof(user->nick), "Non_logged_in_user");

#ifdef HAVE_SSL
   /* If this is a TLS connection, set up SSL */
   if(sock == tls_listening_socket && ssl_ctx != NULL)
     {
	int hs_ret;
	user->ssl = SSL_new(ssl_ctx);
	if(user->ssl == NULL)
	  {
	     logprintf(1, "Error - In new_human_user(): SSL_new() failed\n");
	     close(user->sock);
	     free(user);
	     return -1;
	  }
	SSL_set_fd(user->ssl, user->sock);
	user->ssl_handshake_start = time(NULL);
	hs_ret = ssl_do_handshake(user);
	if(hs_ret == -1)
	  {
	     /* Handshake failed immediately - plain client on TLS port */
	     SSL_free(user->ssl);
	     close(user->sock);
	     free(user);
	     return 1;
	  }
     }
#endif

   /* Check if hub is full */
   if(sock == listening_socket
#ifdef HAVE_SSL
      || sock == tls_listening_socket
#endif
      )
     {
	if((count_all_users()) >= max_users)
	  {
	     hub_mess(user, HUB_FULL_MESS);
	     if(!((redirect_host == NULL) || ((int)redirect_host[0] <= 0x20)))
	       {
		  uprintf(user, "$ForceMove %s|", redirect_host);
	       }

#ifdef HAVE_SSL
	     if(user->ssl != NULL)
	       {
		  SSL_shutdown(user->ssl);
		  SSL_free(user->ssl);
		  user->ssl = NULL;
	       }
#endif
	     while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");

	     if(erret != 0)
	       {
		  logprintf(1, "Error - In new_human_user()/close(): ");
		  logerror(1, errno);
	       }

	     free(user);
	     return 1;
	  }
     }
   
   /* Check if user is banned */
     {
	banret = check_if_banned(user, BAN);
	allowret = check_if_allowed(user);   
	
	if(ban_overrides_allow == 0)
	  {
	     if((allowret != 1) && (banret == 1))
	       {
		  hub_mess(user, BAN_MESS);
		  inet_ntop(AF_INET, &client.sin_addr, ip_str, sizeof(ip_str));
		  logprintf(4, "User %s from %s (%s) denied\n",  user->nick, user->hostname, ip_str);
#ifdef HAVE_SSL
		  if(user->ssl != NULL)
		    {
		       SSL_shutdown(user->ssl);
		       SSL_free(user->ssl);
		       user->ssl = NULL;
		    }
#endif
		  while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
		    logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");

		  if(erret != 0)
		    {
		       logprintf(1, "Error - In new_human_user()/close(): ");
		       logerror(1, errno);
		    }

		  free(user);
		  return 1;
	       }	
	  }
	
	else
	  {	
	     if((allowret != 1) || (banret == 1))
	       {
		  hub_mess(user, BAN_MESS);
		  inet_ntop(AF_INET, &client.sin_addr, ip_str, sizeof(ip_str));
		  logprintf(4, "User %s from %s (%s) denied\n",  user->nick, user->hostname, ip_str);
#ifdef HAVE_SSL
		  if(user->ssl != NULL)
		    {
		       SSL_shutdown(user->ssl);
		       SSL_free(user->ssl);
		       user->ssl = NULL;
		    }
#endif
		  while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
		    logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");

		  if(erret != 0)
		    {
		       logprintf(1, "Error - In new_human_user()/close(): ");
		       logerror(1, errno);
		    }

		  free(user);
		  return 1;
	       }	
	  }
	
	if((banret == -1) || (allowret == -1))
	  {
#ifdef HAVE_SSL
	     if(user->ssl != NULL)
	       {
		  SSL_shutdown(user->ssl);
		  SSL_free(user->ssl);
		  user->ssl = NULL;
	       }
#endif
	     while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");

	     if(erret != 0)
	       {
		  logprintf(1, "Error - In new_human_user()/close(): ");
		  logerror(1, errno);
	       }
	     free(user);
	     return -1;
	  }   
     }
   /* Check if the user is gagged */
   gagret = check_if_gagged(user);
   if (gagret == 1)
   {
   	user->gag = 1;
   }
   else
   {
   	user->gag = 0;
   }
           
   /* Add sock struct of the user.  */
   add_socket(user);
   
   if(sock == listening_socket)
     logprintf(4, "New connection on socket %d from user at %s\n", user->sock, user->hostname);
#ifdef HAVE_SSL
   else if(sock == tls_listening_socket)
     logprintf(4, "New TLS connection on socket %d from user at %s\n", user->sock, user->hostname);
#endif
   /* If it's a regular user (plain or TLS).  */
   if(sock == listening_socket
#ifdef HAVE_SSL
      || sock == tls_listening_socket
#endif
      )
     {
	if(check_key != 0)
	  user->type = UNKEYED;
#ifdef HAVE_SSL
	/* Only send Lock if TLS handshake is already done (or no TLS) */
	if(user->ssl == NULL || user->ssl_handshake_done != 0)
#endif
	  {
	     send_lock(user);
	     hub_mess(user, INIT_MESS);
	  }
     }
   if((count_users(UNKEYED | NON_LOGGED | REGULAR | REGISTERED | OP | OP_ADMIN
		   | ADMIN) >= users_per_fork)
      || (max_sockets <= count_users(0xFFFF)+10))
     {
	set_listening_pid(0);	
	while(((erret =  close(listening_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In new_human_user()/close(): ");
	     logerror(1, errno);
	  }
	
	listening_socket = -1;
#ifdef HAVE_SSL
	if(tls_listening_socket != -1)
	  {
	     close(tls_listening_socket);
	     tls_listening_socket = -1;
	  }
#endif
	send_to_user("$ClosedListen|", non_human_user_list);
     }   
	
   return 0;
}

/* Add a non-human user to the linked list.  */
void add_non_human_to_list(struct user_t *user)
{
   /* Add the user at the first place in the list */
   user->next = non_human_user_list;
   non_human_user_list = user;
}

/* Remove a non-human user.  */
void remove_non_human(struct user_t *our_user)
{
   int erret;
   struct user_t *user, *last_user;
  
   user = non_human_user_list;
   last_user = NULL;
   
   while(user != NULL)
     {
	if(user == our_user)
	  {
	     if(our_user->type != LINKED)
	       {
#ifdef HAVE_SSL
		  if(our_user->ssl != NULL)
		    {
		       SSL_shutdown(our_user->ssl);
		       SSL_free(our_user->ssl);
		       our_user->ssl = NULL;
		    }
#endif
		  while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
		    logprintf(1, "Error - In remove_non_human()/close(): Interrupted system call. Trying again.\n");

		  if(erret != 0)
		    {
		       logprintf(1, "Error - In remove_non_human()/close(): ");
		       logerror(1, errno);
		    }
	       }
	     
	     if(last_user == NULL)
	       non_human_user_list = user->next;
	     else
	       last_user->next = user->next;
	     if(our_user->type != LINKED)
	       {
		  if(our_user->buf != NULL)
		    free(our_user->buf);
		  if(our_user->outbuf != NULL)
		    free(our_user->outbuf);
	       }
	     	  
	     free(our_user);	     
	     
	     return;
	  }
	last_user = user;
	user = user->next;
     }
}

/* Add a human user to the hashtable.  */
void add_human_to_hash(struct user_t *user)
{
   int hashv;
   
   hashv = get_hash(user->nick);
   
   /* Adds the user first in the linked list of the specified hash value.  */
   user->next = human_hash_table[hashv];
   human_hash_table[hashv] = user;
}

/* Returns a human user from a certain nick.  */
struct user_t* get_human_user(char *nick)
{
   struct user_t *user;
   
   user = human_hash_table[get_hash(nick)];
 
   while((user != NULL) 
	 && !((strncasecmp(user->nick, nick, strlen(nick)) == 0) 
	      && (strlen(nick) == strlen(user->nick))))
     user = user->next;
   
   return user;
}

/* Removes a human user from hashtable.  */
void remove_human_from_hash(char *nick)
{
   struct user_t *user, *last_user;
   int hashv;
   
   hashv = get_hash(nick);
   user = human_hash_table[hashv];
   last_user = NULL;
   
   while(user != NULL)
     {
	if((strncmp(user->nick, nick, strlen(nick)) == 0)
	   && (strlen(nick) == strlen(user->nick)))
	  {
	     if(last_user == NULL)
	       human_hash_table[hashv] = user->next;
	     else
	       last_user->next = user->next;

	     return;
	  }
	last_user = user;
	user = user->next;
     }
}

/* Removes a human user.  */
void remove_human_user(struct user_t *user)
{
   int erret;
   
   /* Remove the user from the hashtable.  */
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     remove_human_from_hash(user->nick);
    

   /* When a logged in user in a non script process leaves, the user should
    * be removed from the list and the users share should be subtracted from 
    * the total share.  */
   if((user->nick != NULL) 
      && ((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0) 
      && (pid == 0))
     {	
	if(user->share > 0)
	  add_total_share(-user->share);
     }
   
#ifdef HAVE_SSL
   if(user->ssl != NULL)
     {
	/* Best-effort unidirectional shutdown; don't wait for peer's close_notify
	 * on a non-blocking socket — just send ours and move on. */
	int shut_ret = SSL_shutdown(user->ssl);
	if(shut_ret == 0)
	  SSL_shutdown(user->ssl); /* Second call for bidirectional if possible */
	SSL_free(user->ssl);
	user->ssl = NULL;
     }
#endif

   while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_human_user()/close(): Interrupted system call. Trying again.\n");

   if(erret != 0)
     {
	logprintf(1, "Error - In remove_human_user()/close(): ");
	logerror(1, errno);
     }
   
   if(user->buf != NULL)
     {	     
	free(user->buf);
	user->buf = NULL;
     }   
   if(user->outbuf != NULL)
     {		     
	free(user->outbuf);
	user->outbuf = NULL;
     }   
   if(user->email != NULL)
     {		     
	free(user->email);
	user->email = NULL;
     }   
   if(user->desc != NULL)
     {		     
	free(user->desc);
	user->desc = NULL;
     }      
   
   /* Remove the socket struct of the user.  */
   remove_socket(user);
   
   
   /* And free the user.  */
   free(user);
      
   if((count_users(UNKEYED | NON_LOGGED | REGULAR | REGISTERED | OP 
		   | OP_ADMIN | ADMIN) == 0) && (pid == 0)
      && (listening_socket == -1))
     kill_forked_process();
}

/* Removes a user. Sends the $quit string if send_quit is non-zero and removes
 * the user from the userlist if remove_from_list is non-zero.  */
void remove_user(struct user_t *our_user, int send_quit, int remove_from_list)
{
   char quit_string[MAX_NICK_LEN+10];
   
   if(send_quit != 0)
     {
	if((our_user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
	  {
	     snprintf(quit_string, sizeof(quit_string), "$Quit %s|", our_user->nick);
	     send_to_non_humans(quit_string, FORKED, NULL);
	     send_to_humans(quit_string, REGULAR | REGISTERED | OP | OP_ADMIN,
			    our_user);
	     /* Send admin event for user quit */
	     json_event_user_quit(our_user->nick);
	  }
     }

   if((remove_from_list != 0)
      && (our_user->type & (REGULAR | REGISTERED | OP | OP_ADMIN))
      != 0)
     remove_user_from_list(our_user->nick);
   
   if((our_user->type & (UNKEYED | NON_LOGGED | REGULAR | REGISTERED | OP
			| OP_ADMIN | ADMIN)) != 0)
     remove_human_user(our_user);
   else
     remove_non_human(our_user);
}

/* Removes all users who have the rem variable set to non-zero */
void clear_user_list(void)
{
   struct user_t *non_human;
   struct user_t *next_non_human;
   struct sock_t *human_user;
   struct sock_t *next_human_user;
   
   non_human = non_human_user_list;
   human_user = human_sock_list;
   
   while(non_human != NULL)
     {
	next_non_human = non_human->next;
	if(non_human->rem != 0)
	  remove_user(non_human, non_human->rem & SEND_QUIT, 
		      non_human->rem & REMOVE_FROM_LIST);
	
	non_human = next_non_human;
     }
   
   while(human_user != NULL) 
     {
	next_human_user = human_user->next;
	if(human_user->user->rem != 0)
	  remove_user(human_user->user, human_user->user->rem & SEND_QUIT,
		      human_user->user->rem & REMOVE_FROM_LIST);
	
	human_user = next_human_user;
     }
}

/********************************************************/
/* Get action from a connected socket  */
/* Returns -1 on error,                */
/* 0 on connection closed,             */
/* 1 on received message               */
int socket_action(struct user_t *user)
{
   int buf_len;
   char *command_buf;
   char buf[MAX_MESS_SIZE + 1];
   int i = 0;
   
   command_buf = NULL;

   /* Error or connection closed? */
#ifdef HAVE_SSL
   if(user->ssl != NULL)
     {
	buf_len = SSL_read(user->ssl, buf, MAX_MESS_SIZE);
	if(buf_len <= 0)
	  {
	     int ssl_err = SSL_get_error(user->ssl, buf_len);
	     if(ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
	       return 0; /* Not ready yet, return to event loop */
	     if(ssl_err == SSL_ERROR_ZERO_RETURN)
	       buf_len = 0; /* Clean shutdown */
	  }
     }
   else
#endif
   {
   while(((buf_len = recv(user->sock, buf, MAX_MESS_SIZE, 0)) == -1)
	 && ((errno == EAGAIN) || (errno == EINTR)))
     {
	i++;
	usleep(500);
	/* Giving up after half a second */
	if(i == 1000)
	  break;
     }
   }

   if(buf_len <= 0)
     {	
	/* Connection closed */
	if(buf_len == 0)
	  {
	     /* If it was a human user.  */
	     if((user->type & (LINKED | FORKED)) == 0)
	       {		       
		  if((int)user->nick[0] > 0x20)
		    logprintf(1, "%s from %s at socket %d hung up\n", user->nick, user->hostname, user->sock);
		  else
		    logprintf(1, "User at socket %d from %s hung up\n", user->sock, user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;		  		
	       }
	     else
	       {
		  /* If the parent process disconnected, exit this process.  */
		  if(pid <= 0)
		    {
		       if(count_users(FORKED) == 1)
			 kill_forked_process();
		    }

		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		  
		  /* If it was a forked process, check if we have a listening
		   * process. I we don't, we fork.  */
		  if((user->type == FORKED) && (get_listening_pid() == 0) 
		     && (pid > 0)) 
		    do_fork = 1;
	       }
	     return 0;
	  } 
	else if(errno == ECONNRESET)
	  {
	     if((user->type & (LINKED | FORKED)) == 0)
	       {		  
		  if((int)user->nick[0] > 0x20)
		    logprintf(1, "%s from %s at socket %d hung up (Connection reset by peer)\n", user->nick, user->hostname, user->sock);
		  else
		    logprintf(1, "User at socket %d from %s hung up (Connection reset by peer)\n", user->sock, user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	       }	     
	     else
	       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	     return 0;	       
	  }
	else if(errno == ETIMEDOUT)
	  {
	     if((user->type & (LINKED | FORKED)) == 0)
	       {		  
		  if((int)user->nick[0] > 0x20)
		    logprintf(1, "%s from %s at socket %d hung up (Connection timed out)\n", user->nick, user->hostname, user->sock);
		  else
		    logprintf(1, "User at socket %d from %s hung up (Connection timed out)\n", user->sock, user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	       }	     
	     else
	       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	     return 0;
	  }
	else if(errno == EHOSTUNREACH)
	  {
	     if((user->type & (LINKED | FORKED)) == 0)
	       {		  
		  if((int)user->nick[0] > 0x20)
		    logprintf(1, "%s from %s at socket %d hung up (No route to host)\n", user->nick, user->hostname, user->sock);
		  else
		    logprintf(1, "User at socket %d from %s hung up (No route to host)\n", user->sock, user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	       }
	     else
	       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	     return 0;	       
	  }
	else
	  {
	     logprintf(4, "Error - In get_socket_action()/socket_action()/recv() when receiving from %s: ", user->hostname);
	     logerror(4, errno);
	     return -1;
	  }
     } 
   else 
     {
	/* Set the char after the last received one in buf to null in case the memory
	 * position was set to something else than null before */
	buf[buf_len] = '\0';
	
	/* If the inbuf is empty */
	if(user->buf == NULL)
	  {
	     if((command_buf = malloc(sizeof(char) * (buf_len + 1))) == NULL)
	       {
		  logprintf(1, "Error - In socket_action()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	       }
	     strncpy(command_buf, buf, buf_len + 1);
	     command_buf[buf_len] = '\0';
	     if(strchr(command_buf, '|') != NULL)
	       {
		  if(handle_command(command_buf, user) == 0)
		    {
		       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		       free(command_buf);
		       return 0;
		    }
	       }
	     
	     /* If the string doesn't contain the '|' at all */
	     if(strchr(buf, '|') == NULL)
	       {
		  if((user->buf = malloc(sizeof(char) * (buf_len + 1))) == NULL)
		    {
		       logprintf(1, "Error - In socket_action()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       free(command_buf);
		       return -1;
		    }
		  strncpy(user->buf, buf, buf_len + 1);
		  user->buf[buf_len] = '\0';
	       }
	     else
	       /* If the string continues after the last '|' */
	       {
		  size_t tail_len = strlen(strrchr(buf, '|') + 1);
		  if((user->buf = malloc(sizeof(char) * (tail_len + 1))) == NULL)
		    {
		       logprintf(1, "Error - In socket_action()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       free(command_buf);
		       return -1;
		    }
		  strncpy(user->buf, strrchr(buf, '|') + 1, tail_len + 1);
		  user->buf[tail_len] = '\0';
	       }
	  }
	else
	  /* We have something in the inbuf */
	  {
	     if((command_buf = malloc(sizeof(char) * (buf_len + strlen(user->buf) + 1))) == NULL)
	       {
		  logprintf(1, "Error - In socket_action()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	       }
	     snprintf(command_buf, buf_len + strlen(user->buf) + 1, "%s%s", user->buf, buf);
	     if(strchr(command_buf, '|') != NULL)
	       {
		  if(handle_command(command_buf, user) == 0)
		    {
		       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		       free(command_buf);
		       return 0;
		    }
	       }
	     
	     /* If the string doesn't contain a '|' */
	     if(strchr(buf, '|') == NULL)
	       {
		  size_t old_len = strlen(user->buf);
		  size_t new_size = buf_len + old_len + 1;
		  if((user->buf = realloc(user->buf, sizeof(char)
		      * new_size)) == NULL)
		    {
		       logprintf(1, "Error - In socket_action()/realloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       free(command_buf);
		       return -1;
		    }
		  strncpy(user->buf + old_len, buf, new_size - old_len);
		  user->buf[new_size - 1] = '\0';
		  
		  /* The buf shouldn't be able to grow too much. If it gets 
		   * really big, it's probably due to some kind of attack */
		  if(strlen(user->buf) >= MAX_BUF_SIZE)
		    {
		       if(user->rem == 0)
			 logprintf(1, "User from %s had too big buf, kicking user\n", user->hostname);
		       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		    }
	       }	     
	     
	     /* If the string continues after the last '|' */
	     else if(strlen(strrchr(buf, '|')) > 1)
	       {
		  size_t tail_len = strlen(strrchr(buf, '|') + 1);
		  if((user->buf = realloc(user->buf, sizeof(char)
			   * (tail_len + 1))) == NULL)
		    {
		       logprintf(1, "Error - In socket_action()/realloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       free(command_buf);
		       return -1;
		    }
		  strncpy(user->buf, strrchr(buf, '|') + 1, tail_len + 1);
		  user->buf[tail_len] = '\0';
   
		  /* The buf shouldn't be able to grow too much. If it gets 
		   * really big, it's probably due to some kind of attack.  */
		  if(strlen(user->buf) >= MAX_BUF_SIZE)
		    {
		       if(user->rem == 0)
			 logprintf(1, "User from %s had to big buf, kicking user\n", user->hostname);
		       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		    }
	       }
	     
	  
	     /* The string ends with the '|' */
	     else
	       {	
		  free(user->buf);
		  user->buf = NULL;	
	       }
	  }
	
	logprintf(5, "PID: %d Received command from %s, type 0x%X: %s\n", 
		    (int)getpid(), user->hostname, user->type, command_buf);

	if(command_buf != NULL)
	  free(command_buf);

	return 1;
     }
}

/* Handles udp packages. */
int udp_action(void)
{
   int mess_len;
   int sin_len;
   char message[4096];
   struct sockaddr_in sin;
   struct user_t *user_list;
   struct addrinfo hints, *res;
   int gai_ret;
   char ip_str[INET_ADDRSTRLEN];
   int i=0;
   
   memset(&sin, 0, sizeof(struct sockaddr_in));
   sin_len = sizeof(struct sockaddr);
   
   while(((mess_len = recvfrom(listening_udp_socket, message, sizeof(message), 0,
	    (struct sockaddr *)&sin, &sin_len)) == -1) 
	 && ((errno == EAGAIN) || (errno == EINTR)))
     {
	i++;
	usleep(500);
	/* Giving up after half a second */
	if(i == 1000)
	  break;
     }
   
   if(mess_len <= 0)
     {	
	logprintf(4, "Error - In udp_action()/recvfrom(): ");
	logerror(4, errno);
	return -1;
     }     
   
   message[mess_len] = '\0';
   
   /* Check if user is in the list */
   user_list = non_human_user_list;
   while(user_list != NULL)
     {
	if(user_list->type == LINKED)
	  {
	     memset(&hints, 0, sizeof(hints));
	     hints.ai_family = AF_INET;
	     hints.ai_socktype = SOCK_DGRAM;
	     gai_ret = getaddrinfo(user_list->hostname, NULL, &hints, &res);
	     if(gai_ret != 0)
	       {
		  logprintf(1, "Error - In udp_action()/getaddrinfo(): %s\n", gai_strerror(gai_ret));
		  user_list = user_list->next;
		  continue;
	       }
	     if((((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == sin.sin_addr.s_addr) && (user_list->key == ntohs(sin.sin_port)))
	       {
		  if(strncmp(message, "$Search ", 8) == 0)
		    search(message, user_list);
		  else if(strncmp(message, "$ConnectToMe ", 13) == 0)
		    connect_to_me(message, user_list);
	       }
	     freeaddrinfo(res);
	  }
	user_list = user_list->next;
     }	
   
   if((strncmp(message, "$Up ", 4) == 0) || (strncmp(message, "$UpToo ", 7) == 0))
     up_cmd(message, ntohs(sin.sin_port));
   
   inet_ntop(AF_INET, &sin.sin_addr, ip_str, sizeof(ip_str));
   logprintf(5, "Received udp packet from %s, port %d:\n%s\n",
	       ip_str, ntohs(sin.sin_port), message);
   
   return 1;
}
  

/* Takes password and encrypts it using bcrypt (preferred) or MD5 crypt fallback */
void encrypt_pass(char* password)
{
  const char *result;
  char entropy[16];

  if(crypt_enable == 0)
    return;

  /* Read entropy from /dev/urandom */
  {
     int ufd = open("/dev/urandom", O_RDONLY);
     if(ufd >= 0)
       {
	  if(read(ufd, entropy, sizeof(entropy)) != sizeof(entropy))
	    {
	       /* Fallback: seed with time+pid */
	       unsigned long seed[2];
	       seed[0] = time(NULL);
	       seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);
	       memcpy(entropy, seed, sizeof(seed) < sizeof(entropy) ? sizeof(seed) : sizeof(entropy));
	    }
	  close(ufd);
       }
     else
       {
	  unsigned long seed[2];
	  seed[0] = time(NULL);
	  seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);
	  memcpy(entropy, seed, sizeof(seed) < sizeof(entropy) ? sizeof(seed) : sizeof(entropy));
       }
  }

#ifdef HAVE_CRYPT_GENSALT
  /* Use bcrypt ($2b$) with cost factor 12 */
  {
     char *salt = crypt_gensalt("$2b$", 12, entropy, sizeof(entropy));
     if(salt != NULL)
       {
	  result = crypt(password, salt);
	  if(result != NULL && strncmp(result, "$2", 2) == 0)
	    {
	       strncpy(password, result, MAX_ADMIN_PASS_LEN);
	       password[MAX_ADMIN_PASS_LEN] = '\0';
	       return;
	    }
       }
     /* If bcrypt fails, fall through to MD5 crypt */
     logprintf(1, "Warning: bcrypt failed, falling back to MD5 crypt\n");
  }
#endif

  /* Fallback: MD5 crypt ($1$) */
  {
     const char *const seedchars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
     char salt[] = "$1$........";
     unsigned long seed[2];
     int i;
     memcpy(seed, entropy, sizeof(seed));
     for (i = 0; i < 8; i++)
       salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];
     result = crypt(password, salt);
     if(result != NULL)
       {
	  strncpy(password, result, MAX_ADMIN_PASS_LEN);
	  password[MAX_ADMIN_PASS_LEN] = '\0';
       }
  }
}

 

/**********************************************************/
/* Main function */
int main(int argc, char *argv[])
{
   int ret;
   int erret;
   int x;
#ifdef SWITCH_USER
   struct passwd *userinfo;
   struct group *groupinfo;
   int got_user = 0;
   int got_group = 0;
   cap_t cap;
   int cap_failed = 0;
   cap_value_t caps[1];
   caps[0] = CAP_NET_BIND_SERVICE;
#endif

   max_sockets = getdtablesize();
   
#ifndef HAVE_POLL
# ifdef FD_SETSIZE
   if(max_sockets > FD_SETSIZE)
     max_sockets = FD_SETSIZE;
# endif
#endif
   
   /* Init some variables */
   listening_socket = -1;
   debug = 0;
   do_send_linked_hubs = 0;
   do_purge_user_list = 0;
   do_fork = 0;
   upload = 0;
   quit = 0;
   
   verbosity = 4;
   redir_on_min_share = 1;
   hub_full_mess = NULL;
   non_human_user_list = NULL;
   human_sock_list = NULL;
   memset(logfile, 0, MAX_FDP_LEN+1);
   syslog_enable = 0;
   syslog_switch = 0;
   searchcheck_exclude_internal = 0;
   searchcheck_exclude_all = 0;
   kick_bantime = 0;
   searchspam_time = 0;
   working_dir[0] = '\0';
   max_email_len = 50;
   max_desc_len = 100;
   crypt_enable = 1;
   current_forked = 1;
   	
   /* Parse arguments to program */
   for (x = 0; x < argc; x++)
     {
	/* Debug mode */
	if ((strcmp(argv[x], "-d")) == 0)
	  debug = 1;
#ifdef SWITCH_USER
	else if ((strcmp(argv[x], "-u")) == 0)
	  {
	     x++;
	     userinfo = getpwnam(argv[x]);
	     if(userinfo == NULL)
	       {
		  printf("Couldn't locate user: %s\n", argv[x]);
		  perror("getpwnam");
		  exit(EXIT_FAILURE);
	       }
	     dchub_user = userinfo->pw_uid;
	     got_user = 1;
	     if(got_group == 0)
		dchub_group = userinfo->pw_gid;
	  }
	else if ((strcmp(argv[x], "-g")) == 0)
	  {
	     x++;
	     groupinfo = getgrnam(argv[x]);
	     if(groupinfo == NULL)
	       {
		  printf("Couldn't locate group: %s\n", argv[x]);
		  perror("getgrnam");
		  exit(EXIT_FAILURE);
	       }
	     dchub_group = groupinfo->gr_gid;
	     got_group = 1;
	  }
#endif
	/* Print help and exit*/
	else if ((strcmp(argv[x], "-h")) == 0)
	  {
	     printf("\nOpen DC Hub, version %s\n", VERSION);
	     printf("  -d           : Debug mode. Also prevents Open DC Hub from making itself a\n                 background daemon.\n");
	     printf("  -h           : Print this help and exit.\n");
	     printf("  --version    : Print version.\n");
	     printf("  -l <logfile> : Set logfile.\n");
	     printf("  -s           : Use syslog instead of a logfile.\n");
	     printf("  -w <path>    : Set the path to the working directory.\n");
#ifdef SWITCH_USER
	     printf("  -u <user>    : User to switch to run as.\n");
	     printf("  -g <group>   : Group to switch to run as.\n");
#endif
	     exit(EXIT_SUCCESS);
	}
	/* Set logfile */
	else if ((strcmp(argv[x], "-l")) == 0)
	  {
	     x++;
	     /* Check if argv[x] is usable as logfile.  */
	     if((ret = open(argv[x], O_RDWR | O_CREAT, 0600)) >= 0)
	       {
		  /* Set logfile. */
		  strncpy(logfile,argv[x],MAX_FDP_LEN);
		  printf("Using logfile: %s\n", logfile);
		  close(ret);
		}
	     else
	       {
		  printf("Couldn't open logfile: %s\n", argv[x]);
		  perror("open");
		  exit(EXIT_FAILURE);
	       }	     
	  }
	else if ((strcmp(argv[x], "-s")) == 0)
	  {
	     syslog_switch = 1;
	     openlog(SYSLOG_IDENT, LOG_ODELAY, LOG_USER);
	  }
	else if ((strcmp(argv[x], "-w")) == 0)
	  {
	     x++;
	     strncpy(working_dir, argv[x], MAX_FDP_LEN);
	     if((ret = access(working_dir, F_OK)) < 0)
	       {
		  printf("Directory does not exist: %s\n", argv[x]);
		  perror("access");
		  exit(EXIT_FAILURE);
	       }
	  }
	else if ((strcmp(argv[x], "--version"))== 0)
	  {
	     printf("Open DC Hub %s\n", VERSION);
	     exit(EXIT_SUCCESS);
	  }	
     }
#ifdef SWITCH_USER
   if (got_user)
     {
        if ((geteuid() == 0) && ((cap = cap_init()) != NULL))
	  {
	     if (prctl(PR_SET_KEEPCAPS, 1))
		cap_failed = 1;
	     else if (setgroups(0, NULL) == -1)
		cap_failed = 1;
	     else if ((setegid(dchub_group) == -1)
		      || (seteuid(dchub_user) == -1))
		cap_failed = 1;
	     else if (cap_set_flag(cap, CAP_EFFECTIVE, 1, caps, CAP_SET) == -1)
		cap_failed = 1;
	     else if (cap_set_flag(cap, CAP_PERMITTED, 1, caps, CAP_SET) == -1)
		cap_failed = 1;
	     else if (cap_set_flag(cap, CAP_INHERITABLE, 1, caps, CAP_SET) == -1)
		cap_failed = 1;
	     else if (cap_set_proc(cap) == -1)
		cap_failed = 1;
	     else if ((setresgid(dchub_group, dchub_group, dchub_group) == -1) ||
		      (setresuid(dchub_user, dchub_user, dchub_user) == -1))
		cap_failed = 1;
	     else if (setuid(0) == 0)
		cap_failed = 1;
	     cap_free(cap);
	  }
	else
	   cap_failed = 1;

	if(cap_failed != 0)
	  {
	     perror("Error in switching user\n");
	     exit(EXIT_FAILURE);
	  }
     }
   else
     {
	dchub_user = getuid();
	dchub_group = getgid();
     }
#endif
   
   
   /* This is only a list of addresses to users, not users, so it won't be that
    * space consuming although this will use more memory than a linked list.
    * It's simply faster operation on behalf of more memory usage. */
   if((human_hash_table = calloc(max_sockets + 1, sizeof(struct user_t *))) == NULL)
     {
	printf("Couldn't initiate human_hash_table.\n");
	perror("calloc");
	exit(EXIT_FAILURE);
     }
   
   if(init_dirs() == 0)
     return 1;
   
   logprintf(1, "***Started Open DC Hub version %s***\n", VERSION);
   hub_start_time = time(NULL);
   if(read_config() == -1)
     {
	if(set_default_vars() == 0)
	  {
	     logprintf(1, "Failed setting config variables! Exiting\n");
	     exit(EXIT_FAILURE);
	  }
	if(write_config_file() == -1)
	  {
	     logprintf(1, "Failed writing config file! Exiting\n");
	     exit(EXIT_FAILURE);
	  }
	logprintf(1, "Created config file\n");
     }
#ifdef HAVE_SYSLOG_H
   if((syslog_enable != 0) && (syslog_switch == 0))
     {
	logprintf(1, "***Switching to syslog***\n");
	openlog(SYSLOG_IDENT, LOG_ODELAY, LOG_USER);
     }
#endif
   if((ret = write_motd("Welcome to the hub. Enjoy your stay.", 0)) == -1)
     {
	logprintf(1, "Failed creating motd file! Exiting\n");
	exit(EXIT_FAILURE);
     }
   else if(ret == 1)
     logprintf(1, "Created motd file\n");
   
   create_banlist();
   create_gaglist();
   create_nickbanlist();
   create_allowlist();
   create_reglist();
   create_linklist();
   create_op_permlist();
   if((int)hub_hostname[0] <= 0x20)
     if(set_hub_hostname() == -1)     
       return 1;

   /* Test if we can open the listening socket.  */
   if((listening_socket = get_listening_socket(listening_port, 0)) == -1)
     {
	printf("Bind failed.\nRemember, to use a listening port below 1024, you need to be root.\nAlso, make sure that you don't have another instance of the program\nalready running.\n");
	close(listening_unx_socket);
	close(listening_udp_socket);
	return 1;
     }
   
   while(((erret =  close(listening_socket)) != 0) && (errno == EINTR))
     logprintf(1, "Error - main()/close(): Interrupted system call. Trying again.\n");	
   
   if(erret != 0)
     {	
	logprintf(1, "Error - main/close(): ");
	perror("close");
	return 1;
     }
   
   listening_socket = -1;

#ifdef HAVE_SSL
   /* Check for port conflicts */
   if(tls_port != 0 && tls_port == listening_port)
     {
	printf("Error: tls_port %u conflicts with listening_port. Disabling TLS.\n",
	       tls_port);
	tls_port = 0;
     }

   /* Initialize SSL/TLS if configured */
   if(tls_port != 0 && tls_cert_file[0] != '\0' && tls_key_file[0] != '\0')
     {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
	SSL_load_error_strings();
#endif
	if(init_ssl_ctx() == 0)
	  {
	     /* Test if we can open the TLS listening socket */
	     int tls_test_sock = get_listening_socket(tls_port, 0);
	     if(tls_test_sock == -1)
	       {
		  printf("TLS bind failed on port %u. Disabling TLS.\n", tls_port);
		  cleanup_ssl_ctx();
		  tls_port = 0;
	       }
	     else
	       {
		  close(tls_test_sock);
	       }
	  }
	else
	  {
	     printf("SSL initialization failed. Disabling TLS.\n");
	     tls_port = 0;
	  }
     }
#endif

   if((listening_unx_socket = get_listening_unx_socket()) == -1)
     return 1;
   
   if((listening_udp_socket = get_listening_udp_socket(listening_port)) == -1)
     {
	printf("Bind failed.\nRemember, to use a listening port below 1024, you need to be root.\nAlso, make sure that you don't have another instance of the program\nalready running.\n");
	close(listening_unx_socket);
	return 1;     
     }
   
   /* Tell user that hub is running */
   printf("Hub is up and running. Listening for user connections on port %u\n", listening_port);
#ifdef HAVE_SSL
   if(tls_port != 0 && ssl_ctx != NULL)
     printf("and listening for TLS connections on port %u\n", tls_port);
#endif

   /* With -d, for debug, we will run in console so skip this part. */
   if(debug == 0)
      {
	 /* Make program a daemon */
	 pid = fork();
	 if(pid < 0)
	   {
	      perror("fork");
	      exit(EXIT_FAILURE);
	   }
	 if(pid > 0)
	   exit(EXIT_SUCCESS);
	 if(setsid() < 0)
	   {
	      perror("setsid");
	      exit(EXIT_FAILURE);
	   }
	   
	 if(close(STDIN_FILENO) != 0)
	   {
	      logprintf(1, "Error - When closing STDIN_FILENO, exiting\n");
	      exit(EXIT_FAILURE);
	   }
	 if(close(STDOUT_FILENO) != 0)
	   {
	      logprintf(1, "Error - When closing STDOUT_FILENO, exiting\n");
	      exit(EXIT_FAILURE);
	   }
	 if(close(STDERR_FILENO) != 0)
	   {
	      logprintf(1, "Error - When closing STDERR_FILENO, exiting\n");
	      exit(EXIT_FAILURE);
	   }
      }
   
   /* Set pid */
   pid = getpid();
   
    /* Initialize the semaphores.  */
   if(init_sem(&total_share_sem) ==  -1)
     {
	logprintf(1, "Couldn't initialize the total share semaphore.\n");
	exit(EXIT_FAILURE);
     }
   
   if(init_sem(&user_list_sem) ==  -1)
     {
	logprintf(1, "Couldn't initialize the user list semaphore.\n");
	exit(EXIT_FAILURE);
     }
   
   if(init_share_shm() == -1)
     {
	logprintf(1, "Couldn't initialize the total share shared memory segment.\n");
	semctl(total_share_sem, 0, IPC_RMID, NULL);
	semctl(user_list_sem, 0, IPC_RMID, NULL);
     }
   
    if(init_user_list() == -1)
     {
	logprintf(1, "Couldn't initialize the user list.\n");
	semctl(total_share_sem, 0, IPC_RMID, NULL);
	semctl(user_list_sem, 0, IPC_RMID, NULL);
     }
	
   init_sig();

   /* Send initial alarm */
   if((kill(pid, SIGALRM)) < 0)
     {
	return 1;
     }

   /* Initialize JSON gateway socket (parent process only) */
   if(pid > 0 && json_socket_enabled)
     {
	/* Default socket path if not configured */
	if(json_socket_path[0] == '\0')
	  snprintf(json_socket_path, MAX_JSON_SOCK_PATH, "%s/gateway.sock", config_dir);
	if(json_socket_init() != 0)
	  logprintf(1, "Warning - JSON socket initialization failed\n");
     }

   /* Fork process which holds the listening sockets.  */
   if(pid > 0)
     fork_process();
   
   while(quit == 0)
     {
	if(pid > 0)
	  {
	     if((upload != 0) && (hublist_upload != 0))
	       do_upload_to_hublist();
	     if(do_reload_conf != 0)
	       {
		  logprintf(1, "Received SIGHUP, reloading configuration\n");
		  read_config();
		  do_reload_conf = 0;
	       }
	     if(do_write != 0)
	       {
		  write_config_file();
		  do_write = 0;
	       }
	     if(do_send_linked_hubs != 0)
	       {  
		  send_linked_hubs();
		  do_send_linked_hubs = 0;
	       }
	     if(do_purge_user_list != 0)
	       {
		  purge_user_list();
		  do_purge_user_list = 0;
	       }
	     if(do_alarm != 0)
	       {
		  handle_alarm();
		  do_alarm = 0;
	       }
	  }
	get_socket_action();
	clear_user_list();
	if((do_fork == 1) && (pid > 0))
	  {	     
	     fork_process();
	     do_fork = 0;
	  }	
     }
   quit_program();
   remove_all(0xFFFF, 0, 0);
   return 0;
}
