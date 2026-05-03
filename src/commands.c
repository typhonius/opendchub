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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

#include "main.h"
#include "utils.h"
#include "fileio.h"
#include "commands.h"
#include "network.h"
#include "userlist.h"
#include "json_socket.h"

#ifndef HAVE_STRTOLL
# ifdef HAVE_STRTOQ
#  define strtoll(X, Y, Z) (long long)strtoq(X, Y, Z)
# endif
#endif

/* This command has the following format:
 * $SR fromnick filename\5filesize openslots/totalslots\5hubname (hubip:hubport)\5tonick| */
void sr(char *buf, struct user_t *user)
{
   char command[6];
   char fromnick[MAX_NICK_LEN+1];
   char filename[501]; /* Should do */
   long long unsigned filesize;
   int openslots;
   int totalslots;
   char hubname[301];
   char tonick[MAX_NICK_LEN+1];
   char *send_buf;
   struct user_t *to_user;

   if(sscanf(buf, "%5s %50s %500[^\5]\5%llu %d/%d\5%300[^\5]\5%50[^|]|", 
	  command, fromnick, filename, &filesize, &openslots, 
	     &totalslots, hubname, tonick) != 8)
     {
	/* Sometimes, the filesize seems to be skipped. */
	if(sscanf(buf, "%5s %50s %500[^\5]\5%300[^\5]\5%50[^|]|", 
		  command, fromnick, filename, hubname, tonick) != 5)
	  {	     
	     logprintf(4, "Received bad $SR command from %s at %s:\n", 
		       user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }	
     }
   
   /* First a validation check */
   if(tonick[0] == '\0')
     {
	logprintf(4, "Received bad $SR command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if((strncmp(fromnick, user->nick, strlen(fromnick)) != 0)
	   || (strlen(fromnick) != strlen(user->nick)))
	  {
	     logprintf(3, "User %s at %s claims to be someone else in $SR:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(3, "%s\n", buf);
	     else
	       logprintf(3, "too large buf\n");
	     user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	     return;
	  }
     }
  
   if((send_buf = malloc(sizeof(char) * (strlen(buf) + 1))) == NULL)
     {
	logprintf(1, "Error - In sr()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return;
     }
   snprintf(send_buf, strlen(buf) + 1, "%s", buf);

   /* Remove the nick at the end */
   {
      char *p = strrchr(send_buf, '\005');
      if(p != NULL)
	{
	   *(p + 1) = '\0';
	   p = strrchr(send_buf, '\005');
	   if(p != NULL)
	     *p = '|';
	}
   }

   /* And then forward it */
   if((to_user = get_human_user(tonick)) != NULL)
     send_to_user(send_buf, to_user);
   else   
     /* If user wasn't found, forward to other processes */
     send_to_non_humans(buf, FORKED, user);
   
   free(send_buf);
}

/* The search command, has the following format:
 * $Search ip:port byte1?byte2?size?byte3?searchpattern|
 * If the search was made by a client in passive mode, the ip:port is replaced
 * by Hub:nickname */
void search(char *buf, struct user_t *user)
{
   char command[15]; 
   char ip[MAX_HOST_LEN+1];
   char port[MAX_NICK_LEN+1];
   char byte1, byte2, byte3;
   char pattern[51]; /* It's the last argument, so it doesn't matter if it fits in the string */
   long long unsigned size;
   time_t now;

   /* Don't bother to check the command if it was sent from a forked process */
   if(user->type != FORKED)
     {	
	if(sscanf(buf, "%14s %122[^:]:%50s %c?%c?%llu?%c?%50[^|]|", 
		  command, ip, port, &byte1, &byte2, &size, &byte3, pattern) != 8)
	  {
	     logprintf(4, "Received bad $Search command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	
	/* Make sure that the user is the one he claims to be.  */
	if(((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0) &&
	   (searchcheck_exclude_all == 0))
	  {	     
	     char user_ip_str[INET_ADDRSTRLEN];
	     ip_to_string(user->ip, user_ip_str, sizeof(user_ip_str));
	     if(!((strncmp(ip, user_ip_str, strlen(ip)) == 0)
		  || (strncmp(port, user->nick, strlen(port)) == 0)
                  || (is_internal_address(user->ip) == 0)))
	       {
		  logprintf(1, "%s from %s claims to be someone else in $Search, removing user\n", user->nick, user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		  return;
	       }	
	  }
	
	if(pattern[0] == '\0')
	  {
	     logprintf(4, "Received bad $Search command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
     }
   
   if(user->type != FORKED)
     {
	
	now = time(NULL);
	if((searchspam_time > 0) && 
	   (difftime(now, user->last_search) <= (double)searchspam_time))
	  {
	     user->last_search = now;
	     uprintf(user, "<Hub-Security> Search ignored.  Please leave at least %d seconds between search attempts.|", searchspam_time);
	     return;
	  }
	user->last_search = now;
   
   /* If you want to control searches, here is the place to add the source.
    * The search pattern is in the variable pattern. A couple of examples: */
   
   /* If the search is three characters or less, throw it away: */
   /*
    * 
    if(strlen(pattern) <= 3)
        return; 
    */
   
   /* If user is searching for a bad word, tell him about it and kick him: */
   /*
    * 
   if(strstr(pattern, "bad word") != NULL)
     {
	uprintf(user, "<Hub-Security> No searches for bad words in this hub!|");
	user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	return;
     }
    */					 
     }
   
   /* Now, forward to all users */
   send_to_humans(buf, REGULAR | REGISTERED |  OP | OP_ADMIN, NULL);
   send_to_non_humans(buf, FORKED, user);

   /* Send admin event for search.
    * For direct users, we have the parsed nick and pattern.
    * For forked process forwards, parse from buf. */
   if(user->type != FORKED)
     {
	json_event_search(user->nick, pattern);
     }
   else
     {
	/* buf is "$Search ip:port T?F?size?type?pattern|" or "$Search Hub:nick ..."
	 * Parse to extract search pattern for the event */
	char ev_ip[MAX_HOST_LEN+1];
	char ev_port[MAX_NICK_LEN+1];
	char ev_pattern[256];
	memset(ev_ip, 0, sizeof(ev_ip));
	memset(ev_port, 0, sizeof(ev_port));
	memset(ev_pattern, 0, sizeof(ev_pattern));
	if(sscanf(buf, "$Search %122[^:]:%50s %*c?%*c?%*[^?]?%*c?%255[^|]",
		  ev_ip, ev_port, ev_pattern) >= 3)
	  {
	     /* Search events forwarded via JSON socket in json_event_search() */
	  }
     }
}

/* Search on linked hubs, same format as $Search */
void multi_search(char *buf, struct user_t *user)
{
   char command[15]; 
   char ip[MAX_HOST_LEN+1];
   unsigned int port;
   char byte1, byte2, byte3;
   char pattern[11];
   char *temp;   
   long long unsigned size;
   
   if(sscanf(buf, "%14s %122[^:]:%u %c?%c?%llu?%c?%10[^|]|", 
	     command, ip, &port, &byte1, &byte2, &size, &byte3, pattern) != 8)
     {	
	logprintf(4, "Received bad $MultiSearch command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   if(pattern[0] == '\0')
     {                                                                               
	logprintf(4, "Received bad $MultiSearch command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   
   /* If we are the parent, forward it to linked hubs. Otherwise, forward to 
    * parent process */  
   
   if(pid > 0)
     {
	/* Send $Search to linked hubs */
	temp = buf+5;
	temp[0] = '$';	
	send_to_non_humans(temp, LINKED, user);
	temp[0] = 'i';
     }
   else
     send_to_non_humans(buf, FORKED, user);
}

/* Connect to users on linked hubs, the format is:
 * $MultiConnectToMe requested_user requesting_ip:requesting_port hub_ip:hub_port, 
 * but the hubport doesn't show if it's 411 */
void multi_connect_to_me(char *buf, struct user_t *user)
{
   int i;
   char command[21];
   char requested[MAX_NICK_LEN+1];
   char ip[MAX_HOST_LEN+1];
   char hubip[MAX_HOST_LEN+10];
   unsigned int port;
   char *temp;
   char *pointer;
   char save1, save2;
   
   if(sscanf(buf, "%20s %50s %121[^:]:%u %130[^|]|", command, requested, 
	     ip, &port, hubip) != 5)
     {                                                                           
	logprintf(4, "Received bad $MultiConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   /* Validation check */
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if(port == 0)
	  {                                                                                  
	     logprintf(4, "Received bad $MultiConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
     }
  
   /* If we are the parent, forward it to linked hubs. Otherwise, forward to 
    * parent process */  
   
   if(pid > 0)
     {
	temp = buf+5;
	pointer = temp;
	for(i = 1; i <= 3; i++)
	  {
	     pointer++;
	     if((pointer = strchr(pointer, ' ')) == NULL)
	       return;
	  }
	save1 = *pointer;
	save2 = *(pointer+1);
	*pointer = '|';
	*(pointer+1) = '\0';
	temp[0] = '$';
	send_to_non_humans(temp, LINKED, user);
	*pointer = save1;
	*(pointer+1) = save2;
	temp[0] = 'i';
     }
   else
     send_to_non_humans(buf, FORKED, user);
}  
	     
	     
/* Forwards to all logged in users.
 * No !command parsing -- all moderation handled by gateway. */
void chat(char *buf, struct user_t *user)
{
   char nick[MAX_NICK_LEN+1];
   char chatstring[31];

   chatstring[0] = '\0';

   /* Only check nick if the command was sent directly from user */
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if(sscanf(buf, "<%50[^>]> %30[^|]|", nick, chatstring) < 1)
	  {
	     logprintf(4, "Received bad chat command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }

	if(chatstring[0] == '\0')
	  {
	     logprintf(4, "Received bad chat command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	if((strncmp(buf + 1, user->nick, strlen(nick)) != 0) || (strlen(nick) != strlen(user->nick)))
	  {
	     logprintf(3, "User %s at %s claims to be someone else in chat:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(3, "%s\n", buf);
	     else
	       logprintf(3, "too large buf\n");
	     user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	     return;
	  }
     }

   /* Forward to gateway for decision (gag check, broadcast, storage).
    * The gateway will echo back via send_raw if the message should be broadcast.
    * Parse "<nick> message|" into nick and message for the JSON event. */
   {
      char json_nick[MAX_NICK_LEN+1];
      const char *msg_start;
      if(buf[0] == '<')
	{
	   const char *end = strchr(buf + 1, '>');
	   if(end != NULL)
	     {
		int nlen = end - buf - 1;
		if(nlen > MAX_NICK_LEN) nlen = MAX_NICK_LEN;
		strncpy(json_nick, buf + 1, nlen);
		json_nick[nlen] = '\0';
		msg_start = end + 1;
		if(*msg_start == ' ') msg_start++;
		/* Strip trailing pipe */
		int mlen = strlen(msg_start);
		if(mlen > 0 && msg_start[mlen-1] == '|') mlen--;
		char *msg_clean = malloc(mlen + 1);
		if(msg_clean != NULL)
		  {
		     memcpy(msg_clean, msg_start, mlen);
		     msg_clean[mlen] = '\0';
		     json_event_chat(json_nick, msg_clean);
		     free(msg_clean);
		  }
	     }
	}
   }
}

/* Forwards request from one user to another,
 $RevConnectToMe requesting_user requested_user| i.e, the other way around if you compare it
 with $ConnectToMe */
void rev_connect_to_me(char *buf, struct user_t *user)
{
   char command[21];
   char requesting[MAX_NICK_LEN+1];
   char requested[MAX_NICK_LEN+1];
   struct user_t *to_user;
   
   if(sscanf(buf, "%20s %50s %50[^|]|", command, requesting, requested) != 3)
     {                                                                           
	logprintf(4, "Received bad $RevConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
  
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if(requested[0] == '\0')
	  {	                                                                               
	     logprintf(4, "Received bad $RevConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	if((strncmp(requesting, user->nick, strlen(requesting)) != 0) 
	    || (strlen(requesting) != strlen(user->nick)))
	    {	                                                                                   
	       logprintf(3, "User %s at %s claims to be someone else in $RevConnectToMe:\n", user->nick, user->hostname);
	       if(strlen(buf) < 3500)
		 logprintf(3, "%s\n", buf);
	       else
		 logprintf(3, "too large buf\n");
	       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	       return;
	    }
     }
   
   /* And forward to requested user.  */
   if((to_user = get_human_user(requested)) != NULL)
     send_to_user(buf, to_user);
   else
     send_to_non_humans(buf, FORKED, user);
}
       

/* Forwards request from one user to another. The command has the following fomat:
 $ConnectToMe requested_user requesting_ip:requesting_port */
void connect_to_me(char *buf, struct user_t *user)
{
   char command[21];
   char requested[MAX_NICK_LEN+1];
   char ip[MAX_HOST_LEN+1];
   unsigned int port;
   struct user_t *to_user;
   
   if(sscanf(buf, "%20s %50s %121[^:]:%u|", command, requested, ip, &port) != 4)
     {                                                                        
	logprintf(4, "Received bad $ConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   /* Validation check */
     if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN | LINKED)) != 0)
     {
	if(port == 0)
	  {	                                                                            
	     logprintf(4, "Received bad $ConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
     }
	
   /* And forward to requested user */
   if((to_user = get_human_user(requested)) != NULL)
     send_to_user(buf, to_user);
   else
     send_to_non_humans(buf, FORKED, user);
}
   
/* Send message from user to specified user, has the following format:
 * $To: tonick From: fromnick $message string| */
void to_from(char *buf, struct user_t *user)
{
   char command[6];
   struct user_t *to_user;
   char fromnick[MAX_NICK_LEN+1];
   char tonick[MAX_NICK_LEN+1];
   char chatnick[MAX_NICK_LEN+1];
   char message[11];
   
   if(sscanf(buf, "%5s %50s From: %50s $<%50[^>]> %10[^|]|", command, tonick, fromnick, chatnick, message) != 5)
     {                                                                
	logprintf(4, "Received bad $To command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if(message[0] == '\0')
	  {	                                                                    
	     logprintf(4, "Received bad $To command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	if((user->type & (REGULAR | REGISTERED)) != 0)
	  {	     
	     if(((strncmp(fromnick, user->nick, strlen(fromnick)) != 0) 
		 || (strlen(fromnick) != strlen(user->nick))) 
		|| ((strncmp(chatnick, user->nick, strlen(fromnick)) != 0) 
		    || (strlen(chatnick) != strlen(user->nick))))
	       {	                                                                   	                        
		  logprintf(3, "User %s at %s claims to be someone else in $To:\n", user->nick, user->hostname);
		  if(strlen(buf) < 3500)
		    logprintf(3, "%s\n", buf);
		  else
		    logprintf(3, "too large buf\n");
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		  return;
	       }
	  }	
     }
   
   /* And forward the message to specified user.  */
   if((to_user = get_human_user(tonick)) != NULL)
     {
	/* Virtual user: forward PM to gateway instead of sending over socket */
	if(to_user->sock == -1)
	  {
	     char *pm_start = strstr(buf, "$<");
	     if(pm_start != NULL)
	       {
		  char *msg_body = strchr(pm_start, '>');
		  if(msg_body != NULL)
		    {
		       msg_body++;
		       if(*msg_body == ' ') msg_body++;
		       int msg_len = strlen(msg_body);
		       if(msg_len > 0 && msg_body[msg_len - 1] == '|')
			 msg_len--;
		       char saved = msg_body[msg_len];
		       msg_body[msg_len] = '\0';
		       json_event_pm(user->nick, tonick, msg_body);
		       msg_body[msg_len] = saved;
		    }
	       }
	  }
	else
	  send_to_user(buf, to_user);
     }
   else
     send_to_non_humans(buf, FORKED, user);
}
  

/* If a user wants info about one other, it looks like this:
 * $GetINFO requested_user requesting_user| */
void get_info(char *buf, struct user_t *user)
{
   char command[11];
   char requesting[MAX_NICK_LEN+1];
   char requested[MAX_NICK_LEN+1];
   struct user_t *from_user;
   
   if(sscanf(buf, "%10s %50s %50[^|]|", command, requested, requesting) != 3)
     {                                                                    
	logprintf(4, "Received bad $GetINFO command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if(requesting[0] == '\0')
	  {                                                                         
	     logprintf(4, "Received bad $GetINFO command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	if((strncmp(requesting, user->nick, strlen(requesting)) != 0) 
	    || (strlen(requesting) != strlen(user->nick)))
	    {	                                                                       	                      
	       logprintf(3, "User %s at %s claims to be someone else in $GetINFO:\n", user->nick, user->hostname);
	       if(strlen(buf) < 3500)
		 logprintf(3, "%s\n", buf);
	       else
		 logprintf(3, "too large buf\n");
	       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	       return;
	    }
     }
  
   /* Check if the requested user is connected to this process.  */
   if((from_user = get_human_user(requested)) != NULL)
     {
	/* If the requesting user is connected to this process.  */
	if(get_human_user(requesting) != NULL)
	  send_user_info(from_user, requesting, TO_ALL);
	/* If the requesting user isn't connected to this process, forward it.  */
	else
	  send_user_info(from_user, requesting, PRIV);
     }   
   else
     send_to_non_humans(buf, FORKED, user);
}

/* Handles the MyINFO command. Returns 0 if user should be removed. 
 * Has the following format:
 * $MyINFO $ALL nickname filedescription$ $connection type$email$sharesize$| 
 * Since some of these variables can be empty, I havent used sscanf which 
 * makes this function a little bit hard to follow.  */
int my_info(char *org_buf, struct user_t *user)
{
   int i, k, ret;
   int desc_too_long = 0;
   int email_too_long = 0;
   char *buf;
   char *send_buf;
   char hello_buf[MAX_NICK_LEN+9];
   char temp_size[50];
   char to_nick[MAX_NICK_LEN+1];
   char temp_nick[MAX_NICK_LEN+1];
   struct user_t *to_user;
   char quit_string[MAX_NICK_LEN+10];
   struct user_t *save_user = NULL;
   int new_user = 0;   /* 0 for users that are already logged in, 1 for users
			 * who send $MyINFO for the first time.  */
   
   buf = org_buf + 9;
   
   /* Check if message is for all or for a specific user */
   if(strncmp(buf, "ALL ", 4) == 0)
     {
	buf += 4;
	
	/* If user is a process, just forward the command.  */
	if(user->type == FORKED)
	  {
	     send_to_non_humans(org_buf, FORKED, user);
	     send_to_humans(org_buf, REGULAR | REGISTERED | OP | OP_ADMIN,
			    user);
	     /* Emit MYINFO event for MyINFO forwarded from child process.
	      * buf points past "$MyINFO $ALL ", so it starts with "nick ..." */
	     return 1;
	  }
	if(*user->nick == (char) NULL)
	  return 0;
	
	/* Registration checks removed — gateway handles auth */
     }
   else
     {	
	/* It's not $MyINFO $ALL, but $MyINFO to_nick, so send $MyINFO $ALL to
	 * the specified user in to_nick.  */
	i = cut_string(buf, ' ');
	if((i == -1) || (i>50) || (user->type != FORKED))
	  return -1;
	
	strncpy(to_nick, buf, i);
	to_nick[i] = '\0';
	buf += (i + 1);
	
	/* Check if the destination user is in this process */
	if(((to_user = get_human_user(to_nick)) != NULL) 
	   || (strncmp(to_nick, "$Script", 7) == 0))
	  {
	     if((send_buf = malloc(sizeof(char) * (strlen(buf) + 14))) == NULL)
	       {
		  logprintf(1, "Error - In my_info()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	       }
	     snprintf(send_buf, strlen(buf) + 14, "$MyINFO $ALL %s", buf);
	     send_to_user(send_buf, to_user);
	     free(send_buf);
	  }
	else
	  /* The user wasn't connected to this process, forward to other 
	   * processes.  */
	  send_to_non_humans(org_buf, FORKED, user);
	
	return 1;
     }  
   
   /* If the user was NON_LOGGED before, or if the flag was 0, it's the first 
    * time the user sends $MyINFO $ALL.  */
   if((user->type == NON_LOGGED) 
      || ((user->flag == 0) 
	  && ((user->type & (REGISTERED | OP | OP_ADMIN)) != 0)))
     new_user = 1;
   
   /* First set users variables */
   if(((i = cut_string(buf, ' ')) == -1)
      || cut_string(buf, ' ') > cut_string(buf, '$'))
     return 0;
     
   sscanf(buf, "%50s", temp_nick);
   
   /* If we are a script process, temporary save the parent process user.  */
   if(pid == -1)
     {
	save_user = user;
	if((user = get_human_user(temp_nick)) == NULL)
	  return -1;
     }   
   
   /* Make sure that user isn't on the user list already. This could only
    * happen if a user first sends ValidateNick, then the process forks, and
    * after that the user sends MyINFO $ALL.  */
   if(user->type == NON_LOGGED)
     {		
	if((check_if_on_user_list(temp_nick)) != NULL)
	  return 0;
     }
   
   /*�If the command was sent from a human, make sure that the provided nick 
    * matches the one provided with $ValidateNick.  */
    if((user->type & (NON_LOGGED | REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
     {
	if((strncmp(temp_nick, user->nick, strlen(user->nick)) != 0)
	   || (strlen(temp_nick) != strlen(user->nick)))
	  {
	     logprintf(3, "User from %s provided a nick in $MyINFO that does not match the one from $ValidateNick, removing user.\n", user->hostname);
	     return 0;
	  }
     }
   
   buf = buf + i + 1;
   
   if(user->desc != NULL)
     {
	free(user->desc);
	user->desc = 0;
     }
     
   if(*buf != '$')
     {
	k = cut_string(buf, '$');
	if((max_desc_len == 0) || (k <= max_desc_len))
	  {
	     if((user->desc = (char *) malloc(sizeof(char) * (k + 1))) == NULL)
	       {
		  logprintf(1, "Error - In my_info()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	        }
	     strncpy(user->desc, buf, k);
	     user->desc[k] = '\0';
	  }
	else
	     desc_too_long = 1;
	buf = buf + k + 1;
     }
   buf++;
   
   /* Not sure if the next argument is ever set to anything else than a 
    * blankspace. Skipping it for now.  */
    if((i = cut_string(buf, '$')) == -1)
     return 0;
   
   buf = buf + i + 1;
   
   /* Get connection of user */
    if((i = cut_string(buf, '$')) == -1)
     return 0;
   
   /* Switching the first letter in connection name */
   switch(*buf)
     {
      case '2':
	user->con_type = 1;
	break;
      case '3':
	user->con_type = 2;
	break;
      case '5':
	user->con_type = 3;
	break;
      case 'S':
	user->con_type = 4;
	break;
      case 'I':
	user->con_type = 5;
	break;
      case 'D':
	user->con_type = 6;
	break;
      case 'C':
	user->con_type = 7;
	break;
      case 'L':
	/* We have both T1 and T3 here */
	if(buf[i-3] == '3')
	  user->con_type = 9;
	else
	  user->con_type = 8;
	break;
// @Ciuly: Added a list of connection types (issue derived from 1027168	
      case 'W':
        user->con_type = 10; //Wireless
        break;
      case 'M':
        user->con_type = 11; //Modem
	break;
      case 'N':
        user->con_type = 12; //Netlimiter
	break;
// end @Ciuly
      default:
// Start fix for 1027168 by Ciuly
//	return 0;
        user->con_type = 255;//unknown
	break;
// End fix for 1027168
     }
   
   /* Set flag */
   user->flag = (int)buf[i - 1];
   
   buf = buf + i + 1;
   
   if((i = cut_string(buf, '$')) == -1)
     return 0;
	
   if(user->email != NULL)
     {
	free(user->email);
	user->email = 0;
     }

   /* Set email.  */
   if(buf[0] != '$')
     {
	k = cut_string(buf, '$');
	if((max_email_len == 0) || (k <= max_email_len))
	  {
	     if((user->email = (char *) malloc(sizeof(char) * (k + 1))) == NULL)
	       {
		  logprintf(1, "Error - In my_info()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	       }
	     strncpy(user->email, buf, k);
	     user->email[k] = '\0';
	  }
	else
	     email_too_long = 1;
     }
   buf = buf + i + 1;
   
   /* Parse share size.  */
   if((i = cut_string(buf, '$')) == -1)
     return 0;
   
   /* If a user has uploaded share size before, we'll have to subtract the 
    * old share from the total share first.  */
   if(((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0) 
      && (user->share != 0) && (save_user == NULL))
     add_total_share(-user->share);
   
   /* If the size of users share is a number with more than 20 digits, 
    * something must be wrong */
   if(i>20)
     return 0;

   memset(temp_size, 0, sizeof(temp_size));
   if(*buf != '$')
     {
	strncpy(temp_size, buf, i);
	user->share = strtoll(temp_size,(char **)NULL, 10);
     }
   else
     user->share = 0;

   /* Switch back to the parent process user.  */
   if(save_user != NULL)
     user = save_user;
   
   /* Check if user is sharing enough.  */
   /* Op:s don't have to meet the requirement for now. May be optional in 
    * the future.  */
   if(((user->type & (NON_LOGGED | REGULAR | REGISTERED)) != 0)
      && (user->share < min_share))
     {
	user->flag = 0;
	if(min_share < (1 << 30))
	  {
	     if((redir_on_min_share == 1) && (redirect_host != NULL) && ((int)redirect_host[0] > 0x20))
	       {		  
		  uprintf(user, "$Hello %s|$To: %s From: Hub $Minimum share for this hub is %lld MegaBytes. You are being redirected.|", user->nick, user->nick, (long long)min_share / (1024*1024));
		  uprintf(user, "$ForceMove %s|", redirect_host);
		  logprintf(1, "User %s at %s doesn't share enough, redirecting user\n", user->nick, user->hostname);		  
		  if((user->type & (REGULAR | REGISTERED)) != 0)
		    {
		       remove_user_from_list(user->nick);
		       remove_human_from_hash(user->nick);
		       user->type = NON_LOGGED;
		       snprintf(quit_string, sizeof(quit_string), "$Quit %s|", user->nick);
		       send_to_humans(quit_string, REGULAR | REGISTERED | OP
				      | OP_ADMIN, user);
		       send_to_non_humans(quit_string, FORKED, NULL);
		    }
		  return 1;
	       }
	     else
	       uprintf(user, "$Hello %s|$To: %s From: Hub $Minimum share for this hub is %lld MegaBytes. Please share some more.|", user->nick, user->nick, (long long)min_share / (1024*1024));
	  }

	else
	  {
	     if((redir_on_min_share == 1) && (redirect_host != NULL) && ((int)redirect_host[0] > 0x20))
	       {
		  uprintf(user, "$Hello %s|$To: %s From: Hub $Minimum share for this hub is %2.2f GigaBytes. You are being redirected.|", user->nick, user->nick, (double)min_share / (1024*1024*1024));
		  uprintf(user, "$ForceMove %s|", redirect_host);
		  logprintf(1, "User %s at %s doesn't share enough, redirecting user\n", user->nick, user->hostname);
		  if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN))
		     != 0)
		    {
		       remove_user_from_list(user->nick);
		       remove_human_from_hash(user->nick);
		       user->type = NON_LOGGED;
		       snprintf(quit_string, sizeof(quit_string), "$Quit %s|", user->nick);
		       send_to_humans(quit_string, REGULAR | REGISTERED | OP
				      | OP_ADMIN, user);
		       send_to_non_humans(quit_string, FORKED, NULL);
		    }		  
		  return 1;
	       }
	     else
	       uprintf(user, "$Hello %s|$To: %s From: Hub $Minimum share for this hub is %2.2f GigaBytes. Please share some more.|", user->nick, user->nick, (double)min_share / (1024*1024*1024));
	  }
	
	logprintf(1, "User %s at %s doesn't share enough, kicking user\n", user->nick, user->hostname);
	return 0;
     }

   /* Disconnect user if email or descriptions are too long */
   if(desc_too_long != 0)
     {
	uprintf(user, "$Hello %s|$To: %s From: Hub $Your description is too long for this hub.  The maximum allowed description is %d characters, please modify yours.|", user->nick, user->nick, max_desc_len);
	logprintf(1, "User %s at %s has too long a description, kicking user\n", user->nick, user->hostname);
	return 0;
     }
   if(email_too_long != 0)
     {
	uprintf(user, "$Hello %s|$To: %s From: Hub $Your email address is too long for this hub.  The maximum allowed email address is %d characters, please modify yours.|", user->nick, user->nick, max_email_len);
	logprintf(1, "User %s at %s has too long an email address, kicking user\n", user->nick, user->hostname);
	return 0;
     }
   
   /* If the user has been non logged in so far, send Hello string first.  */
   if((user->type & (NON_LOGGED | FORKED)) != 0)
     {
	snprintf(hello_buf, sizeof(hello_buf), "$Hello %s|", user->nick);
	send_to_non_humans(hello_buf, FORKED, user);
	send_to_humans(hello_buf, REGULAR | REGISTERED | OP | OP_ADMIN, user);
     }

    /* By now, the user should have passed all tests and therefore be counted
     * as logged in.  */
   if(user->type == NON_LOGGED)
     {	
	user->type = REGULAR;
	logprintf(1, "%s logged in from %s\n", user->nick, user->hostname);
     }       
   
   /* Add share to total_share.  */
   if((user->type & (FORKED)) == 0)
     add_total_share(user->share);
   
   /* And then send the MyINFO string. */
   send_to_non_humans(org_buf, FORKED, user);

   send_to_humans(org_buf, REGULAR | REGISTERED | OP | OP_ADMIN, NULL);

   /* Send admin events for JOIN (new users) and MYINFO (all updates).
    * For MYINFO, forward the original MyINFO string after "$MyINFO $ALL ". */
   if(new_user != 0)
     {
	/* JSON event: user join */
	{
	   char ip_str[INET_ADDRSTRLEN];
	   struct in_addr addr;
	   addr.s_addr = user->ip;
	   inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
#ifdef HAVE_SSL
	   json_event_user_join(user->nick, ip_str, user->ssl != NULL);
#else
	   json_event_user_join(user->nick, ip_str, 0);
#endif
	}
     }
   /* JSON event: myinfo update */
   json_event_myinfo(user->nick,
		     user->desc ? user->desc : "",
		     "", /* speed derived from con_type, but user_list sends it */
		     user->email ? user->email : "",
		     user->share);

   if((new_user != 0) && (user->type == REGULAR))
     add_human_to_hash(user);
   
   /* Add user to user list */
   if((user->type & (NON_LOGGED | REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {	
	if((ret = add_user_to_list(user)) == 0)
	  {
	     increase_user_list();
	     if(add_user_to_list(user) == -1)
	       return 0;
	  }	
	else if(ret == -1)
	  return 0;
     }   
   return 1;
}

/* Handles the ValidateNick command */
/* This one has to check if the name is taken or if it is reserved */
/* Returns 0 if user should be kicked */
int validate_nick(char *buf, struct user_t *user)
{
   char temp_nick[MAX_NICK_LEN+1];
   char command[21];
   
   if(sscanf(buf, "%20s %50s|", command, temp_nick) != 2)
     {                                                                         
	logprintf(4, "Received bad $ValidateNick command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return 0;
     }
   
   /* Remove trailing '|'  */
   if(temp_nick[strlen(temp_nick)-1] == '|')
     temp_nick[strlen(temp_nick)-1] = '\0';
   
   /* Reject nicks containing NMDC protocol delimiters or control chars */
   if(strchr(temp_nick, '\005') != NULL
      || strchr(temp_nick, '|') != NULL
      || strchr(temp_nick, '$') != NULL)
     {
	uprintf(user, "$ValidateDenide %s|", temp_nick);
	return 0;
     }
   
   /* Check that it isn't "Hub-Security" */
   if(strncasecmp(temp_nick, "hub-security", 12) == 0)
     {	
	/* I know that it should be spelled "ValidateDenied", but since the
	 * protocol is designed this way, we can't expect the clients to 
	 * understand the command if it's spelled in any other way.  */
	uprintf(user, "$ValidateDenide %s|", temp_nick);
	return 0;
     }
   
   /* Or "Administrator"  */
   if(strncasecmp(temp_nick, "Administrator", 13) == 0)
     {
	uprintf(user, "$ValidateDenide %s|", temp_nick);
	return 0;
     }   
   
   /* Check if nick is already taken by another online user */
   if(((check_if_on_user_list(temp_nick)) != NULL)
       || (get_human_user(temp_nick) != NULL))
     {
	uprintf(user, "$ValidateDenide %s|", temp_nick);
	memset(temp_nick, 0, sizeof(temp_nick));
	return -1;
     }

   /* Set nick, then ask gateway whether this user is registered.
    * Gateway will respond with login_user (unregistered) or send_getpass (registered).
    * User stays in NON_LOGGED state until gateway responds.
    *
    * If we're in the parent process (pid > 0 or no forking), call the JSON
    * event directly.  If we're in a child, relay via an internal command
    * to the parent which owns the JSON socket. */
   strncpy(user->nick, temp_nick, MAX_NICK_LEN);
   user->nick[MAX_NICK_LEN] = '\0';
   logprintf(3, "validate_nick: %s (pid=%d)\n", temp_nick, (int)pid);
   if (pid <= 0) {
      /* Parent process or no forking — send directly */
      json_event_validate_nick(temp_nick);
   } else {
      /* Child process — relay to parent via internal command */
      char relay[MAX_NICK_LEN + 20];
      snprintf(relay, sizeof(relay), "$GwValidateNick %s|", temp_nick);
      send_to_non_humans(relay, FORKED, user);
   }
   return 1;
}

/* Sets the version of the client the user is using */
int version(char *buf, struct user_t *user)
{  
   if(sscanf(buf, "$Version %30[^ |]|", user->version) != 1)
     {                                                                    
	logprintf(4, "Received bad $Version command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return 0;
     }
   
   
   /* Check if version is equal to min_version or later */
   if((int)min_version[0] > 0x20)
     {
	if(strcmp(min_version, user->version) > 0)
	  {
	     uprintf(user, "<Hub-Security> Sorry, only clients of version %s or later are allowed to this hub.|", min_version);
	     return 0;
	  }
     }
   return 1;
}

/* Forward password to gateway for verification.
 * Gateway will respond with login_user (correct) or reject_user (wrong). */
int my_pass(char *buf, struct user_t *user)
{
   char pass[MAX_ADMIN_PASS_LEN+1];

   /* Strip trailing | */
   strncpy(pass, buf, MAX_ADMIN_PASS_LEN);
   pass[MAX_ADMIN_PASS_LEN] = '\0';
   {
      char *pipe = strchr(pass, '|');
      if (pipe) *pipe = '\0';
   }

   if (pid <= 0) {
      json_event_check_password(user->nick, pass);
   } else {
      char relay[MAX_NICK_LEN + MAX_ADMIN_PASS_LEN + 20];
      snprintf(relay, sizeof(relay), "$GwCheckPass %s %s|", user->nick, pass);
      send_to_non_humans(relay, FORKED, user);
   }
   return 1;  /* keep user connected, waiting for gateway response */
}

/* Removes a user without sending $Quit.  */
void disc_user(char *buf, struct user_t *user)
{
   char nick[MAX_NICK_LEN+1];
   struct user_t *remove_user;
   
   if(pid > 0)
     send_to_non_humans(buf, FORKED, user);
   else
     {	
	sscanf(buf, "$DiscUser %50[^|]|", nick);
	if((remove_user = get_human_user(nick)) != NULL)
	  {
	     remove_human_from_hash(nick);
	     remove_user->rem = REMOVE_USER;
	  }
     }
}

/* Kick a user. tempban is 1 if the command is sent from a human, but 0 if
 * used internally.  */
void kick(char *buf, struct user_t *user, int tempban)
{
   char command[11];
   char nick[MAX_NICK_LEN+1];
   char host[MAX_HOST_LEN+1];
   char ban_command[MAX_HOST_LEN+4];
   struct user_t *to_user;
   
   if(sscanf(buf, "%10s %50[^|]|", command, nick) != 2)
     {                                                                 
	logprintf(4, "Received bad $Kick command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   if((user != NULL) && (strncmp(nick, user->nick, strlen(nick)) == 0)
      && (strlen(nick) == strlen(user->nick)))
     return;
  
   /* If it was triggered internally.  */
   if(user == NULL)
     {
	if(check_if_on_user_list(nick) == NULL)
	  return;
	remove_user_from_list(nick);
     }
   
   else if((user->type & (OP | OP_ADMIN | ADMIN)) != 0)
     {	
	if(check_if_on_user_list(nick) == NULL)
	  {
	     if(user->type == ADMIN)
	       uprintf(user, "\r\nUser %s wasn't found in this hub\r\n", nick);
	     return;
	  }
	
	get_users_hostname(nick, host);
	logprintf(1, "User %s at %s was kicked by %s\n", nick, host, user->nick);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nUser %s was kicked\r\n", nick);
	remove_user_from_list(nick);

	/* Send event for kick */
	json_event_kick(nick, user->nick);
     }

   if((to_user = get_human_user(nick)) != NULL)
     {	
	to_user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	return;
     }
   
   send_to_non_humans(buf, FORKED, user);
}

/* Quits the program */
void quit_program(void)
{  
   /* If we are a child process and the command wasn't sent from a forked
    * process, don't remove users.  */
   if(pid <= 0) 
     send_to_non_humans("$QuitProgram|", FORKED, NULL);
   
   else
     {	   
	logprintf(1, "Got term signal, exiting...\n\n");
	
	/* If we are the parent.  */
	remove_all(0xFFFF, 0, 0);

	/* Give child processes some time to remove their users.  */
	sleep(1);
	
	/* Remove semaphores and shared memory segments.  */
	semctl(total_share_sem, 0, IPC_RMID, NULL);
	shmctl(total_share_shm, IPC_RMID, NULL);
	semctl(user_list_sem, 0, IPC_RMID, NULL);
	shmctl(get_user_list_shm_id(), IPC_RMID, NULL);
	shmctl(user_list_shm_shm, IPC_RMID, NULL);	
	write_config_file();	  
	
	/* Clean up JSON gateway socket */
	json_socket_cleanup();

	/* If we are the parent, close the listening sockets and close the temp file */
	close(listening_socket);
	close(listening_unx_socket);
#ifdef HAVE_SSL
	if(tls_listening_socket != -1)
	  close(tls_listening_socket);
	cleanup_ssl_ctx();
#endif
	unlink(un_sock_path);
	exit(EXIT_SUCCESS);
     }
}

/* Constant-time string comparison to prevent timing attacks */
int secure_strcmp(const char *a, const char *b)
{
   size_t alen = strlen(a);
   size_t blen = strlen(b);
   size_t maxlen = (alen > blen) ? alen : blen;
   volatile unsigned char result = (alen != blen) ? 1 : 0;
   size_t i;
   for(i = 0; i < maxlen; i++)
     result |= ((unsigned char)(i < alen ? a[i] : 0))
	      ^ ((unsigned char)(i < blen ? b[i] : 0));
   return result;
}

