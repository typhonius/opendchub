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
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if HAVE_CRYPT_H
# include <crypt.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
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
#include <errno.h>
#include <dirent.h>
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif
#ifdef SWITCH_USER
# include <pwd.h>
#endif

#include "main.h"
#include "utils.h"
#include "fileio.h"
#include "network.h"
#ifndef HAVE_STRTOLL
# ifdef HAVE_STRTOQ
#  define strtoll(X, Y, Z) (long long)strtoq(X, Y, Z)
# endif
#endif

/* Reads config file */
int read_config(void)
{
   int i, j;
   int fd;
   int erret;
   FILE *fp;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, CONFIG_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In read_config()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In read_config()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   	
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In read_config(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }
   
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In read_config()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	
	j = strlen(line);
	if(j != 0)
	  {
	     /* Jump to next char which isn't a space */
	     i = 0;
	     while(line[i] == ' ')
	       i++;
	     
	     /* Name of the hub */
	     if(strncmp(line + i, "hub_name", 8) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(hub_name, strchr(line + i, '"') + 1, MAX_HUB_NAME);
		  hub_name[MAX_HUB_NAME] = '\0';
		  if(*(hub_name + strlen(hub_name) - 1) == '"')
		    *(hub_name + strlen(hub_name) - 1) = '\0';
	       }
	     
	     /* Maximum hub users */
	     else if(strncmp(line + i, "max_users", 9) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  max_users = atoi(line + i);
	       }
	     /* Number of users when fork occurs */
	     else if(strncmp(line + i, "users_per_fork", 14) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  users_per_fork = atoi(line + i);
	       }
	     
	     /* The message displayed if hub is full */
	     else if(strncmp(line + i, "hub_full_mess", 13) == 0)
	       {
		  /* The string has to begin with a '"' at the same line */
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  if((hub_full_mess = malloc(sizeof(char) 
		       * (strlen(line+i+1) + 1))) == NULL)
		    {
		       logprintf(1, "Error - In read_config()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       set_lock(fd, F_UNLCK);
		       fclose(fp);
		       return -1;
		    }
		  strncpy(hub_full_mess, strchr(line + i, '"') + 1, strlen(line+i+1));
		  hub_full_mess[strlen(line+i+1)] = '\0';
		  while((line[strlen(line) - 1] != '"') && (fgets(line, 1023, fp) != NULL))
		    {		
		       trim_string(line);
		       if((hub_full_mess = realloc(hub_full_mess, sizeof(char) 
			* (strlen(hub_full_mess) + strlen(line) + 3))) == NULL)
			 {
			    logprintf(1, "Error - In read_config()/realloc(): ");
			    logerror(1, errno);
			    quit = 1;
			    set_lock(fd, F_UNLCK);
			    fclose(fp);
			    return -1;
			 }
		       sprintfa(hub_full_mess, strlen(hub_full_mess) + strlen(line) + 3, "\r\n%s", line);
		    }
		  if(*(hub_full_mess + strlen(hub_full_mess) - 1) == '"')
		     *(hub_full_mess + strlen(hub_full_mess) - 1) = '\0';
	       }
	     
	     /* Description of hub. Sent to public hub list */
	     else if(strncmp(line + i, "hub_description", 15) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(hub_description, strchr(line + i, '"') + 1, MAX_HUB_DESC);
		  hub_description[MAX_HUB_DESC] = '\0';
		  if(*(hub_description + strlen(hub_description) - 1) == '"')
		    *(hub_description + strlen(hub_description) - 1) = '\0';
	       }
	     
	     /* Minimum share to allow a user access */
	     else if(strncmp(line + i, "min_share", 9) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  min_share = strtoll(line + i, (char **)NULL, 10);
	       }
	     
             /* Default password */
             else if(strncmp(line + i, "default_pass", 12) == 0)
               {
                  if(strchr(line + i, '"') == NULL)
                    {
                       set_lock(fd, F_UNLCK);
                         while(((erret = fclose(fp)) != 0) && (errno == EINTR))
                         logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");

                       if(erret != 0)
                         {
                            logprintf(1, "Error - In read_config()/fclose(): ");
                            logerror(1, errno);
                            return -1;
                         }

                       return -1;
                    }
                  strncpy(default_pass, strchr(line + i, '"') + 1, MAX_ADMIN_PASS_LEN);
                  default_pass[MAX_ADMIN_PASS_LEN] = '\0';
                  if(*(default_pass + strlen(default_pass) - 1) == '"')
                    *(default_pass + strlen(default_pass) - 1) = '\0';
               }
	     
	     /* Password for hub linking */
	     else if(strncmp(line + i, "link_pass", 9) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(link_pass, strchr(line + i, '"') + 1, MAX_ADMIN_PASS_LEN);
		  link_pass[MAX_ADMIN_PASS_LEN] = '\0';
		  if(*(link_pass + strlen(link_pass) - 1) == '"')
		    *(link_pass + strlen(link_pass) - 1) = '\0';
	       }
	     
	     /* The port the hub is listening on */
	     else if(strncmp(line + i, "listening_port", 14) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  listening_port = (unsigned int)(atoi(line + i));
	       }
	     
	     /* JSON gateway socket path */
	     else if(strncmp(line + i, "json_socket_path", 16) == 0)
	       {
		  if(strchr(line + i, '"') != NULL)
		    {
		       strncpy(json_socket_path, strchr(line + i, '"') + 1, MAX_JSON_SOCK_PATH - 1);
		       json_socket_path[MAX_JSON_SOCK_PATH - 1] = '\0';
		       if(*(json_socket_path + strlen(json_socket_path) - 1) == '"')
			 *(json_socket_path + strlen(json_socket_path) - 1) = '\0';
		       json_socket_enabled = 1;
		    }
	       }

	     /* JSON gateway socket shared secret */
	     else if(strncmp(line + i, "json_socket_secret", 18) == 0)
	       {
		  if(strchr(line + i, '"') != NULL)
		    {
		       strncpy(json_socket_secret, strchr(line + i, '"') + 1, MAX_JSON_SECRET_LEN - 1);
		       json_socket_secret[MAX_JSON_SECRET_LEN - 1] = '\0';
		       if(*(json_socket_secret + strlen(json_socket_secret) - 1) == '"')
			 *(json_socket_secret + strlen(json_socket_secret) - 1) = '\0';
		    }
	       }

	     /* Public hub list host */
	     else if(strncmp(line + i, "public_hub_host", 15) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(public_hub_host, strchr(line + i, '"') + 1, MAX_HOST_LEN);
		  public_hub_host[MAX_HOST_LEN] = '\0';
		  if(*(public_hub_host + strlen(public_hub_host) - 1) == '"')
		    *(public_hub_host + strlen(public_hub_host) - 1) = '\0';
	       }
	     
	     /* Hostname to upload to public hublist */
	     else if(strncmp(line + i, "hub_hostname", 12) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(hub_hostname, strchr(line + i, '"') + 1, MAX_HOST_LEN);
		  hub_hostname[MAX_HOST_LEN] = '\0';
		  if(*(hub_hostname + strlen(hub_hostname) - 1) == '"')
		    *(hub_hostname + strlen(hub_hostname) - 1) = '\0';
	       }
	     
	     /* Minimum client version */
	     else if(strncmp(line + i, "min_version", 11) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(min_version, strchr(line + i, '"') + 1, 30);
		  min_version[30] = '\0';
		  if(*(min_version + strlen(min_version) - 1) == '"')
		    *(min_version + strlen(min_version) - 1) = '\0';
	       }
	     
	     /* 1 if hub should upload description to public hublist */
	      else if(strncmp(line + i, "hublist_upload", 14) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  hublist_upload = atoi(line + i);
	       }
	     
	     /*  Host to redirect users if hub is full */
	     else if(strncmp(line + i, "redirect_host", 13) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       redirect_host[0] = '\0';
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return 1;
		    }
		  strncpy(redirect_host, strchr(line + i, '"') + 1, MAX_HOST_LEN);
		  redirect_host[MAX_HOST_LEN] = '\0';
		  if(*(redirect_host + strlen(redirect_host) - 1) == '"')
		    *(redirect_host + strlen(redirect_host) - 1) = '\0';
	       }
	     
	     /* 1 for registered only mode */
	     else if(strncmp(line + i, "registered_only", 15) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  registered_only = atoi(line + i);
	       }
	     
	      /* 1 for ban to override allow */
	     else if(strncmp(line + i, "ban_overrides_allow", 19) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  ban_overrides_allow = atoi(line + i);
	       }
	     
	     /* 1 for validation of clients Keys */
	     else if(strncmp(line + i, "check_key", 9) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  check_key = atoi(line + i);
	       }
	     
	       /* 1 for Reverse DNS lookups */
	     else if(strncmp(line + i, "reverse_dns", 11) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  reverse_dns = atoi(line + i);
	       }
	     
	     /* 5 for all possible logging, 0 for no logging at all */
	     else if(strncmp(line + i, "verbosity", 9) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  verbosity = atoi(line + i);
	       }
	     /* 1 if user should be redirected if he doesn't share enough */
	     else if(strncmp(line + i, "redir_on_min_share", 18) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  redir_on_min_share = atoi(line + i);
	       }
	     /* 1 if logging should go to syslog instead */
	     else if(strncmp(line + i, "syslog_enable", 13) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  syslog_enable = atoi(line + i);
	       }
	     /* 0 for text log format, 1 for JSON structured logging */
	     else if(strncmp(line + i, "log_format", 10) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  log_format = atoi(line + i);
	       }
	     /* Alternative log file path */
	     else if(strncmp(line + i, "log_file", 8) == 0)
	       {
		  if(strchr(line + i, '"') != NULL)
		    {
		       strncpy(log_file_path, strchr(line + i, '"') + 1, MAX_HOST_LEN);
		       log_file_path[MAX_HOST_LEN] = '\0';
		       if(*(log_file_path + strlen(log_file_path) - 1) == '"')
			 *(log_file_path + strlen(log_file_path) - 1) = '\0';
		    }
	       }
	     /* 1 if search IP check should ignore internal IP addresses */
	     else if(strncmp(line + i, "searchcheck_exclude_internal", 28) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  searchcheck_exclude_internal = atoi(line + i);
	       }
	     /* 1 if search IP check should be skipped altogether */
	     else if(strncmp(line + i, "searchcheck_exclude_all", 23) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  searchcheck_exclude_all = atoi(line + i);
	       }
	     /* Number of minutes user should be banned for when kicked */
	     else if(strncmp(line + i, "kick_bantime", 12) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  kick_bantime = atoi(line + i);
	       }
	     /* Min number of seconds between searches */
	     else if(strncmp(line + i, "searchspam_time", 15) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  searchspam_time = atoi(line + i);
	       }
	     /* Max length of email addresses */
	     else if(strncmp(line + i, "max_email_len", 13) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  max_email_len = atoi(line + i);
	       }
	     /* Max length of user descriptions */
	     else if(strncmp(line + i, "max_desc_len", 12) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  max_desc_len = atoi(line + i);
	       }
	     /* Enable encrypted passwords? */
	     else if(strncmp(line + i, "crypt_enable", 12) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		 crypt_enable = atoi(line + i);
	       }
#ifdef HAVE_SSL
	     /* TLS listening port */
	     else if(strncmp(line + i, "tls_port", 8) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  {
		     int val = atoi(line + i);
		     if(val > 0 && val <= 65535)
		       tls_port = (unsigned int)val;
		  }
	       }
	     /* TLS certificate file */
	     else if(strncmp(line + i, "tls_cert_file", 13) == 0)
	       {
		  if(strchr(line + i, '"') != NULL)
		    {
		       strncpy(tls_cert_file, strchr(line + i, '"') + 1, MAX_FDP_LEN);
		       tls_cert_file[MAX_FDP_LEN] = '\0';
		       if(*(tls_cert_file + strlen(tls_cert_file) - 1) == '"')
			 *(tls_cert_file + strlen(tls_cert_file) - 1) = '\0';
		    }
	       }
	     /* TLS private key file */
	     else if(strncmp(line + i, "tls_key_file", 12) == 0)
	       {
		  if(strchr(line + i, '"') != NULL)
		    {
		       strncpy(tls_key_file, strchr(line + i, '"') + 1, MAX_FDP_LEN);
		       tls_key_file[MAX_FDP_LEN] = '\0';
		       if(*(tls_key_file + strlen(tls_key_file) - 1) == '"')
			 *(tls_key_file + strlen(tls_key_file) - 1) = '\0';
		    }
	       }
#endif
	  }
     }
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In read_config()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   return 1;
}

/* Stubs — gateway owns registration data but these are still called from
 * add_reg_user/remove_reg_user/add_perm/remove_perm and userlist.c.
 * Always return 0 (not registered / no permissions). */
int check_if_registered(char *user_nick)
{ (void)user_nick; return 0; }

int get_permissions(char *user_nick)
{ (void)user_nick; return 0; }

/* Write config file */
int write_config_file(void)
{
   FILE *fp;
   int fd;
   int erret;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, CONFIG_FILE);
   
   /* Remove existing config file */
   unlink(path);
   
   while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In write_config_file()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In write_config_file()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {
	logprintf(1, "Error - In write_config_file(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "w")) == NULL)
     {
	logprintf(1, "Error - In write_config_file()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   fprintf(fp, "hub_name = \"%s\"\n\n", hub_name);	       	       
	       
   fprintf(fp, "max_users = %d\n\n", max_users);
   
   fprintf(fp, "hub_full_mess = \"%s\"\n\n", hub_full_mess);
   
   fprintf(fp, "hub_description = \"%s\"\n\n", hub_description);
   
   fprintf(fp, "min_share = %llu\n\n", min_share);
	       

   fprintf(fp, "default_pass = \"%s\"\n\n", default_pass);
	       	
   fprintf(fp, "link_pass = \"%s\"\n\n", link_pass);
   
   fprintf(fp, "users_per_fork = %d\n\n", users_per_fork);
   
   fprintf(fp, "listening_port = %u\n\n", listening_port);
   

   
   if(json_socket_path[0] != '\0')
     fprintf(fp, "json_socket_path = \"%s\"\n\n", json_socket_path);
   if(json_socket_secret[0] != '\0')
     fprintf(fp, "json_socket_secret = \"%s\"\n\n", json_socket_secret);

   fprintf(fp, "hublist_upload = %d\n\n", hublist_upload);
  
   fprintf(fp, "public_hub_host = \"%s\"\n\n", public_hub_host);
  
   fprintf(fp, "hub_hostname = \"%s\"\n\n", hub_hostname);
   
   fprintf(fp, "min_version = \"%s\"\n\n", min_version);
   
   fprintf(fp, "redirect_host = \"%s\"\n\n", redirect_host);
   
   fprintf(fp, "registered_only = %d\n\n", registered_only);
   
   fprintf(fp, "check_key = %d\n\n", check_key);
   
   fprintf(fp, "reverse_dns = %d\n\n", reverse_dns);
   
   fprintf(fp, "ban_overrides_allow = %d\n\n", ban_overrides_allow);
   
   fprintf(fp, "verbosity = %d\n\n", verbosity);
   
   fprintf(fp, "redir_on_min_share = %d\n\n", redir_on_min_share);
   
   fprintf(fp, "syslog_enable = %d\n\n", syslog_enable);

   fprintf(fp, "log_format = %d\n\n", log_format);

   if(strlen(log_file_path) > 0)
     fprintf(fp, "log_file = \"%s\"\n\n", log_file_path);
   else
     fprintf(fp, "log_file = \"\"\n\n");

   fprintf(fp, "searchcheck_exclude_internal = %d\n\n", searchcheck_exclude_internal);
   
   fprintf(fp, "searchcheck_exclude_all = %d\n\n", searchcheck_exclude_all);
   
   fprintf(fp, "kick_bantime = %d\n\n", kick_bantime);
   
   fprintf(fp, "searchspam_time = %d\n\n", searchspam_time);
   
   fprintf(fp, "max_email_len = %d\n\n", max_email_len);
   
   fprintf(fp, "max_desc_len = %d\n\n", max_desc_len);
   
   fprintf(fp, "crypt_enable = %d\n\n", crypt_enable);

#ifdef HAVE_SSL
   fprintf(fp, "tls_port = %u\n\n", tls_port);

   fprintf(fp, "tls_cert_file = \"%s\"\n\n", tls_cert_file);

   fprintf(fp, "tls_key_file = \"%s\"\n\n", tls_key_file);
#endif

   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In write_config_file()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In write_config_file()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   return 1;
}
     
/* Set lock on file */
int set_lock(int fd, int type)
{
   int ret;
   struct flock lock;
   
   memset(&lock, 0, sizeof(struct flock));
   lock.l_whence = SEEK_SET;
   lock.l_start = 0;
   lock.l_len = 0;
   
   lock.l_type = type;
   
   while(((ret = fcntl(fd, F_SETLKW, &lock)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In set_lock()/fcntl(): Interrupted system call. Trying again.\n");
   
   if(ret < 0)
     {
	logprintf(1, "Error - In set_lock()/fcntl(): ");
	logerror(1, errno);
	quit = 1;
	return 0;
     }   
   
   return 1;
}

/* Removes a user from the reglist */
int remove_reg_user(char *buf, struct user_t *user)
{
   int nick_len;
   char *temp;
   char nick[MAX_NICK_LEN+1];
   char path[MAX_FDP_LEN+1];
   int line_nbr;
   
   line_nbr = 0;
   temp = NULL;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, REG_FILE);
   
   if(buf[strlen(buf)-1] == '|')
     nick_len = strlen(buf)-1;
   else
     nick_len = strlen(buf);
   
   snprintf(nick, (nick_len>MAX_NICK_LEN)?MAX_NICK_LEN+1:nick_len+1, buf);

   if((user->type != ADMIN) && 
      (check_if_registered(nick) > check_if_registered(user->nick)))
     return -1;
   
   return remove_line_from_file(nick, path, 0);
}
   

/* Adds a user to the reglist. Returns 2 if the command had bad format and 3
 * if it's already registered Format is: $AddRegUser <nick> <pass> <opstatus> */
int add_reg_user(char *buf, struct user_t *user)
{
   int ret;
   char command[21];
   char nick[MAX_NICK_LEN+1];
   char pass[MAX_ADMIN_PASS_LEN+1];
   char path[MAX_FDP_LEN+1];
   char line[MAX_ADMIN_PASS_LEN + MAX_NICK_LEN + 10];
   int  type;

   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, REG_FILE);

   if(sscanf(buf, "%20s %50s %120s %d|", command, nick, pass, &type) != 4)
     return 2;
   
   if((pass[0] == '\0') || ((type != 0) && (type != 1) && (type != 2)))
     return 2;

   if ((user != NULL) && (user->type != ADMIN)
       && (type >= check_if_registered(user->nick)))
     return -1;
   
   /* If the user already is there, then remove the user first */
   if(check_if_registered(nick) != 0)
     return 3;
   
   encrypt_pass(pass);

   snprintf(line, sizeof(line), "%s %s %d", nick, pass, type);
   
   ret = add_line_to_file(line, path);
   
   return ret;
}

/* Adds a hub to the linklist. Returns 2 if the command had bad format */
/* Format is: $AddLinkedHub hub_ip port */
int add_linked_hub(char *buf)
{
   char command[21];
   char ip[MAX_HOST_LEN+1];
   char path[MAX_FDP_LEN+1];
   int  port;
   int ret;
   char line[MAX_HOST_LEN + 6];
   int checkret;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LINK_FILE);
   
   if(sscanf(buf, "%20s %121s %d|", command, ip, &port) != 3)
     return 2;
   
   if((ip[0] == '\0') || (port < 1) || (port > 65536))
     return 2;
   
   if((checkret = check_if_on_linklist(ip, port)) == 1)
     return 3;
   else if(checkret == -1)
     return -1;
   
   /* And add the hub */
   snprintf(line, sizeof(line), "%s %d", ip, port);
   
   ret = add_line_to_file(line, path);
   
   return ret;
}

/* Removes a hub from the linklist */
int remove_linked_hub(char *buf)
{
   int ip_len;
   char line[1024];
   char ip[MAX_HOST_LEN+1];
   int port;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LINK_FILE);
   
   if(sscanf(buf, "%121s %d|", ip, &port) != 2)
     return 2;
   
   if((ip[0] == '\0') || (port < 1) || (port > 65536))
     return 2;
   
   ip_len = strlen(ip);

   snprintf(line, sizeof(line), "%s %d", ip, port);
   
   return remove_line_from_file(line, path, port);
}

/* Set the directories used */
int init_dirs(void)
{
   char path[MAX_FDP_LEN+1];

   if(strlen(working_dir) == 0)
     {
#ifdef __CYGWIN__
	getcwd(working_dir, MAX_FDP_LEN);
#else
#ifdef SWITCH_USER
	struct passwd *user = getpwuid(dchub_user);
	snprintf( working_dir, MAX_FDP_LEN, user->pw_dir );
#else
	if( getenv( "HOME" ) == NULL )
	   return 0;
   
	snprintf( working_dir, MAX_FDP_LEN, getenv( "HOME" ) );
#endif
#endif
     }
   strncpy(path, working_dir, MAX_FDP_LEN);
   snprintf( config_dir, MAX_FDP_LEN, "%s/.opendchub", path );

   sprintfa(path, MAX_FDP_LEN + 1, "/tmp");
   snprintf(un_sock_path, MAX_FDP_LEN + 1, "%s/%s", path, UN_SOCK_NAME);
   mkdir(config_dir, 0700);
   mkdir(path, 0700);
   return 1;
}

/* Print to log file */
/* Map verbosity level to log level string for JSON output */
static const char *verb_to_level(int verb)
{
   switch(verb)
     {
      case 1:  return "error";
      case 2:  return "warn";
      case 3:  return "info";
      case 4:  return "debug";
      case 5:  return "trace";
      default: return "info";
     }
}

/* Write a JSON-escaped version of src into dst (up to dst_size-1 chars).
 * Escapes backslash, double-quote, and control characters. */
static void json_escape(char *dst, const char *src, size_t dst_size)
{
   size_t di = 0;
   size_t si;

   if(dst_size == 0)
     return;

   for(si = 0; src[si] != '\0' && di < dst_size - 1; si++)
     {
	unsigned char c = (unsigned char)src[si];
	if(c == '"' || c == '\\')
	  {
	     if(di + 2 >= dst_size) break;
	     dst[di++] = '\\';
	     dst[di++] = c;
	  }
	else if(c == '\n')
	  {
	     if(di + 2 >= dst_size) break;
	     dst[di++] = '\\';
	     dst[di++] = 'n';
	  }
	else if(c == '\r')
	  {
	     if(di + 2 >= dst_size) break;
	     dst[di++] = '\\';
	     dst[di++] = 'r';
	  }
	else if(c == '\t')
	  {
	     if(di + 2 >= dst_size) break;
	     dst[di++] = '\\';
	     dst[di++] = 't';
	  }
	else if(c < 0x20)
	  {
	     /* Skip other control characters */
	  }
	else
	  {
	     dst[di++] = c;
	  }
     }
   dst[di] = '\0';
}

void logprintf(int verb, const char *format, ...)
{
   static char buf[4096];
   char path[MAX_FDP_LEN+1];
   FILE *fp = NULL;
   int fd=0;
   int erret;
   char *localtime;
   char *temp;
   time_t current_time;
   int priority;

   if(verb > verbosity)
     return;

   if ((syslog_enable == 0) && (syslog_switch == 0))
     {
	/* log_file_path takes precedence if set, then logfile, then default */
	if(strlen(log_file_path) > 1)
	  strncpy(path, log_file_path, MAX_FDP_LEN);
	else if (strlen(logfile) > 1)
	  strncpy(path, logfile, MAX_FDP_LEN);
	else									/* If no preset logfile. */
	  snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LOG_FILE);
     }

   if(format)
     {
	va_list args;
	va_start(args, format);
	vsnprintf(buf, 4095, format, args);
	va_end(args);

	if((syslog_enable == 0) && (syslog_switch == 0))
	  {
	     while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
	       {
	       }

	     if(fd < 0)
	       return;

	     /* Set the lock */
	     if(set_lock(fd, F_WRLCK) == 0)
	       {
		  close(fd);
		  return;
	       }

	     if((fp = fdopen(fd, "a")) == NULL)
	       {
		  set_lock(fd, F_UNLCK);
		  close(fd);
		 return;
	      }
	  }

	current_time = time(NULL);
	localtime = ctime(&current_time);
	temp = localtime;
	temp += 4;
	localtime[strlen(localtime)-6] = 0;
	if(debug != 0)
	  {
	     if(log_format == 1)
	       {
		  /* JSON output to stdout in debug mode */
		  static char escaped[8192];
		  struct tm *tm_info;
		  char iso_time[64];
		  tm_info = gmtime(&current_time);
		  strftime(iso_time, sizeof(iso_time), "%Y-%m-%dT%H:%M:%SZ", tm_info);
		  json_escape(escaped, buf, sizeof(escaped));
		  printf("{\"timestamp\":\"%s\",\"level\":\"%s\",\"message\":\"%s\"}\n",
			 iso_time, verb_to_level(verb), escaped);
	       }
	     else
	       printf("%s %s", temp, buf);
	  }
#ifdef HAVE_SYSLOG_H
	else if((syslog_enable != 0) || (syslog_switch != 0))
	  {
	     if(verb > 1)
		priority = LOG_DEBUG;
	     else if (strncmp(buf, "Error - ", 8))
		priority = LOG_ERR;
	     else
		priority = LOG_WARNING;
	     syslog(priority, "%s", buf);
	  }
#endif
	else
	  {
	     if(log_format == 1)
	       {
		  /* JSON output to log file */
		  static char escaped[8192];
		  struct tm *tm_info;
		  char iso_time[64];
		  tm_info = gmtime(&current_time);
		  strftime(iso_time, sizeof(iso_time), "%Y-%m-%dT%H:%M:%SZ", tm_info);
		  json_escape(escaped, buf, sizeof(escaped));
		  fprintf(fp, "{\"timestamp\":\"%s\",\"level\":\"%s\",\"message\":\"%s\"}\n",
			  iso_time, verb_to_level(verb), escaped);
	       }
	     else
	       fprintf(fp, "%s %s", temp, buf);
	  }

	if((syslog_enable == 0) && (syslog_switch == 0))
	  {
	     set_lock(fd, F_UNLCK);
	     while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	       {
	       }
	  }
     }
}

/* Write the motd. Creates the motd file if it doesn't exist. Overwrites
   current motd if overwrite is set to 1. Returns 1 on created file and
   0 if it already exists. */
int write_motd(char *buf, int overwrite)
{
   FILE *fp;
   int fd;
   int erret;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, MOTD_FILE);
   
   if(overwrite == 0)
     {
	while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
	  logprintf(1, "Error - In write_motd()/open(): Interrupted system call. Trying again.\n"); 
	
	if(fd >= 0)
	  {
	     /* MOTD already exists */
	     close(fd);
	     return 0;
	  }
     }
   
   if(overwrite != 0)
     unlink(path);
   
   while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In write_motd()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In write_motd()/open(): ");
	logerror(1, errno);
	return -1;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {	
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "w")) == NULL)
     {
	logprintf(1, "Error - In write_motd()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   fprintf(fp, "%s", buf);
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In write_motd()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In write_motd()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   if(overwrite != 0)
     return 0;
   else
     return 1;
}

/* Sends the motd to the particular user. */
int send_motd(struct user_t *user)
{
   FILE *fp;
   int fd;
   int erret;
   char line[4095];
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, MOTD_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In send_motd()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In send_motd()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In send_motd(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In send_motd()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   if(fgets(line, 4094, fp) != NULL)
     {
	trim_string(line);
	uprintf(user, "%s", line);
	while(fgets(line, 4094, fp) != NULL)
	  {
	     trim_string(line);
	     uprintf(user, "\r\n%s", line);
	  }
     }  
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In send_motd()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In send_motd()/fclose(): ");
	logerror(1, errno);
	return -1;
     }

   return 1;
}

/* Sends the welcome message to a newly connected user. */
int welcome_mess(struct user_t *user)
{
   int ret;
   //uprintf(user, "$To: %s From: Hub $", user->nick);   //This did not let motd to be sent when new user connects. 
   ret = send_motd(user);
   send_to_user("|", user);
   return ret;
}

/* Prints the error to the log file */
void logerror(int verb, int error)
{
   char path[MAX_FDP_LEN+1];
   FILE *fp=NULL;
   int fd=0;
   int erret;
   int priority;
   
   if(verb > verbosity)
     return;
   
   if((syslog_enable == 0) && (syslog_switch == 0))
     {
	snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LOG_FILE);
   	
	while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
	  {
	  }	     
	
	if(fd < 0)
	  return;
   
	/* Set the lock */
	if(set_lock(fd, F_WRLCK) == 0)
	  {
	     close(fd);
	     return;
	  }
   
	if((fp = fdopen(fd, "a")) == NULL)
	  {
	     set_lock(fd, F_UNLCK);
	     close(fd);
	     return;
	  }
     }
   
   if(debug != 0)
     printf("%s\n", strerror(error));
#ifdef HAVE_SYSLOG_H
   else if((syslog_enable != 0) || (syslog_switch != 0))
     {
	if(verb > 1)
	   priority = LOG_DEBUG;
	else
	   priority = LOG_ERR;
	syslog(priority, "%s", strerror(error));
     }
#endif
   else
     fprintf(fp, "%s\n", strerror(error));
   
   if((syslog_enable == 0) && (syslog_switch == 0))
     {
	set_lock(fd, F_UNLCK);
	
	while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	  {
	  }		
     }
}   

/* Adds line to end of a file */
int add_line_to_file(char *line, char *file)
{
   FILE *fp;
   int fd;
   int erret;
   
   /* Open the file */
   while(((fd = open(file, O_RDWR)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In add_line_to_file()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In add_line_to_file()/open(), file = %s: ", file);
	logerror(1, errno);
	return -1;	
     }   
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {	
	logprintf(1, "Error - In add_line_to_file(): Couldn't set file lock, file = %s\n", file);
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "a")) == NULL)
     {	
	logprintf(1, "Error - In add_line_to_file()/fdopen(), file = %s: ", file);
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   fprintf(fp, "%s\n", line);
   
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In add_line_to_file()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In add_line_to_file()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   return 1;
}

/* Removes line from file. Word has to match first word in the line in
 * the file. If port is set to anything else than zero, it assumes it's the
 * linklist file and then the port must match as well. Returns 1 on success, 
 * 0 if pattern wasn't found and -1 on error.  */
int remove_line_from_file(char *line, char *file, int port)
{
   FILE *fp;
   int fd;
   int erret;
   char *temp;
   char word[201];
   char fileline[1024];
   char fileword[201];
   int i, len;
   int fileport;
   int line_nbr = 0;
   
   if((temp = malloc(sizeof(char) * 2)) == NULL)
     {
	logprintf(1, "Error - In remove_line_from_file()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return -1;
     }   

   sscanf(line, "%200s", word);
   
   snprintf(temp, 2, "%c", '\0');

   while(((fd = open(file, O_RDWR)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_line_from_file()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In remove_line_from_file()/open(), file = %s: ", file);
	logerror(1, errno);
	free(temp);
	return -1;	
     }   
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {	
	logprintf(1, "Error - In remove_line_from_file(): Couldn't set file lock, file = %s\n", file);
	close(fd);
	free(temp);
	return -1;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {	
	logprintf(1, "Error - In remove_line_from_file()/fdopen(), file = %s: ", file);
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	free(temp);
	return -1;
     }
   
   while(fgets(fileline, 1023, fp) != NULL)
     {	
	line_nbr++;
	if(port != 0)	     
	  sscanf(fileline, "%200s %d", fileword, &fileport);
	else 
	  {	     
	     sscanf(fileline, "%200s", fileword);
	     fileport = 0;
	  }	
	
	if(((strncasecmp(word, fileword, strlen(word)) == 0)
	   && (strlen(word) == strlen(fileword))
	   && (port == fileport)))
	  {	     
	     /* Put the rest of the file in the temporary string */
	     while(fgets(fileline, 1023, fp) != NULL)
	       {		  
		  if((temp = realloc(temp, sizeof(char)
				     * (strlen(temp) + strlen(fileline) + 1))) == NULL)
		    {
		       logprintf(1, "Error - In remove_line_from_file()/realloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       set_lock(fd, F_UNLCK);
		       fclose(fp);
		       return -1;
		    }
		  snprintf(temp + strlen(temp), strlen(fileline) + 1, "%s", fileline);
	       }	     
	     rewind(fp);
	     
	     /* Go to the position where the user name is */
	     for(i = 1; i<= (line_nbr-1); i++)
	       fgets(fileline, 1023, fp);
	     
	     /* Truncate the file */
	     len = ftell(fp);
	     
	     while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In remove_line_from_file()/fclose(): Interrupted system call. Trying again.\n");
	     
	     if(erret != 0)
	       {
		  logprintf(1, "Error - In remove_line_from_file()/fclose(): ");
		  logerror(1, errno);
		  return -1;
	       }
	     
	     truncate(file, len);
	     
	     while(((fd = open(file, O_RDWR)) < 0) && (errno == EINTR))
	       logprintf(1, "Error - In remove_line_from_file()/open(): Interrupted system call. Trying again.\n");   
	     
	     if(fd < 0)
	       {		  
		  logprintf(1, "Error - In remove_line_from_file()/open(), file = %s: ", file);
		  logerror(1, errno);
		  free(temp);
		  return -1;
	       }
	     
	     if((fp = fdopen(fd, "a")) == NULL)
	       {		  
		  logprintf(1, "Error - In remove_line_from_file()/fdopen(), file = %s: ", file);
		  logerror(1, errno);
		  set_lock(fd, F_UNLCK);
		  close(fd);
		  free(temp);
		  return -1;
	       }	     
	     fwrite(temp, strlen(temp), 1, fp);
	     
	     set_lock(fd, F_UNLCK);
	     
	     while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In remove_line_from_file()/fclose(): Interrupted system call. Trying again.\n");
	     
	     if(erret != 0)
	       {
		  logprintf(1, "Error - In remove_line_from_file()/fclose(): ");
		  logerror(1, errno);
		  free(temp);
		  return -1;
	       }
	     
	     free(temp);
	     return 1;
	  }	
     }   
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_line_from_file()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In remove_line_from_file()/fclose(): ");
	logerror(1, errno);
	free(temp);
	return -1;
     }
   
   free(temp);
   return 0;
}

/* Remove an expired ban/allow line from a file.  */
int remove_exp_from_file(time_t now_time, char *file)
{
   FILE *fp;
   FILE *newfp;
   int fd;
   int erret;
   int newfd;
   char *newfile;
   char fileline[1024];
   char fileword[201];
   time_t exp_time;
   
   if((newfile = malloc(strlen(file) + 2)) == NULL)
     {
	logprintf(1, "Error - In remove_exp_from_file()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return -1;
     }   

   snprintf(newfile, strlen(file) + 2, "%s1", file);
   
   while(((fd = open(file, O_RDWR)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_exp_from_file()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {	
	logprintf(1, "Error - In remove_exp_from_file()/open(), file = %s: ", file);
	logerror(1, errno);
	free(newfile);
	return -1;
     }

   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {	
	logprintf(1, "Error - In remove_exp_from_file(): Couldn't set file lock, file = %s\n", file);
	close(fd);
	free(newfile);
	return -1;
     }

   if((fp = fdopen(fd, "r")) == NULL)
     {	
	logprintf(1, "Error - In remove_exp_from_file()/fdopen(), file = %s: ", file);
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	free(newfile);
	return -1;
     }

   unlink(newfile);
   
   while(((newfd = open(newfile, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_exp_from_file()/open(): Interrupted system call. Trying again.\n");   
   
   if(newfd < 0)
     {
	logprintf(1, "Error - In remove_exp_from_file()/open(), file = %s: ", newfile);
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In remove_exp_from_file()/fclose(): Interrupted system call. Trying again.\n");
	
	if(erret != 0)
	  {
	     logprintf(1, "Error - In remove_exp_from_file()/fclose(): ");
	     logerror(1, errno);
	     free(newfile);
	     return -1;
	  }
       
	free(newfile);
	return -1;
     }
   
   if(set_lock(newfd, F_WRLCK) == 0)
     {
	logprintf(1, "Error - In remove_exp_from_file(): Couldn't set file lock, file = %s\n", newfile);
	set_lock(fd, F_UNLCK);
	fclose(fp);
	close(newfd);
	free(newfile);
	return -1;
     }

   if((newfp = fdopen(newfd, "w")) == NULL)
     {
	logprintf(1, "Error - In remove_exp_from_file()/fdopen(), file = %s: ", newfile);
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	fclose(fp);
	set_lock(newfd, F_UNLCK);
	close(newfd);
	free(newfile);
	return -1;
     }

   while(fgets(fileline, 1023, fp) != NULL)
     {	
	exp_time = 0;
	sscanf(fileline, "%200s %lu", fileword, &exp_time);
	
	if((exp_time == 0) || (exp_time > now_time))
	  fprintf(newfp, "%s", fileline);
     }   
   set_lock(newfd, F_UNLCK);
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(newfp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_exp_from_file()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In remove_exp_from_file()/fclose(): ");
	logerror(1, errno);
	free(newfile);
	return -1;
     }
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_exp_from_file()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In remove_exp_from_file()/fclose(): ");
	logerror(1, errno);
	free(newfile);
	return -1;
     }
   
   rename(newfile, file);
   free(newfile);
   return 0;
}

/* This puts a list of all files in directory dirname that ends with '.pl'
 * in namelist. It returns the number of matching entries.  */
int my_scandir(char *dirname, char *namelist[])
{
   DIR *dp;
   struct dirent *dent;
   int i = 0;
   
   if((dp = opendir(dirname)) == NULL)
     return -1;
   
   while((dent = readdir(dp)) != NULL)
     i++;
   
   if(i == 0)
     return 0;
   
   rewinddir(dp);
   
   i = 0;
   
   while((dent = readdir(dp)) != NULL)
     {
	
	/* Only parse files with filenames ending with .pl  */
	if(!((strlen( (strrchr(dent->d_name, 'l') == NULL)
		      ? "" : strrchr(dent->d_name, 'l')) == 1)
	     && (strlen( (strrchr(dent->d_name, 'p') == NULL)
			 ? "" : strrchr(dent->d_name, 'p')) == 2)
	     && (strlen( (strrchr(dent->d_name, '.') == NULL)
			 ? "" : strrchr(dent->d_name, '.')) == 3)))
	  continue;
	if((namelist[i] = (char *)malloc(sizeof(char)
				    * (strlen(dirname) + strlen(dent->d_name) + 2))) == NULL)
	  {	     
	     logprintf(1, "Error - In my_scandir()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return 0;
	  }
	snprintf(namelist[i], strlen(dirname) + strlen(dent->d_name) + 2, "%s/%s", dirname, dent->d_name);
	i++;
     }
   closedir(dp);
   return i;
}

/* Checks if an entry exists in the linklist. Returns 1 if user exists,
 * otherwise 0.  */
int check_if_on_linklist(char *ip, int port)
{
   int fd;
   int erret;
   FILE *fp;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   char fileip[MAX_HOST_LEN+1];
   int fileport;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LINK_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In check_if_on_linklist()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In check_if_on_linklist()/open(): ");
	logerror(1, errno); 	
	return -1;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In check_if_on_linklist): Couldn't set lock\n");
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In check_if_on_linklist()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	sscanf(line, "%121s %d", fileip, &fileport);
	if((strncmp(ip, fileip, strlen(fileip)) == 0)
	   && (port == fileport) && (strlen(ip) == strlen(fileip)))
	  {	     
	     while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In check_if_on_linklist()/fclose(): Interrupted system call. Trying again.\n");
	     return 1;
	  }
     }
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In check_if_on_linklist()/fclose(): Interrupted system call. Trying again.\n");
   
   return 0;
}
   
