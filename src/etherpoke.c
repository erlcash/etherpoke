/*
 * etherpoke.c
 * 
 * Copyright 2013 Earl Cash <erl@codeward.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libconfig.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"

#include "etherpoke.h"
#include "queue.h"
#include "session.h"
#include "log.h"

#include "listener.h"
#include "executioner.h"
#include "clocker.h"

conf_t *etherpoke_conf = NULL;
session_t *sessions = NULL;

pthread_t *threads = NULL;
int **threads_loop_state = NULL;

// Queue variables
queue_t packet_queue;
pthread_mutex_t packet_queue_mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t packet_queue_cond = PTHREAD_COND_INITIALIZER;

// Print help
static void
etherpoke_help (const char *p)
{
	fprintf (stdout, "%s v%s\n\nUsage:\n"
					 "  %s [-dfhv] -c <FILE>\n\n"
					 "Options:\n"
					 "  -c <FILE>\tconfiguration file\n"
					 "  -d\t\trun as a daemon\n"
					 "  -f <FILE>\twrite output to specified file instead of stderr\n"
					 "  -h\t\tshow this help text\n"
					 "  -v\t\tshow version information\n"
					 , p, ETHERPOKE_VER, p);
}

static void
etherpoke_version (const char *p)
{
	fprintf (stdout, "%s v%s\n", p, ETHERPOKE_VER);
}

static void
etherpoke_die (int signo)
{
	int i;
	
	for ( i = 0; i < ETHERPOKE_THREAD_COUNT (etherpoke_conf->interfaces_count); i++ )
		*(threads_loop_state[i]) = 0;
	
	// Signal executioner to unblock itself
	pthread_mutex_lock (&packet_queue_mut);
	pthread_cond_signal (&packet_queue_cond);
	pthread_mutex_unlock (&packet_queue_mut);
}

int
main (int argc, char *argv[])
{
	pthread_attr_t thread_attr;
	listener_data_t *listener_data;
	executioner_data_t executioner_data;
	clocker_data_t clocker_data;
	char *config_file, *log_file, conf_errbuf[CONF_ERRBUF_SIZE];
	int i, c, th_rc, daemonize = 0;
	FILE *log_fd;
	pid_t pid;
	
	config_file = NULL;
	log_file = NULL;
	log_fd = stderr;
	
	while ( (c = getopt (argc, argv, "c:df:hv")) != -1 ){
		switch (c){
			case 'c':
				config_file = strdup (optarg);
				
				if ( config_file == NULL ){
					fprintf (stderr, "%s: cannot allocate memory for configuration file\n", argv[0]);
					exit (EXIT_FAILURE);
				}
				break;
			
			case 'd':
				daemonize = 1;
				break;
			
			case 'f':
				log_file = strdup (optarg);
				
				if ( log_file == NULL ){
					fprintf (stderr, "%s: cannot allocate memory for log file\n", argv[0]);
					exit (EXIT_FAILURE);
				}
				break;
			
			case 'h':
				etherpoke_help (argv[0]);
				exit (EXIT_SUCCESS);
				break;
			
			case 'v':
				etherpoke_version (argv[0]);
				exit (EXIT_SUCCESS);
				break;
			
			default:
				etherpoke_help (argv[0]);
				exit (EXIT_FAILURE);
				break;
		}
	}
	
	if ( config_file == NULL ){
		fprintf (stderr, "%s: configuration file not specified. Use '-h' to see usage.\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	etherpoke_conf = conf_init (config_file, conf_errbuf);
	
	if ( etherpoke_conf == NULL ){
		fprintf (stderr, "%s: cannot load configuration file '%s': %s\n", argv[0], config_file, conf_errbuf);
		free (config_file);
		exit (EXIT_FAILURE);
	}
	
	// Initialize the packet queue
	queue_init (&packet_queue);
	
	// Initialize session data
	sessions = (session_t*) malloc (sizeof (session_t) * etherpoke_conf->filters_count);
	
	if ( sessions == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for session data.\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	for ( i = 0; i < etherpoke_conf->filters_count; i++ )
		session_init (&(sessions[i]));
	
	// Allocate memory space for thread structure.
	// How many threads will be created is dependent on number of interfaces provided in configuration file
	// plus 2 threads (clocker and executioner).
	threads = (pthread_t*) malloc (sizeof (pthread_t) * ETHERPOKE_THREAD_COUNT(etherpoke_conf->interfaces_count));
	
	if ( threads == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for threads.\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	threads_loop_state = (int**) malloc (sizeof (int*) * ETHERPOKE_THREAD_COUNT(etherpoke_conf->interfaces_count));
	
	if ( threads_loop_state == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for threads loop state.\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	pthread_attr_init (&thread_attr);
	pthread_attr_setdetachstate (&thread_attr, PTHREAD_CREATE_JOINABLE);
	
	listener_data = (listener_data_t*) malloc (sizeof (listener_data_t) * etherpoke_conf->interfaces_count);
	
	if ( listener_data == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for listener data.\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	// Attempt to open specified file for writing
	if ( log_file != NULL ){
		log_fd = log_open (log_file);
		
		if ( log_fd == NULL ){
			fprintf (stderr, "%s: cannot open log file '%s'.\n", argv[0], log_file);
			exit (EXIT_FAILURE);
		}
		
		// Free memory used by log's filename
		free (log_file);
	}
	
	// Daemonize the process if the flag was set
	if ( daemonize == 1 ){
		pid = fork ();
		
		if ( pid > 0 ){
			exit (EXIT_SUCCESS);
		} else if ( pid == -1 ){
			fprintf (stderr, "%s: cannot daemonize the process (fork failed).\n", argv[0]);
			exit (EXIT_FAILURE);
		}
		
		if ( setsid () == -1 ){
			fprintf (stderr, "%s: cannot daemonize the process (setsid failed).\n", argv[0]);
			exit (EXIT_FAILURE);
		}
		
		umask (0);
		chdir ("/");
		fclose (stdin);
		fclose (stdout);
		fclose (stderr);
	}
	
	// Spawn listeners
	for ( i = 0; i < etherpoke_conf->interfaces_count; i++ ){
		listener_set_data (&(listener_data[i]), i, (const conf_t*) etherpoke_conf, log_fd, (const char*) etherpoke_conf->interfaces[i]);	
		threads_loop_state[i] = &(listener_data[i].loop_state);
		th_rc = pthread_create (&(threads[i]), &thread_attr, listener_main, (void*) &(listener_data[i]));
		
		if ( th_rc != 0 ){
			fprintf (stderr, "%s: cannot spawn listener thread\n", argv[0]);
			exit (EXIT_FAILURE);
		}
	}
	
	// Spawn executioner
	executioner_set_data (&executioner_data, etherpoke_conf->interfaces_count, (const conf_t*) etherpoke_conf, log_fd);
	threads_loop_state[etherpoke_conf->interfaces_count] = &(executioner_data.loop_state);
	th_rc = pthread_create (&(threads[etherpoke_conf->interfaces_count]), &thread_attr, executioner_main, (void*) &executioner_data);
	
	if ( th_rc != 0 ){
		fprintf (stderr, "%s: cannot spawn executioner thread\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	// Spawn clocker
	clocker_set_data (&clocker_data, etherpoke_conf->interfaces_count + 1, (const conf_t*) etherpoke_conf, log_fd);
	threads_loop_state[etherpoke_conf->interfaces_count + 1] = &(clocker_data.loop_state);
	th_rc = pthread_create (&(threads[etherpoke_conf->interfaces_count + 1]), &thread_attr, clocker_main, (void*) &clocker_data);
	
	if ( th_rc != 0 ){
		fprintf (stderr, "%s: cannot spawn clocker thread\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	pthread_attr_destroy (&thread_attr);
	
	// Bind signal handlers
	signal (SIGINT, etherpoke_die);
	signal (SIGTERM, etherpoke_die);
	signal (SIGQUIT, etherpoke_die);
	
	for ( i = 0; i < ETHERPOKE_THREAD_COUNT (etherpoke_conf->interfaces_count); i++ ){
		th_rc = pthread_join (threads[i], NULL); // maybe we could (should) take a look at the status returned from thread?
		
		if ( th_rc != 0 ){
			fprintf (stderr, "%s: cannot join with the threads\n", argv[0]);
			exit (EXIT_FAILURE);
		}
	}
	
	free (threads);
	free (threads_loop_state);
	free (listener_data);
	queue_destroy (&packet_queue);
	conf_destroy (etherpoke_conf);
	free (config_file);
	
	if ( log_fd != stderr )
		log_close (log_fd);
	
	pthread_exit (NULL);
}
