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
#include <unistd.h>

#include "etherpoke.h"
#include "queue.h"
#include "config.h"

#include "listener.h"
#include "executioner.h"

conf_t *etherpoke_conf = NULL;

pthread_t *threads = NULL;

queue_t packet_queue;
pthread_mutex_t packet_queue_mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t packet_queue_cond = PTHREAD_COND_INITIALIZER;

// Print help
static
void etherpoke_help (const char *p)
{
	fprintf (stdout, "%s v%s\n\nUsage:\n"
					 "  %s [-dhv] -c <FILE>\n\n"
					 "Options:\n"
					 "  -c <FILE>\tconfiguration file\n"
					 "  -d\t\trun as a daemon\n"
					 "  -h\t\tshow this help text\n"
					 "  -v\t\tshow version information\n"
					 , p, ETHERPOKE_VER, p);
}

static
void etherpoke_version (const char *p)
{
	fprintf (stdout, "%s v%s\n", p, ETHERPOKE_VER);
}

// Callback for signals leading to an end of the program
static
void signal_death (int signo)
{
	fprintf (stderr, "signal caught (killing threads)...\n");
	
	exit (signo);
}

// Callback for reconfiguration
static
void signal_reconf (int signo)
{
	fprintf (stderr, "reconfiguring...\n");
}

int
main (int argc, char *argv[])
{
	pthread_attr_t thread_attr;
	listener_data_t *listener_data;
	executioner_data_t executioner_data;
	char *config_file;
	int i, c, th_rc;
	
	config_file = NULL;
	
	while ( (c = getopt (argc, argv, "c:dhv")) != -1 ){
		switch (c){
			case 'c':
				config_file = strdup (optarg);
				
				if ( config_file == NULL ){
					fprintf (stderr, "%s: cannot allocate memory for configuration file\n", argv[0]);
					abort ();
				}
				break;
			
			case 'd':
				// run as a daemon
				break;
			
			case 'h':
				etherpoke_help (argv[0]);
				exit (EXIT_SUCCESS);
				break;
			
			case 'v':
				etherpoke_version (argv[0]);
				exit (EXIT_SUCCESS);
				break;
			
			case '?':
				break;
		}
	}
	
	if ( config_file == NULL ){
		fprintf (stderr, "%s: configuration file not specified. Use '-h' to see help.\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	etherpoke_conf = conf_init (config_file);
	
	if ( etherpoke_conf == NULL ){
		fprintf (stderr, "%s: cannot load configuration file '%s'.\n", argv[0], config_file);
		free (config_file);
		exit (EXIT_FAILURE);
	}
	
	queue_init (&packet_queue);
	
	// Allocate memory space for thread structure.
	// How many threads will be created is dependent on number of interfaces provided in configuration file
	// plus 2 threads (worker and executioner).
	threads = (pthread_t*) malloc (sizeof (pthread_t) * (etherpoke_conf->interfaces_count + (1)));
	
	if ( threads == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for threads.\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	pthread_attr_init (&thread_attr);
	pthread_attr_setdetachstate (&thread_attr, PTHREAD_CREATE_JOINABLE);
	
	listener_data = (listener_data_t*) malloc (sizeof (listener_data_t) * etherpoke_conf->interfaces_count);
	
	if ( listener_data == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for listener data.\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	// Spawn listeners
	for ( i = 0; i < etherpoke_conf->interfaces_count; i++ ){
		listener_data[i].id = i;
		listener_data[i].interface = etherpoke_conf->interfaces[i];
		listener_data[i].filters = etherpoke_conf->filters;
		
		th_rc = pthread_create (&(threads[i]), &thread_attr, listener_main, (void*) &(listener_data[i]));
		
		if ( th_rc != 0 ){
			fprintf (stderr, "%s: cannot spawn listener thread\n", argv[0]);
			exit (EXIT_FAILURE);
		}
	}
	
	// Spawn executioner
	executioner_data.id = etherpoke_conf->interfaces_count;
	th_rc = pthread_create (&(threads[etherpoke_conf->interfaces_count]), &thread_attr, executioner_main, (void*) &executioner_data);
	
	if ( th_rc != 0 ){
		fprintf (stderr, "%s: cannot spawn executioner thread\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	pthread_attr_destroy (&thread_attr);
	
	signal (SIGTERM, signal_death);
	signal (SIGINT, signal_death);
	signal (SIGQUIT, signal_death);
	signal (SIGHUP, signal_reconf);
	
	// Wait for threads to finish (don't forget to wait for executioner, hence + 1)
	for ( i = 0; i < etherpoke_conf->interfaces_count + 1; i++ ){
		th_rc = pthread_join (threads[i], NULL); // maybe we could (should) take a look at the status returned from thread?
		
		if ( th_rc != 0 ){
			fprintf (stderr, "%s: cannot join with the threads\n", argv[0]);
			exit (EXIT_FAILURE);
		}
	}
	
	free (threads);
	free (listener_data);
	queue_destroy (&packet_queue);
	conf_destroy (etherpoke_conf);
	free (config_file);
	
	pthread_exit ((void*) 0);
}
