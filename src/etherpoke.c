#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <libconfig.h>
#include <pthread.h>

#include "config.h"

#include "listener.h"
#include "worker.h"
#include "executioner.h"

#define CONF_FILE "conf/etherpoke.conf"

conf_t *etherpoke_conf = NULL;

// Callback for signals leading to an end of execution of the program
static
void signal_death (int signo)
{

}

// Callback for reconfiguration
static
void signal_reconf (int signo)
{

}

int
main (int argc, char *argv[])
{
	pthread_t *threads;
	pthread_attr_t thread_attr;
	listener_data_t *listener_data;
	worker_data_t worker_data;
	executioner_data_t executioner_data;
	int i, th_rc;
	
	etherpoke_conf = conf_init (CONF_FILE);
	
	if ( etherpoke_conf == NULL ){
		fprintf (stderr, "%s: cannot load configuration file '%s'\n", argv[0], CONF_FILE);
		exit (EXIT_FAILURE);
	}
	
	// Allocate memory space for thread structure.
	// How many threads will be created is dependent on number of interfaces provided in configuration file
	// plus 2 threads (worker and executioner).
	threads = (pthread_t*) malloc (sizeof (pthread_t) * (etherpoke_conf->interfaces_count + (1) + (1)));
	
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
	
	// Spawn worker
	worker_data.id = etherpoke_conf->interfaces_count;
	th_rc = pthread_create (&(threads[etherpoke_conf->interfaces_count]), &thread_attr, worker_main, (void*) &worker_data);
	
	if ( th_rc != 0 ){
		fprintf (stderr, "%s: cannot spawn worker thread\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	// Spawn executioner
	executioner_data.id = etherpoke_conf->interfaces_count + 1;
	th_rc = pthread_create (&(threads[etherpoke_conf->interfaces_count + 1]), &thread_attr, executioner_main, (void*) &executioner_data);
	
	if ( th_rc != 0 ){
		fprintf (stderr, "%s: cannot spawn executioner thread\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	
	pthread_attr_destroy (&thread_attr);
	
	// Wait for threads to finish (don't forget to wait for worker and executioner, hence + 2)
	for ( i = 0; i < etherpoke_conf->interfaces_count + 2; i++ ){
		th_rc = pthread_join (threads[i], NULL); // maybe we could take a look at the status returned from thread?
		
		if ( th_rc != 0 ){
			fprintf (stderr, "%s: cannot join with the threads\n", argv[0]);
			exit (EXIT_FAILURE);
		}
	}
	
	free (threads);
	free (listener_data);
	conf_destroy (etherpoke_conf);
	
	pthread_exit ((void*) 0);
}
