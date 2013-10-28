#include <stdio.h>
#include <stdlib.h>

#include "worker.h"

void*
worker_main (void *th_data)
{
	worker_data_t *worker_data;
	
	worker_data = (worker_data_t*) th_data;
	
	fprintf (stderr, "th_%d: worker spawned\n", worker_data->id);
	
	for ( ;; ){
		sleep (1);
	}
	
	pthread_exit (NULL);
}
