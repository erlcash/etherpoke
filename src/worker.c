#include <stdio.h>
#include <stdlib.h>

#include "worker.h"

void*
worker_main (void *th_data)
{
	for ( ;; ){
		fprintf (stderr, "working my ass off\n");
		sleep (2);
	}
	
	pthread_exit (NULL);
}
