#include <stdio.h>
#include <stdlib.h>

#include "executioner.h"

void*
executioner_main (void *th_data)
{
	for ( ;; ){
		fprintf (stderr, "cutting the heads\n");
		sleep (2);
	}
	
	pthread_exit (NULL);
}
