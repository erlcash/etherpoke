#include <stdio.h>
#include <stdlib.h>

#include "executioner.h"

void*
executioner_main (void *th_data)
{
	executioner_data_t *executioner_data;
	
	executioner_data = (executioner_data_t*) th_data;
	
	fprintf (stderr, "th_%d: executioner spawned\n", executioner_data->id);
	
	for ( ;; ){	
		sleep (1);
	}
	
	pthread_exit (NULL);
}
