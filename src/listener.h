#ifndef _LISTENER_H
#define _LISTENER_H

#include "config.h"

#define SNAPSHOT_LENGTH 4096

typedef struct
{
	int id;
	char *interface;
	filter_t *filters;
} listener_data_t;

extern void* listener_main (void *th_data);

#endif
