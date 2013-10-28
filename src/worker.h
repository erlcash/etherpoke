#ifndef _WORKER_H
#define _WORKER_H

typedef struct
{
	int id;
} worker_data_t;

extern void* worker_main (void *th_data);

#endif
