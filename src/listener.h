#ifndef _LISTENER_H
#define _LISTENER_H

#include "config.h"

#define SNAPSHOT_LENGTH 65535


#define LISTENER_BPF_TEMPL "(ether src host %s)"

// Length of expanded bpf template
#define LISTENER_BPF_TEMPL_LEN 34
// Length of logical operator ' OR ' in bpf program
#define LISTENER_BPF_LOGOPER_LEN 4

typedef struct
{
	int id;
	char *interface;
	filter_t *filters;
} listener_data_t;

extern void* listener_main (void *th_data);

#endif
