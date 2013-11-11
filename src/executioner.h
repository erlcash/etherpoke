#ifndef _EXECUTIONER_H
#define _EXECUTIONER_H

// Length of metapkt_t buffer, this represents how many packets is retrieved
// from the packet queue in every cycle.
#define METAPKT_BUFF_LEN 2048

typedef struct
{
	int id;
} executioner_data_t;

extern void* executioner_main (void *th_data);

#endif
