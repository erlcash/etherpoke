#ifndef _EXECUTIONER_H
#define _EXECUTIONER_H

typedef struct
{
	int id;
} executioner_data_t;

extern void* executioner_main (void *th_data);

#endif
