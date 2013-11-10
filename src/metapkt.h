#ifndef _METAPKT_H
#define _METAPKT_H

#include <stdint.h>

typedef struct
{
	uint8_t eth_addr[6];
	uint32_t ts;
} metapkt_t;

extern metapkt_t* metapkt_init (uint8_t *eth_addr, uint32_t ts);
extern void metapkt_destroy (metapkt_t *pkt);

#endif
