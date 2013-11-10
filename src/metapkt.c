#include <stdlib.h>
#include <string.h>

#include "metapkt.h"

metapkt_t*
metapkt_init (uint8_t *eth_addr, uint32_t ts)
{
	metapkt_t *pkt;
	
	pkt = (metapkt_t*) malloc (sizeof (metapkt_t));
	
	if ( pkt == NULL )
		return NULL;
	
	memset (pkt, 0, sizeof (metapkt_t));
	
	// Make a copy of eth address
	memcpy (pkt->eth_addr, eth_addr, sizeof (uint8_t) * 6);
	memcpy (&(pkt->ts), &ts, sizeof (uint32_t));
	
	return pkt;
}

void
metapkt_destroy (metapkt_t *pkt)
{
	free (pkt);
}
