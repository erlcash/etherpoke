/*
 * metapkt.c
 * 
 * Copyright 2013 Earl Cash <erl@codeward.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */

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
