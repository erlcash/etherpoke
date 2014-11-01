/*
 * metapkt.h
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
