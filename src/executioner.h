/*
 * executioner.h
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

#ifndef _EXECUTIONER_H
#define _EXECUTIONER_H

#include "config.h"

// Length of metapkt_t buffer, this represents how many packets is retrieved
// from the packet queue in every cycle.
#define METAPKT_BUFF_LEN 2048

typedef struct
{
	int id;
	const conf_t *config;
} executioner_data_t;

extern void* executioner_main (void *th_data);
extern void executioner_set_data (executioner_data_t *data, int thread_id, const conf_t *config);

#endif
