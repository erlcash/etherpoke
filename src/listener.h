/*
 * listener.h
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

#ifndef _LISTENER_H
#define _LISTENER_H

#include "config.h"

#define SNAPSHOT_LENGTH 65535

// Length of expanded bpf template
#define LISTENER_BPF_TEMPL_LEN 34
// Length of logical operator ' OR ' in bpf program
#define LISTENER_BPF_LOGOPER_LEN 4

#define LISTENER_BPF_TEMPL "(ether src host %s)"
#define LISTENER_BPG_LOGOPER " or "

typedef struct
{
	int id;
	char *interface;
	filter_t *filters;
} listener_data_t;

extern void* listener_main (void *th_data);

#endif
