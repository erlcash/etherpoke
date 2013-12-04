/*
 * queue.h
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

#ifndef _QUEUE_H
#define _QUEUE_H

typedef struct node
{
	void *value;
	struct node *next;
} node_t;

typedef struct
{
	node_t *first;
	node_t *last;
} queue_t;

extern void queue_init (queue_t *que);
extern node_t* queue_enqueue (queue_t *que, void *value);
extern void* queue_dequeue (queue_t *que);
extern void queue_destroy (queue_t *que);

#endif
