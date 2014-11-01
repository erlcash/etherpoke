/*
 * queue.c
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
#include "queue.h"

void
queue_init (queue_t *que)
{
	que->first = NULL;
	que->last = NULL;
}

node_t*
queue_enqueue (queue_t *que, void *value)
{
	node_t *new_node;
	
	new_node = (node_t*) malloc (sizeof (node_t));
	
	if ( new_node == NULL )
		return NULL;
	
	new_node->value = (void*) value;
	new_node->next = NULL;
	
	if ( que->last == NULL ){
		que->last = new_node;
		que->first = new_node;
	} else {
		que->last->next = new_node;
		que->last = new_node;
	}
	
	return new_node;
}

void*
queue_dequeue (queue_t *que)
{
	node_t *next_node;
	void *value;
	
	if ( que->first == NULL )
		return NULL;
	
	value = que->first->value;
	next_node = que->first->next;
	free (que->first);
		
	que->first = next_node;
	
	if ( que->first == NULL )
		que->last = next_node;
	
	return value;
}

void
queue_destroy (queue_t *que)
{	
	while ( queue_dequeue (que) != NULL );
}
