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
