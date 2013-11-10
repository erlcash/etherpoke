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
