/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#include <stdlib.h>

#include "sock_data.h"
#include "sock_list.h"

void
sock_list_init (struct sock_list *res)
{
	res->head = NULL;
	res->tail = NULL;
}

void
sock_list_add (struct sock_list *res, struct sock_data *item)
{
	if ( res->head == NULL ){
		res->head = item;
		res->tail = res->head;
	} else {
		res->tail->next = item;
		res->tail = item;
	}
}

void
sock_list_del (struct sock_list *res, struct sock_data *item)
{
	struct sock_data *item_prev;
	struct sock_data *item_next;

	item_prev = item->prev;
	item_next = item->next;

	if ( item_prev == NULL )
		res->head = item_next;
	else
		item_prev->next = item_next;

	if ( item_next == NULL )
		res->tail = item_prev;
	else
		item_next->prev = item_prev;

	free (item);
}

void
sock_list_free (struct sock_list *res)
{
	struct sock_data *item_iter, *item_iter_next;

	item_iter = res->head;

	while ( item_iter != NULL ){
		item_iter_next = item_iter->next;
		free (item_iter);
		item_iter = item_iter_next;
	}
}

