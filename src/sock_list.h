/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#ifndef _SOCK_LIST_H
#define _SOCK_LIST_H

#include "sock_data.h"

struct sock_list
{
	struct sock_data *head;
	struct sock_data *tail;
};

extern void sock_list_init (struct sock_list *res);

extern void sock_list_add (struct sock_list *res, struct sock_data *item);

extern void sock_list_del (struct sock_list *res, struct sock_data *item);

extern void sock_list_free (struct sock_list *res);

#endif

