/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#ifndef _SOCK_DATA_H
#define _SOCK_DATA_H

#include <netinet/in.h>

struct sock_data
{
	int sd;
	struct sockaddr_in addr;
	struct sock_data *prev;
	struct sock_data *next;
};

#endif

