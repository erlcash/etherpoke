/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#ifndef _SOCK_H
#define _SOCK_H

#include <stdint.h>
#include <netinet/in.h>

extern int sock_open (int domain);

extern int sock_listen (int sock, const char *addr, uint16_t port);

extern int sock_accept (int sock, struct sockaddr_in *addr);

#endif

