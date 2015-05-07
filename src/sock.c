/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "sock.h"

int
sock_open (int domain)
{
	int sock;
	int type;
	int proto;
	int opt_val;

	switch ( domain ){
		case AF_INET:
		case AF_INET6:
			type = SOCK_STREAM;
			proto = 0;
			break;

		default:
			domain = AF_INET;
			type = SOCK_STREAM;
			proto = 0;
			break;

		// TODO: support for UNIX sockets
	}

	sock = socket (domain, type | SOCK_NONBLOCK, proto);

	if ( sock == -1 )
		return -1;

	opt_val = 1;

	if ( setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof (opt_val)) == -1 )
		return -1;

	return sock;
}

#define LISTEN_QUEUE_LEN 32

int
sock_listen (int sock, const char *addr, uint16_t port)
{
	struct sockaddr_in sock_addr;
	socklen_t opt_len;
	int rval;

	memset (&sock_addr, 0, sizeof (struct sockaddr_in));

	opt_len = sizeof (sock_addr.sin_family);

	rval = getsockopt (sock, SOL_SOCKET, SO_DOMAIN, &(sock_addr.sin_family), &opt_len);

	if ( rval == -1 )
		return -1;

	sock_addr.sin_port = htons (port);

	rval = inet_pton (sock_addr.sin_family, addr, &(sock_addr.sin_addr));

	if ( rval == -1 )
		return -1;

	rval = bind (sock, (struct sockaddr*) &(sock_addr), sizeof (struct sockaddr_in));

	if ( rval == -1 )
		return -1;

	rval = listen (sock, LISTEN_QUEUE_LEN);

	if ( rval == -1 )
		return -1;

	return sock;
}

int
sock_accept (int sock, struct sockaddr_in *addr)
{
	socklen_t sock_addr_len;

	sock_addr_len = sizeof (struct sockaddr_in);

	return accept (sock, (struct sockaddr*) addr, &sock_addr_len);
}

