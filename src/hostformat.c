/*
 * Copyright (c) 2013 - 2016, CodeWard.org
 */
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "hostformat.h"

int
hostformat_parse (const char *str, char *hostname, char *port)
{
	char *semicolon_pos;
	size_t cpy_cnt;

	semicolon_pos = strrchr (str, ':');

	if ( semicolon_pos == NULL )
		return -1;

	cpy_cnt = semicolon_pos - str;

	if ( cpy_cnt > HOST_NAME_MAX )
		cpy_cnt = HOST_NAME_MAX - 1;

	strncpy (hostname, str, cpy_cnt);
	hostname[cpy_cnt] = '\0';

	strncpy (port, (semicolon_pos + 1), PORT_MAX_LEN);
	port[PORT_MAX_LEN - 1] = '\0';

	return 0;
}

