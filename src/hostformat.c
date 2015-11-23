#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

int
hostformat_parse (const char *str, char *hostname, int *port)
{
	char *semicolon_pos, *invchar_pos;
	size_t cpy_cnt;

	semicolon_pos = strrchr (str, ':');

	if ( semicolon_pos == NULL )
		return -1;

	cpy_cnt = semicolon_pos - str;

	if ( cpy_cnt > HOST_NAME_MAX )
		cpy_cnt = HOST_NAME_MAX - 1;

	strncpy (hostname, str, cpy_cnt);
	hostname[cpy_cnt] = '\0';

	errno = 0;
	invchar_pos = NULL;

	*port = strtol ((semicolon_pos + 1), &invchar_pos, 10);

	if ( *port == 0 || *invchar_pos != '\0' || errno == ERANGE )
		return -1;

	return 0;
}

