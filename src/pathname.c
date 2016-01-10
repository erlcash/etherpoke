/*
 * Copyright (c) 2013 - 2016, CodeWard.org
 */
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include "pathname.h"

int
path_split (const char *path, struct pathname *pathname)
{
	pathname->bak = strdup (path);

	if ( pathname->bak == NULL )
		return 1;

	pathname->base = basename (pathname->bak);
	pathname->dir = dirname (pathname->bak);

	return 0;
}

void
path_free (struct pathname *pathname)
{
	if ( pathname->bak != NULL )
		free (pathname->bak);

	pathname->base = NULL;
	pathname->dir = NULL;
}

