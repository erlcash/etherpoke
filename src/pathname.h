/*
 * Copyright (c) 2013 - 2016, CodeWard.org
 */
#ifndef _PATHNAME_H
#define _PATHNAME_H

struct pathname
{
	char *bak;
	char *dir;
	char *base;
};

extern int path_split (const char *path, struct pathname *pathname);

extern void path_free (struct pathname *pathname);

#endif

