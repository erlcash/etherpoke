/*
 * log.c
 * 
 * Copyright 2013 Earl Cash <erl@codeward.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */

#include <stdio.h>
#include "log.h"

FILE*
log_open (const char *file)
{
	FILE *fd;
	
	fd = fopen (file, "a");
	
	if ( fd == NULL )
		return NULL;
	
	if ( setvbuf (fd, NULL, _IOLBF, 0) != 0 ){
		fclose (fd);
		return NULL;
	}
	
	return fd;
}

int
log_close (FILE *log_fd)
{
	return fclose (log_fd);
}

