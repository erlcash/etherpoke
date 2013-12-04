/*
 * session.c
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

#include <pthread.h>
#include <time.h>
#include "session.h"

void
session_init (session_t *session)
{
	pthread_mutex_init (&(session->mut), NULL);
	session->ts = 0;
}

void
session_set_time (session_t *session, time_t ts)
{
	pthread_mutex_lock (&(session->mut));
	session->ts = ts;
	pthread_mutex_unlock (&(session->mut));
}
