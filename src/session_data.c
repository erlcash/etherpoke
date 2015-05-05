/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#include <string.h>
#include <pcap.h>
#include <wordexp.h>

#include "session_data.h"

void
session_data_init (struct session_data *session_data)
{
	session_data->handle = NULL;
	session_data->fd = -1;
	memset (&(session_data->evt), 0, sizeof (struct session_event));
}

void
session_data_free (struct session_data *session_data)
{
	if ( session_data->handle != NULL )
		pcap_close (session_data->handle);

	session_data->handle = NULL;
	session_data->fd = -1;
	memset (&(session_data->evt), 0, sizeof (struct session_event));

	wordfree (&(session_data->evt_cmd_beg));
	wordfree (&(session_data->evt_cmd_err));
	wordfree (&(session_data->evt_cmd_end));
}

