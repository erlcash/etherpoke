#include <pcap.h>

#include "session_data.h"

void
session_data_init (struct session_data *session_data)
{
	session_data->handle = NULL;
	session_data->fd = -1;
	session_data->evt_flag = 0;
	session_data->ts = 0;
}

void
session_data_free (struct session_data *session_data)
{
	if ( session_data->handle != NULL )
		pcap_close (session_data->handle);
	session_data->handle = NULL;
	session_data->fd = -1;
	session_data->evt_flag = 0;
	session_data->ts = 0;
}

