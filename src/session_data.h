/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#ifndef _PCAP_SESSION_H
#define _PCAP_SESSION_H

#include <pcap.h>

struct session_data
{
	pcap_t *handle;
	int fd;
	int evt_flag;
	time_t ts;
};

extern void session_data_init (struct session_data *session_data);

extern void session_data_free (struct session_data *session_data);

#endif

