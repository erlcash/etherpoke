/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdlib.h>
#include <stdint.h>

// Maximum length of interface name
// FIXME: The value should probably be used from IFNAMSIZ
#define INTERFACE_NAME_MAX_LEN 24

#define CONF_ERRBUF_SIZE 1024

enum
{
	FILTER_EVENT_BEGIN = 1,
	FILTER_EVENT_END = 2,
	FILTER_EVENT_ERROR = 3
};

struct config_filter
{
	char *name;
	char *match;
	char *session_begin;
	char *session_end;
	char *session_error;
	char *interface;
	char *link_type;
	uint32_t session_timeout;
	uint8_t rfmon;
};

struct config
{
	struct config_filter *filter;
	uint32_t filter_cnt;
};

extern struct config* config_open (const char *filename, char *errbuf);

extern void config_close (struct config *conf);

#endif

