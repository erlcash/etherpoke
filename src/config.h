/*
 * Copyright (c) 2013 - 2016, CodeWard.org
 */
#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdlib.h>
#include <stdint.h>

#define CONF_FILTER_NAME_MAXLEN 128
#define CONF_FILTER_MAXCNT 256

#define CONF_ERRBUF_SIZE 256

enum
{
	NOTIFY_EXEC = 0x01,
	NOTIFY_SOCK = 0x02
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
	uint8_t notify;
	struct config_filter *next;
};

struct config
{
	struct config_filter *head;
	struct config_filter *tail;
};

extern int config_load (struct config *conf, const char *filename, char *errbuf);

extern void config_unload (struct config *conf);

#endif

