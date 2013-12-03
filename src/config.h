/*
 * config.h
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

#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdlib.h>
#include <stdint.h>

// Maximum length of interface name
// FIXME: The value should probably be used from IFNAMSIZ
#define INTERFACE_NAME_MAX_LEN 24

#define FILTER_EVENT_BEGIN 0
#define FILTER_EVENT_END 1

typedef struct
{
	char *name;
	char *eth_addr;
	uint8_t eth_addr_bin[6];
	char *cmd_session_begin;
	char *cmd_session_end;
	uint32_t session_timeout;
} filter_t;

#define CONF_ERRBUF_SIZE 1024

typedef struct
{
	long int session_timeout;
	char **interfaces;
	uint8_t interfaces_count;
	filter_t *filters;
	uint16_t filters_count;
} conf_t;

extern conf_t* conf_init (const char *file, char *errbuf);
extern void conf_destroy (conf_t *conf);

#endif
