/*
 * config.c
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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libconfig.h>

#include "config.h"

static int
filter_set_name (filter_t *filter, const char *name)
{
	if ( filter->name != NULL )
		free (filter->name);
	
	filter->name = (char*) malloc (sizeof (char) * strlen (name) + 1);
	
	if ( filter->name == NULL )
		return 1;
	
	strncpy (filter->name, name, strlen (name));
	filter->name[strlen (name)] = '\0';
	
	return 0;
}

static int
filter_set_ethaddr (filter_t *filter, const char *eth_addr)
{	
	if ( filter->eth_addr != NULL )
		free (filter->eth_addr);
	
	filter->eth_addr = (char*) malloc (sizeof (char) * strlen (eth_addr) + 1);
	
	if ( filter->eth_addr == NULL )
		return 1;
	
	strncpy (filter->eth_addr, eth_addr, strlen (eth_addr));
	filter->eth_addr[strlen (eth_addr)] = '\0';
	
	// Convert string representation to the 6 byte representation
	sscanf (filter->eth_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &(filter->eth_addr_bin[0]), &(filter->eth_addr_bin[1]),
																&(filter->eth_addr_bin[2]), &(filter->eth_addr_bin[3]),
																&(filter->eth_addr_bin[4]), &(filter->eth_addr_bin[5]));
	
	return 0;
}

static int
filter_set_event (filter_t *filter, const char *cmd, int type)
{
	char **event_type;
	
	switch ( type ){
		case FILTER_EVENT_BEGIN:
			event_type = &(filter->cmd_session_begin);
			break;
		case FILTER_EVENT_END:
			event_type = &(filter->cmd_session_end);
			break;
		default:
			return 1;
	}
	
	if ( *event_type != NULL )
		free (*event_type);
	
	*event_type = (char*) malloc (sizeof (char) * strlen (cmd) + 1);
	
	if ( *event_type == NULL )
		return 1;
	
	strncpy (*event_type, cmd, strlen (cmd));
	*((*event_type) + strlen (cmd)) = '\0';
	
	return 0;
}

static int
filter_set_session_timeout (filter_t *filter, uint32_t session_timeout)
{
	filter->session_timeout = session_timeout;
	
	return 0;
}

static void
filter_destroy (filter_t *filter)
{
	if ( filter->name != NULL )
		free (filter->name);
	if ( filter->eth_addr != NULL )
		free (filter->eth_addr);
	if ( filter->cmd_session_begin != NULL )
		free (filter->cmd_session_begin);
	if ( filter->cmd_session_end != NULL )
		free (filter->cmd_session_end);
	
	free (filter);
	filter = NULL;
}

static int
filter_valid_ethaddr (const char *eth_addr)
{
	size_t input_len;
	
	input_len = strlen (eth_addr);
	
	if ( input_len != 17 )
		return CONFIG_FALSE;
	
	if ( (isxdigit (eth_addr[0]) && isxdigit (eth_addr[1]) && eth_addr[2] == ':')
			&& (isxdigit (eth_addr[3]) && isxdigit (eth_addr[4]) && eth_addr[5] == ':')
			&& (isxdigit (eth_addr[6]) && isxdigit (eth_addr[7]) && eth_addr[8] == ':')
			&& (isxdigit (eth_addr[9]) && isxdigit (eth_addr[10]) && eth_addr[11] == ':')
			&& (isxdigit (eth_addr[12]) && isxdigit (eth_addr[13]) && eth_addr[14] == ':')
			&& (isxdigit (eth_addr[15]) && isxdigit (eth_addr[16])) )
		return CONFIG_TRUE;
	
	return CONFIG_FALSE;
}

//
// conf_t functions
//

static int
conf_count_interfaces (config_t *conf)
{
	config_setting_t *interfaces;
	
	interfaces = config_lookup (conf, "common.interfaces");
	
	if ( interfaces == NULL )
		return -1;
	
	return config_setting_length (interfaces);
}

static int
conf_count_filters (config_t *conf)
{
	config_setting_t *filters;
	
	filters = config_lookup (conf, "filters");
	
	if ( filters == NULL )
		return -1;
	
	return config_setting_length (filters);
}

static int
conf_load_interface (config_t *conf, char *interface, size_t index)
{
	config_setting_t *setting_interfaces;
	const char *val;
	
	setting_interfaces = config_lookup (conf, "common.interfaces");
	
	if ( setting_interfaces == NULL )
		return CONFIG_FALSE;
	
	val = config_setting_get_string_elem (setting_interfaces, index);
	
	if ( val == NULL )
		return CONFIG_FALSE;
	
	strncpy (interface, val, INTERFACE_NAME_MAX_LEN);
	interface[INTERFACE_NAME_MAX_LEN] = '\0';
	
	return CONFIG_TRUE;
}

static int
conf_load_filter (config_t *conf, filter_t *filter, size_t index)
{
	const config_setting_t *setting_filters, *setting_filter;
	const char *val;
	long num;
	
	setting_filters = config_lookup (conf, "filters");
	
	if ( setting_filters == NULL )
		return CONFIG_FALSE;
	
	setting_filter = config_setting_get_elem (setting_filters, index);
	
	if ( setting_filter == NULL )
		return CONFIG_FALSE;
	
	val = config_setting_name (setting_filter);
	
	if ( val == NULL )
		return CONFIG_FALSE;
	
	filter_set_name (filter, val);
	
	if ( config_setting_lookup_string (setting_filter, "mac_addr", &val) == CONFIG_FALSE )
		return CONFIG_FALSE;
	
	// Validate eth address
	if ( filter_valid_ethaddr (val) == CONFIG_FALSE )
		return CONFIG_FALSE;
	
	filter_set_ethaddr (filter, val);
	
	if ( config_setting_lookup_string (setting_filter, "session_begin", &val) == CONFIG_FALSE )
		return CONFIG_FALSE;
	
	filter_set_event (filter, val, FILTER_EVENT_BEGIN);
	
	if ( config_setting_lookup_string (setting_filter, "session_end", &val) == CONFIG_FALSE )
		return CONFIG_FALSE;
	
	filter_set_event (filter, val, FILTER_EVENT_END);
	
	if ( config_setting_lookup_int (setting_filter, "session_timeout", &num) == CONFIG_FALSE )
		return CONFIG_FALSE;
	
	filter_set_session_timeout (filter, ((num < 0)? (num * -1):num));
	
	return CONFIG_TRUE;
}

conf_t*
conf_init (const char *file, char *errbuf)
{
	conf_t *conf;
	config_t config; // libconfig structure
	int i;
	
	conf = (conf_t*) malloc (sizeof (conf_t));
	
	if ( conf == NULL )
		return NULL;
	
	memset (conf, 0, sizeof (conf_t));
	memset (errbuf, 0, sizeof (CONF_ERRBUF_SIZE));
	
	config_init (&config);
	
	if ( config_read_file (&config, file) == CONFIG_FALSE ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "%s on line %d", config_error_text (&config), config_error_line (&config));
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	// Load interfaces
	conf->interfaces_count = conf_count_interfaces (&config);
	
	if ( conf->interfaces_count <= 0 ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "no network interfaces specified");
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	conf->interfaces = (char**) calloc (conf->interfaces_count, sizeof (char*));
	
	if ( conf->interfaces == NULL ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "out of memory");
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	for ( i = 0; i < conf->interfaces_count; i++ ){
		conf->interfaces[i] = (char*) calloc ((sizeof (char) * INTERFACE_NAME_MAX_LEN) + 1, 1);
		
		if ( conf->interfaces[i] == NULL ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "out of memory");
			config_destroy (&config);
			conf_destroy (conf);
			return NULL;
		}
		
		if ( conf_load_interface (&config, conf->interfaces[i], i) == CONFIG_FALSE ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "cannot load interface %d", i + 1);
			config_destroy (&config);
			conf_destroy (conf);
			return NULL;
		}
	}
	
	// Load filters
	conf->filters_count = conf_count_filters (&config);
	
	// Fixme: absence of the filters should not be treated as an error
	if ( conf->filters_count == -1 ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "no filters specified");
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	conf->filters = (filter_t*) calloc (conf->filters_count, sizeof (filter_t));
	
	if ( conf->filters == NULL ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "out of memory");
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	for ( i = 0; i < conf->filters_count; i++ ){
		if ( conf_load_filter (&config, &(conf->filters[i]), i) == CONFIG_FALSE ){
			conf->filters_count = (i + 1); // update filter counter to avoid freeing unused memory
			snprintf (errbuf, CONF_ERRBUF_SIZE, "invalid data in filter '%d'", i + 1);
			config_destroy (&config);
			conf_destroy (conf);
			return NULL;
		}
	}
	
	config_destroy (&config); // destroy libconfig object
	
	return conf;
}

void
conf_destroy (conf_t *conf)
{
	int i;
	
	for ( i = 0; i < conf->interfaces_count; i++ )
		free (conf->interfaces[i]);
	free (conf->interfaces);
	
	for ( i = 0; i < conf->filters_count; i++ )
		filter_destroy (&(conf->filters[i]));
	
	free (conf);
	conf = NULL;
}

