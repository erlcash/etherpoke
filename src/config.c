#include <stdlib.h>
#include <string.h>
#include <libconfig.h>
#include "config.h"

int
conf_init (config_t *conf, const char *file)
{
	config_init (conf);
	
	if ( config_read_file (conf, file) == CONFIG_FALSE ){
		config_destroy (conf);
		return CONFIG_FALSE;
	}
	
	return CONFIG_TRUE;
}

void
conf_destroy (config_t *conf)
{
	config_destroy (conf);
}

int
conf_count_interfaces (config_t *conf)
{
	config_setting_t *interfaces;
	
	interfaces = config_lookup (conf, "common.interfaces");
	
	if ( interfaces == NULL )
		return -1;
	
	return config_setting_length (interfaces);
}

int
conf_count_filters (config_t *conf)
{
	config_setting_t *filters;
	
	filters = config_lookup (conf, "filters");
	
	if ( filters == NULL )
		return -1;
	
	return config_setting_length (filters);
}

int
conf_load_session_timeout (config_t *conf, long int *session_timeout)
{
	if ( config_lookup_int (conf, "common.session_timeout", (long int*) session_timeout) == CONFIG_FALSE )
		return CONFIG_FALSE;
	
	return CONFIG_TRUE;
}

int
conf_load_interfaces (config_t *conf, char *interfaces[], size_t length)
{
	config_setting_t *setting_interfaces;
	const char *val;
	int i;
	
	setting_interfaces = config_lookup (conf, "common.interfaces");
	
	if ( setting_interfaces == NULL )
		return CONFIG_FALSE;
	
	for ( i = 0; i < length; i++ ){
		val = config_setting_get_string_elem (setting_interfaces, i);
		
		if ( val == NULL )
			return CONFIG_FALSE;
		
		strncpy (interfaces[i], val, INTERFACE_NAME_MAX_LEN);
		interfaces[i][strlen (val) - 1] = '\0';
	}
	
	return CONFIG_TRUE;
}
