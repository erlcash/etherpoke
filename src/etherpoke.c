#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>

#include "config.h"

#include "listener.h"
#include "worker.h"
#include "executioner.h"

#define CONF_FILE "conf/etherpoke.conf"

conf_t *etherpoke_conf;

int
main (int argc, char *argv[])
{
	etherpoke_conf = conf_init (CONF_FILE);
	
	if ( etherpoke_conf == NULL ){
		fprintf (stderr, "%s: cannot load configuration file '%s'\n", argv[0], CONF_FILE);
		exit (EXIT_FAILURE);
	}
	
	conf_destroy (etherpoke_conf);
	
	return EXIT_SUCCESS;
}
