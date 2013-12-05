/*
 * clocker.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <wordexp.h>
#include <time.h>

#include "config.h"

#include "session.h"
#include "clocker.h"

extern session_t *sessions;

static int
clocker_exec (const char *cmd)
{
	wordexp_t command;
	int rval;
	
	// Parse the command string and create an array which can be passed to execv
	switch ( wordexp (cmd, &command, 0) ){
		case 0:
			break;
		case WRDE_NOSPACE:
			wordfree (&command);
			break;
		default:
			return EXIT_FAILURE;
	}
	
	// Close stdout and stderr we do not want our output polluted
	fclose (stdout); fclose (stderr);
	
	rval = execv (command.we_wordv[0], command.we_wordv);
	wordfree (&command);
	
	if ( rval == -1 )
		return EXIT_FAILURE;
	
	return EXIT_SUCCESS;
}

void*
clocker_main (void *th_data)
{
	clocker_data_t *clocker_data;
	session_t *sessions_ref;
	time_t current_time;
	pid_t pid;
	int i;
	
	clocker_data = (clocker_data_t*) th_data;
	
	sessions_ref = (session_t*) malloc (sizeof (session_t) * clocker_data->config->filters_count);
	
	if ( sessions_ref == NULL ){
		fprintf (clocker_data->log, "th_%d (clocker): cannot allocate memory for the reference session data\n", clocker_data->id);
		abort ();
	}
	
	// Decide which line apply... too tired right now...
	memset (sessions_ref, 0, sizeof (session_t) * clocker_data->config->filters_count);
	
	fprintf (clocker_data->log, "th_%d (clocker): spawned\n", clocker_data->id);
	
	while ( clocker_data->loop_state ){
		time (&current_time);
		
		for ( i = 0; i < clocker_data->config->filters_count; i++ ){
			if ( (sessions_ref[i].ts == 0) && (sessions[i].ts > 0) ){
				sessions_ref[i].ts = sessions[i].ts;
				
				// Trigger event SESSION_BEGIN
				// FIXME: replace exit with pthread_exit (is it valid?)
				pid = fork ();
				
				if ( pid == 0 ){
					if ( clocker_exec (clocker_data->config->filters[i].cmd_session_begin) == EXIT_FAILURE ){
						fprintf (clocker_data->log, "th_%d (clocker): cannot execute event hook '%s': %s\n", clocker_data->id, clocker_data->config->filters[i].cmd_session_begin, "<REASON HERE>");
						exit (EXIT_FAILURE);
					}
					exit (EXIT_SUCCESS);
				}
				
				if ( pid == -1 ){
					fprintf (clocker_data->log, "th_%d (clocker): cannot fork myself\n", clocker_data->id);
					abort ();
				}
			
			} else if ( (sessions[i].ts > 0) && difftime (current_time, sessions[i].ts) >= clocker_data->config->filters[i].session_timeout ){
				session_set_time (&(sessions[i]), 0);
				sessions_ref[i].ts = 0;
				
				// Trigger event SESSION_END
				pid = fork ();
				
				if ( pid == 0 ){
					if ( clocker_exec (clocker_data->config->filters[i].cmd_session_end) == EXIT_FAILURE ){
						fprintf (clocker_data->log, "th_%d (clocker): cannot execute event hook '%s': %s\n", clocker_data->id, clocker_data->config->filters[i].cmd_session_end, "<REASON HERE>");
						exit (EXIT_FAILURE);
					}
					exit (EXIT_SUCCESS);
				}
				
				if ( pid == -1 ){
					fprintf (clocker_data->log, "th_%d (clocker): cannot fork myself\n", clocker_data->id);
					abort ();
				}
			}
			
			waitpid (-1, NULL, WNOHANG);
		}
		
		sleep (1);
	}
	
	fprintf (clocker_data->log, "th_%d (clocker): dying...\n", clocker_data->id);
	
	free (sessions_ref);
	
	pthread_exit ((void*) 0);
}

void
clocker_set_data (clocker_data_t *data, int thread_id, const conf_t *config, FILE *log)
{
	data->id = thread_id;
	data->loop_state = 1;
	data->config = config;
	data->log = log;
}
