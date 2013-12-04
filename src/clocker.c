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

extern conf_t *etherpoke_conf;
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
	
	sessions_ref = (session_t*) malloc (sizeof (session_t) * etherpoke_conf->filters_count);
	
	if ( sessions_ref == NULL ){
		fprintf (stderr, "th_%d: cannot allocate memory for the reference session data\n", clocker_data->id);
		abort ();
	}
	
	// Decide which line apply... too tired right now...
	memset (sessions_ref, 0, sizeof (session_t) * etherpoke_conf->filters_count);
	
	fprintf (stderr, "th_%d: clocker spawned\n", clocker_data->id);
	
	for ( ;; ){
		time (&current_time);
		
		for ( i = 0; i < etherpoke_conf->filters_count; i++ ){
			if ( (sessions_ref[i].ts == 0) && (sessions[i].ts > 0) ){
				sessions_ref[i].ts = sessions[i].ts;
				
				// Trigger event SESSION_BEGIN
				// FIXME: replace exit with pthread_exit (is it valid?)
				pid = fork ();
				
				if ( pid == 0 ){
					if ( clocker_exec (etherpoke_conf->filters[i].cmd_session_begin) == EXIT_FAILURE ){
						fprintf (stderr, "th_%d: cannot execute event hook '%s': %s\n", clocker_data->id, etherpoke_conf->filters[i].cmd_session_begin, "<REASON HERE>");
						exit (EXIT_FAILURE);
					}
					exit (EXIT_SUCCESS);
				}
				
				if ( pid == -1 ){
					fprintf (stderr, "th_%d: cannot fork myself\n", clocker_data->id);
					abort ();
				}
			
			} else if ( (sessions[i].ts > 0) && difftime (current_time, sessions[i].ts) >= etherpoke_conf->filters[i].session_timeout ){
				session_set_time (&(sessions[i]), 0);
				sessions_ref[i].ts = 0;
				
				// Trigger event SESSION_END
				pid = fork ();
				
				if ( pid == 0 ){
					if ( clocker_exec (etherpoke_conf->filters[i].cmd_session_end) == EXIT_FAILURE ){
						fprintf (stderr, "th_%d: cannot execute event hook '%s': %s\n", clocker_data->id, etherpoke_conf->filters[i].cmd_session_end, "<REASON HERE>");
						exit (EXIT_FAILURE);
					}
					exit (EXIT_SUCCESS);
				}
				
				if ( pid == -1 ){
					fprintf (stderr, "th_%d: cannot fork myself\n", clocker_data->id);
					abort ();
				}
			}
			
			waitpid (-1, NULL, WNOHANG);
		}
		
		sleep (1);
	}
	
	pthread_exit ((void*) 0);
}













				// Check session timeouts.
				// The session that was not yet established must be skipped otherwise SESSION_END would be triggered.
				/*if ( sessions[i].ts == 0 )
					continue;
				
				time (&current_time);
				
				if ( difftime (current_time, sessions[i].ts) >= etherpoke_conf->filters[i].session_timeout ){
					fprintf (stderr, "th_%d: triggering SESSION_END for filter '%s'\n", executioner_data->id, etherpoke_conf->filters[i].name);
					sessions[i].ts = 0;
				}*/

/*
						// Trigger event SESSION_BEGIN
						pid = fork ();
						
						if ( pid == 0 ){
							if ( executioner_exec (etherpoke_conf->filters[i].cmd_session_begin) == EXIT_FAILURE ){
								fprintf (stderr, "th_%d: cannot execute event hook '%s': %s\n", executioner_data->id, etherpoke_conf->filters[i].cmd_session_begin, "<REASON HERE>");
								exit (EXIT_FAILURE);
							}
							exit (EXIT_SUCCESS);
						}
						
						if ( pid == -1 ){
							fprintf (stderr, "th_%d: cannot fork myself\n", executioner_data->id);
							abort ();
						}*/
