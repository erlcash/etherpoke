/*
 * executioner.c
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
#include <time.h>

#include "config.h"

#include "queue.h"
#include "metapkt.h"
#include "session.h"
#include "executioner.h"

extern conf_t *etherpoke_conf;

extern queue_t packet_queue;
extern pthread_mutex_t packet_queue_mut;
extern pthread_cond_t packet_queue_cond;

void*
executioner_main (void *th_data)
{
	executioner_data_t *executioner_data;
	session_t *sessions;
	metapkt_t *meta_pkt[METAPKT_BUFF_LEN];
	time_t current_time;
	int i, j;
	
	executioner_data = (executioner_data_t*) th_data;
	sessions = (session_t*) malloc (sizeof (session_t) * etherpoke_conf->filters_count);
	
	if ( sessions == NULL ){
		fprintf (stderr, "th_%d: cannot allocate memory for sessions\n", executioner_data->id);
		abort ();
	}
	
	memset (sessions, 0, sizeof (session_t) * etherpoke_conf->filters_count);
	memset (meta_pkt, 0, sizeof (metapkt_t*) * METAPKT_BUFF_LEN);
	
	fprintf (stderr, "th_%d: executioner spawned\n", executioner_data->id);
	
	for ( ;; ){
		pthread_mutex_lock (&packet_queue_mut);
		pthread_cond_wait (&packet_queue_cond, &packet_queue_mut);
		
		// Load a bunch of metapkts from the queue
		for ( j = 0; j < METAPKT_BUFF_LEN; j++ ){
			meta_pkt[j] = (metapkt_t*) queue_dequeue (&packet_queue);
			
			if ( meta_pkt[j] == NULL )
				break;
		}
		
		pthread_mutex_unlock (&packet_queue_mut);
		
		for ( j = 0; j < METAPKT_BUFF_LEN; j++ ){
			
			if ( meta_pkt[j] == NULL ) // leave the loop - the end of buffer was reached
				break;
		
			for ( i = 0; i < etherpoke_conf->filters_count; i++ ){
				// The packet came from the address matching the filter
				if ( memcmp (meta_pkt[j]->eth_addr, etherpoke_conf->filters[i].eth_addr_bin, sizeof (meta_pkt[j]->eth_addr)) == 0 ){
					
					if ( sessions[i].ts == 0 ){
						fprintf (stderr, "th_%d: triggering SESSION_BEGIN for filter '%s'\n", executioner_data->id, etherpoke_conf->filters[i].name);
						// trigger event SESSION_BEGIN
					}
					
					sessions[i].ts = (time_t) meta_pkt[j]->ts;
					continue;
				}
				
				// Check session timeouts.
				// The session that was not yet established must be skipped otherwise SESSION_END would be triggered.
				if ( sessions[i].ts == 0 )
					continue;
				
				time (&current_time);
				
				if ( difftime (current_time, sessions[i].ts) >= etherpoke_conf->filters[i].session_timeout ){
					fprintf (stderr, "th_%d: triggering SESSION_END for filter '%s'\n", executioner_data->id, etherpoke_conf->filters[i].name);
					sessions[i].ts = 0;
					// trigger event SESSION_END
				}
			}
			
			metapkt_destroy (meta_pkt[j]);
			meta_pkt[j] = NULL;
		}
	}
	
	pthread_exit (NULL);
}
