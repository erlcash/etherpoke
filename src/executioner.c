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

extern session_t *sessions;

extern queue_t packet_queue;
extern pthread_mutex_t packet_queue_mut;
extern pthread_cond_t packet_queue_cond;

void*
executioner_main (void *th_data)
{
	executioner_data_t *executioner_data;
	metapkt_t *meta_pkt[METAPKT_BUFF_LEN];
	int i, j;
	
	executioner_data = (executioner_data_t*) th_data;

	memset (meta_pkt, 0, sizeof (metapkt_t*) * METAPKT_BUFF_LEN);
	
	fprintf (stderr, "th_%d (executioner): spawned\n", executioner_data->id);
	
	while ( executioner_data->loop_state ){
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
			
			// FIXME: This should be replaced by search in hashmap...
			for ( i = 0; i < executioner_data->config->filters_count; i++ ){
				if ( memcmp (meta_pkt[j]->eth_addr, executioner_data->config->filters[i].eth_addr_bin, sizeof (meta_pkt[j]->eth_addr)) == 0 ){
					session_set_time (&(sessions[i]), (time_t) meta_pkt[j]->ts);
					continue;
				}
			}
			
			metapkt_destroy (meta_pkt[j]);
			meta_pkt[j] = NULL;
		}
	}
	
	fprintf (stderr, "th_%d (executioner): dying\n", executioner_data->id);
	
	pthread_exit ((void*) 0);
}

void
executioner_set_data (executioner_data_t *data, int thread_id, const conf_t *config)
{
	data->id = thread_id;
	data->loop_state = 1;
	data->config = config;
}
