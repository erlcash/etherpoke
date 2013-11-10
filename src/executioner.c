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
	metapkt_t *meta_pkt;
	time_t current_time;
	int i;
	
	executioner_data = (executioner_data_t*) th_data;
	sessions = (session_t*) malloc (sizeof (session_t) * etherpoke_conf->filters_count);
	
	if ( sessions == NULL ){
		fprintf (stderr, "th_%d: cannot allocate memory for sessions\n", executioner_data->id);
		abort ();
	}
	
	memset (sessions, 0, sizeof (session_t) * etherpoke_conf->filters_count);
	
	fprintf (stderr, "th_%d: executioner spawned\n", executioner_data->id);
	
	for ( ;; ){
		pthread_mutex_lock (&packet_queue_mut);
		pthread_cond_wait (&packet_queue_cond, &packet_queue_mut);
		
		// Load value from queue
		meta_pkt = (metapkt_t*) queue_dequeue (&packet_queue);
		
		pthread_mutex_unlock (&packet_queue_mut);
		
		if ( meta_pkt == NULL ){
			fprintf (stderr, "th_%d: nothing in queue\n", executioner_data->id);
			continue;
		}
		
		for ( i = 0; i < etherpoke_conf->filters_count; i++ ){
			// The packet came from the address matching the filter
			if ( memcmp (meta_pkt->eth_addr, etherpoke_conf->filters[i].eth_addr_bin, sizeof (meta_pkt->eth_addr)) == 0 ){
				
				if ( sessions[i].ts == 0 ){
					fprintf (stderr, "th_%d: triggering SESSION_BEGIN for '%s'\n", executioner_data->id, etherpoke_conf->filters[i].name);
					// trigger event SESSION_BEGIN
				}
				
				sessions[i].ts = (time_t) meta_pkt->ts;
				continue;
			}
			
			// Check session timeouts.
			// The session that was not yet established must be skipped otherwise SESSION_END would be triggered.
			if ( sessions[i].ts == 0 )
				continue;
			
			time (&current_time);
			
			if ( difftime (current_time, sessions[i].ts) > etherpoke_conf->filters[i].session_timeout ){
				fprintf (stderr, "th_%d: triggering SESSION_END for '%s'\n", executioner_data->id, etherpoke_conf->filters[i].name);
				sessions[i].ts = 0;
				// trigger event SESSION_END
			}
		}
		
		metapkt_destroy (meta_pkt);
	}
	
	pthread_exit (NULL);
}
