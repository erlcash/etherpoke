/*
 * listener.c
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
#include <pcap.h>
#include <netinet/ether.h>
#include <pthread.h>

#include "queue.h"
#include "metapkt.h"
#include "listener.h"

extern queue_t packet_queue;
extern pthread_mutex_t packet_queue_mut;
extern pthread_cond_t packet_queue_cond;

void*
listener_main (void *th_data)
{
	listener_data_t *listener_data;
	pcap_t *pcap_handle;
	struct pcap_pkthdr pkt_header;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *pkt = NULL;
	struct ethhdr *eth_header;
	metapkt_t *meta_pkt;
	
	listener_data = (listener_data_t*) th_data;
	
	pcap_handle = pcap_open_live (listener_data->interface, SNAPSHOT_LENGTH, 1, 0, errbuf);
	
	if ( pcap_handle == NULL ){
		fprintf (stderr, "th_%d: cannot open device '%s': %s\n", listener_data->id, listener_data->interface, errbuf);
		pthread_exit (NULL);
	}
	
	fprintf (stderr, "th_%d: listener spawned (%s)\n", listener_data->id, listener_data->interface);
	
	for ( ;; ){
		pkt = pcap_next (pcap_handle, &pkt_header);
		
		if ( pkt == NULL )
			continue;
		
		eth_header = (struct ethhdr*) pkt;
		
		// NOTICE: memory is freed by executioner
		meta_pkt = metapkt_init (eth_header->h_source, pkt_header.ts.tv_sec);
	
		if ( meta_pkt == NULL ){
			fprintf (stderr, "th_%d: cannot allocate memory for meta packet\n", listener_data->id);
			abort ();
		}
		
		pthread_mutex_lock (&packet_queue_mut);
		if ( queue_enqueue (&packet_queue, (void*) meta_pkt) == NULL ){
			fprintf (stderr, "th_%d: cannot enqueue packet\n", listener_data->id);
			pthread_exit (NULL);
		}
		pthread_cond_signal (&packet_queue_cond); // signal executioner
		pthread_mutex_unlock (&packet_queue_mut);
	}
	
	pcap_close (pcap_handle);
	
	pthread_exit (NULL);
}
