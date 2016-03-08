/*

	eigrp - A routing daemon for the eigrp protocol
	Copyright (C) 2015 Paraskeuas Karahatzis

	This program is free software: you can redistribute it and/or modify it under the terms of the
	GNU General Public License as published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
	even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
	General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program. If not,
	see <http://www.gnu.org/licenses/>. 

	dervelakos.madlax@gmail.com

*/

#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdbool.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "eigrp_ip6.h"
#include "eigrp_base.h"
#include "eigrp_prot.h"
#include "packet_factory.h"
#include "eigrp_structs.h"
#include "utils.h"
#include "config.h"



void send_ip6_packet_multicast(packetv4_param *param, struct eigrp_proccess *proc){
	int i;
	interface *iff;
	struct sockaddr_in sin;
	
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("224.0.0.10");


	for(i=0;i<proc->ifs.size;i++){
		iff = vector_get(&proc->ifs,i);
		if(!iff->is_up)continue;
		if(sendto(iff->socket6, param->buffer, param->buffer_len, 0,(struct sockaddr*)&sin, sizeof(sin)) < 0){
			printf("Error Sending Packet Muticast\n");
		}
	}
}

void send_ip6_packet(packetv4_param *param, int socket){
	
	if(sendto(socket, param->buffer, param->buffer_len, 0,(struct sockaddr*)&param->sin, sizeof(param->sin)) < 0){
		printf("Error Sending Packet\n");
	}
}

int disable_ip6_loopback(int socket){
	char loopch = 0;
	if(setsockopt(socket, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch)) < 0){
		return -1;
	}
	return 0;
}

bool init_ip6(interface *iff){

	//IPv6 is not implemented
	return false;

	char host[NI_MAXHOST];
	int ret;
	iff->socket6 = socket(AF_INET6, SOCK_RAW, EIGRP_PROT_NUM);
	if(iff->socket6 == -1){
		printf("ERROR:Could not create socket ip6 for interface %s.\n", iff->name);
		return false;
	}
	printf("Test Family:%d IF:%s\n",iff->ifa_addr_ip6.sin6_family,iff->name);
	int result = getnameinfo((struct sockaddr*)&iff->ifa_addr_ip6, sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL , 0 , NI_NUMERICHOST);
	if( result != 0){
		printf("ERROR:getnameinfo() failed: %s.\n",gai_strerror(result));
		return false;
	}
	struct ipv6_mreq group;
	struct addrinfo *reslocal,*resmulti;//,hints;
	
	getaddrinfo(host, NULL, NULL, &reslocal);
	getaddrinfo("FF02::A",NULL,NULL,&resmulti);
	group.ipv6mr_multiaddr = ((struct sockaddr_in6 *)resmulti->ai_addr)->sin6_addr;
	group.ipv6mr_interface = ((struct sockaddr_in6 *)reslocal->ai_addr)->sin6_scope_id;
	if(setsockopt(iff->socket6, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char*)&group, sizeof(group)) < 0){
		printf("ERROR:Could not join multicast group at ip6 for interface %s.\n", iff->name);
		return false;
	}
	if(setsockopt(iff->socket6, SOL_SOCKET, SO_BINDTODEVICE, iff->name, sizeof(iff->name))){
		printf("ERROR:Could not bind socket to interface %s.\n", iff->name);
		close(iff->socket6);
		return false;
	}
	int loopch = 0;
	if(setsockopt(iff->socket6, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loopch, sizeof(loopch)) < 0){
		printf("ERROR:Could not set disable loopback to interface %s.\n", iff->name);				
		close(iff->socket6);
		return false;
	}
	ret = 0;//pthread_create(&iff->packet_listener6 ,NULL ,listen_ip6 ,(void*)iff);
	if(ret){
		printf("ERROR:Error creating listen thread for interface %s at ip6.\n", iff->name);
		close(iff->socket6);
		return false;
	}

	freeaddrinfo(reslocal);
	freeaddrinfo(resmulti);

	return true;
}

void send_packets_neighbour_ip6(neighbour *n){
	long long current_time;
	long long delay = 1000; //Send or resend packets every 1 second

	current_time = current_timestamp();

	if(current_time - n->last_response > n->holdtime){
		printf("Neighbour is inactive removing him.\n");
		free_neighbour(n,"holding time expired");
		return;
	}

	if((!n->send_next_packet) && current_time - n->last_packet_sent < delay){
		return;
	}

	n->send_next_packet = false;

	if(linkedlist_isempty(&n->packet_queue)){
		if(n->last_ack_sent != n->pending_ack && n->pending_ack != -1){
			int length = sizeof(struct eigrphdr);
			packetv4_param *packet = create_empty_packet(OPCODE_HELLO,0, n->sin);


	
			n->last_ack_sent = n->pending_ack;
			create_eigrp_header(packet, length, OPCODE_HELLO, n->proc->proccess_id, 0, n->pending_ack, 0);

			//Record packets sent
			n->proc->stats.packets_sent[packet->opcode]++;
			if(n->pending_ack != 0)n->proc->stats.acks_sent++;

			send_ip4_packet(packet,n->interface->socket4);
			n->last_packet_sent = current_time;

			free(packet);
		}
	}else{
		packetv4_param *packet = linkedlist_peekfirst(&n->packet_queue);
		if(packet->seq_num == 0){
			int seq_num = n->proc->seq_num++; //increase the seq_num by 1
			packet->seq_num = seq_num; //assign the seq to the struct so it be retrived later to check for ack
			
			//create_eigrp_header(packet, packet->buffer_len, packet->opcode, n->proc->proccess_id, packet->seq_num , n->pending_ack, packet->flags);
			//n->last_ack_sent = n->pending_ack;

			//Save the seq num for the neighbour state change				
			if( flags_are_set(packet->flags, FLAG_INIT) ){
				n->init_seq = seq_num;
			}
		}

		int ack = n->pending_ack;
		if(ack == -1) ack = 0; 
		create_eigrp_header(packet, packet->buffer_len, packet->opcode, n->proc->proccess_id, packet->seq_num , ack, packet->flags);
		n->last_ack_sent = n->pending_ack;
		
		//Record packets sent
		n->proc->stats.packets_sent[packet->opcode]++;
		if(n->pending_ack != 0)n->proc->stats.acks_sent++;
		
		send_ip4_packet(packet,n->interface->socket4);
		n->last_packet_sent = current_time;
	}
}


void *send_ipv6_packets( void *ptr){
	struct eigrp_proccess *proc;
	neighbour *n;
	//long long current_time;
	struct sockaddr_in sin;
	bool cr = false; //Indicates if cr flag should be set on a multicast packet.
	int flags = 0; //Flag the multicast packet will have
	int seq_len=0; //The actual length we used from the hole buffer

	proc = (struct eigrp_proccess *)ptr;

	while(proc->running){
		sleep_millis(100);

		if(linkedlist_isempty(&proc->multicast_queue)){
			//Send any pending packets from neighbour queue
			hash_collection col;
			prepare_hashcollection(&col,proc->neighbours);
			while( (n = next(&col)) != NULL){
				send_packets_neighbour_ip6(n);
			}

		}else{
			printf("Sending multicast Packet.\n");
			//Send the next multicast packet

			int seq_num = proc->seq_num++; // Get the seq number now cause we might need it for the seq_tlv packet

			//If we have pending ack send the sequence tlv 		
			if(!packet_queues_empty(proc)){
				cr = true;
				
				//Build the sequence tlv
				void *seq_tlv=malloc(PACKET_LENGTH); //We will write the tlv in this buffer and then copy it into the packet
				seq_len = fill_sequence_tlv(seq_tlv, proc);
				//Create the packet
				packetv4_param *seq_packet = create_empty_packet(OPCODE_HELLO, 0 , sin);
				addtlv(seq_packet,seq_tlv,seq_len);
				struct tlv_next_multicast next_mul;
				next_mul.type = htons(0x0005);
				next_mul.length = htons(8);
				next_mul.seq_num = htonl(seq_num);
				addtlv(seq_packet,&next_mul,8);
				create_eigrp_header(seq_packet, seq_packet->buffer_len, seq_packet->opcode, proc->proccess_id, 0, 0, 0);
				send_ip4_packet_multicast(seq_packet,proc);
				//Record packets sent
				proc->stats.packets_sent[seq_packet->opcode]++;
				free(seq_tlv);
				free(seq_packet);
	
			}

			packetv4_param *packet = linkedlist_getfirst(&proc->multicast_queue);
			//int length = sizeof(struct eigrphdr);
			//char* buffer = malloc(length);

			if(cr) flags |= FLAG_CR;
			create_eigrp_header(packet, packet->buffer_len, packet->opcode, proc->proccess_id, seq_num, 0, flags);
			queue_sended_multicast_packet(proc, packet,seq_num);
			send_ip4_packet_multicast(packet,proc);
			//Record packets sent
			proc->stats.packets_sent[packet->opcode]++;
			printf("Done sending multicast packet.\n");
		}
	}

	return NULL;
}

void *hello_packet_thread_ip6(void *ptr){
	struct eigrp_proccess *proc;
	interface *iff;

	proc = (struct eigrp_proccess *)ptr;

	//Prepare the hello packet once so we don't have to make it over and over
	int i;

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("224.0.0.10");

	packetv4_param *packet = create_empty_packet(OPCODE_HELLO, 0, sin);
	create_hello_packet(packet,proc);

	while(proc->running){		
	
		for(i=0;i<proc->ifs.size;i++){
			iff = vector_get(&proc->ifs,i);

			//Record packets sent
			proc->stats.packets_sent[OPCODE_HELLO]++;			

			if(iff->ip4_init && iff->running)
				send_ip4_packet(packet, iff->socket4);
		}
		

		sleep(proc->hello_interval);		
	}
	
	free(packet);

	return NULL;
}
