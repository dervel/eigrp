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

#include "eigrp_ip4.h"
#include "eigrp_base.h"
#include "eigrp_prot.h"
#include "packet_factory.h"
#include "eigrp_structs.h"
#include "utils.h"
#include "config.h"

void send_ip4_packet(packetv4_param *param, int socket){
	
	if(sendto(socket, param->buffer, param->buffer_len, 0,(struct sockaddr*)&param->sin, sizeof(param->sin)) < 0){
		printf("Error Sending Packet\n");
	}
}

void send_ip4_packet_multicast(packetv4_param *packet, struct eigrp_proccess *proc){
	int i;
	interface *iff;
	struct sockaddr_in sin;
	
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr.s_addr = inet_addr("224.0.0.10");

	int seq_num = proc->seq_num++;

	for(i=0;i<proc->ifs.size;i++){
		iff = vector_get(&proc->ifs,i);
		if(!iff->is_up)continue;

		packetv4_param *seq_packet = create_empty_packet(OPCODE_HELLO, 0 , sin);
		unsigned char *seq_tlv=malloc(PACKET_LENGTH); //We will write the tlv in this buffer and then copy it into the packet

		bool send_seq_packet = false;
		int len = 4;
		int flags = 0;
		neighbour *n;
		hash_collection col;
		prepare_hashcollection(&col,proc->neighbours);
		while( (n = next(&col)) != NULL){
			if(n->interface->index == iff->index && !linkedlist_isempty(&n->packet_queue)){
				send_seq_packet = true;
			
				if(n->address.ss_family == AF_INET){
					struct sockaddr_in *address = (struct sockaddr_in *)&n->address;
					seq_tlv[len++] = sizeof(address->sin_addr.s_addr);
					memcpy(&seq_tlv[len],&address->sin_addr.s_addr,sizeof(address->sin_addr.s_addr));
					len += sizeof(address->sin_addr.s_addr);
				}else{
					struct sockaddr_in6 *address = (struct sockaddr_in6 *)&n->address;
					seq_tlv[len++] = sizeof(address->sin6_addr.s6_addr);
					memcpy(&seq_tlv[len],address->sin6_addr.s6_addr,sizeof(address->sin6_addr.s6_addr));
					len += sizeof(address->sin6_addr.s6_addr);
				}
			}
			
		}
		//tlv type and lenght
		seq_tlv[0] = 0x00;
		seq_tlv[1] = 0x03;
		seq_tlv[2] = (len >> 8)	& 0xFF; 
		seq_tlv[3] = len 	& 0xFF;
		addtlv(seq_packet,seq_tlv,len);

		struct tlv_next_multicast next_mul;
		next_mul.type = htons(0x0005);
		next_mul.length = htons(8);
		next_mul.seq_num = htonl(seq_num);
		addtlv(seq_packet,&next_mul,8);

		if(send_seq_packet){		
			create_eigrp_header(seq_packet, seq_packet->buffer_len, seq_packet->opcode, proc->proccess_id, 0, 0, 0);
			send_ip4_packet(seq_packet,iff->socket4);
			proc->stats.packets_sent[seq_packet->opcode]++;
		}
		free(seq_tlv);
		free(seq_packet);

		if(send_seq_packet) flags |= FLAG_CR;
		create_eigrp_header(packet, packet->buffer_len, packet->opcode, proc->proccess_id, seq_num, 0, flags);
		queue_sended_multicast_packet(proc, packet,seq_num);
		packet->sin = sin;
		send_ip4_packet(packet,iff->socket4);
		//Record packets sent
		proc->stats.packets_sent[packet->opcode]++;
	}
}

int disable_ip4_loopback(int socket){
	char loopch = 0;
	if(setsockopt(socket, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch)) < 0){
		return -1;
	}
	return 0;
}

bool init_ip4(interface *iff){
	char host[NI_MAXHOST];
	int ret;
	iff->socket4 = socket(AF_INET, SOCK_RAW, EIGRP_PROT_NUM);
	if(iff->socket4 == -1){
		printf("ERROR:Could not create socket ip4 for interface %s.\n", iff->name);
		return false;
	}
	printf("Test Family:%d IF:%s\n",iff->ifa_addr_ip4.sin_family,iff->name);
	int result = getnameinfo((struct sockaddr*)&iff->ifa_addr_ip4, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL , 0 , NI_NUMERICHOST);
	if( result != 0){
		printf("ERROR:getnameinfo() failed: %s.\n",gai_strerror(result));
		return false;
	}
	struct ip_mreq group;
	group.imr_multiaddr.s_addr = inet_addr("224.0.0.10");
	group.imr_interface.s_addr = inet_addr(host);
	if(setsockopt(iff->socket4, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&group, sizeof(group)) < 0){
		printf("ERROR:Could not join multicast group at ip4 for interface %s\nErr:%s.\n", iff->name,strerror(errno));
		return false;
	}
	if(setsockopt(iff->socket4, SOL_SOCKET, SO_BINDTODEVICE, iff->name, sizeof(iff->name))){
		printf("ERROR:Could not bind socket to interface %s.\n", iff->name);
		close(iff->socket4);
		return false;
	}
		
	//----
	if(disable_ip4_loopback(iff->socket4) < 0){
		printf("ERROR:Could not set disable loopback to interface %s.\n", iff->name);
		close(iff->socket4);
		return false;
	}
	int mtu = get_socket_mtu(iff->socket4,AF_INET,iff->name);
	if(mtu < 0){
		printf("ERROR:Could not get interface %s MTU.\n", iff->name);
		close(iff->socket4);
		return false;
	}
	pthread_cancel(iff->packet_listener4);
	pthread_detach(iff->packet_listener4);
	iff->mtu = mtu;
	ret = pthread_create(&iff->packet_listener4,NULL ,listen_ip4 ,(void*)iff);
	if(ret){
		printf("ERROR:Error creating listen thread for interface %s at ip4.\n", iff->name);
		close(iff->socket4);
		return false;
	}

	return true;
}

void send_packets_neighbour_ip4(neighbour *n){
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

void *send_ipv4_packets( void *ptr){
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED,NULL);

	struct eigrp_proccess *proc;
	neighbour *n;
	//long long current_time;

	proc = (struct eigrp_proccess *)ptr;

	while(proc->running){

		if(linkedlist_isempty(&proc->multicast_queue)){
			//Send any pending packets from neighbour queue
			hash_collection col;
			prepare_hashcollection(&col,proc->neighbours);
			while( (n = next(&col)) != NULL){
				send_packets_neighbour_ip4(n);
			}

		}else{
			packetv4_param *packet = linkedlist_getfirst(&proc->multicast_queue);
			send_ip4_packet_multicast(packet, proc);
			free(packet);
		}

		sleep_millis(100);
		pthread_testcancel();
	}

	return NULL;
}

void *listen_ip4( void *ptr){
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED,NULL);

	interface *iff;

	iff = (interface *)ptr;

	//Interfaces get initialized first, hold until the proccesses are ready as well
	while(!is_ready()){
		sleep(1);
	}
	

	//Make a string with family name for printing
	printf("Starting packet listener thread AF_INET for interface %s.\n",iff->name);

	unsigned char buffer[PACKET_LEN];
	unsigned int cur_length = 0;
	unsigned int pak_length = 0;


	while(iff->running){
		int len;

		sleep_millis(10);
		pthread_testcancel();
		len = recv(iff->socket4, &buffer[cur_length], PACKET_LEN, MSG_DONTWAIT);

		if(len < 0)
			continue;
		
		cur_length += len;
		if(cur_length > 4){
			pak_length = buffer[3] | buffer[2] << 8;
		}else{
			continue;
		}

		//wait for the whole packet to be transmitted
		if(cur_length >= pak_length){
			packet p;
			memcpy(p.data,buffer,pak_length);
			p.length = pak_length;
			handle_packet_ipv4(&p,iff);
			//we have some data from the next packet
			if(cur_length > pak_length){
				memmove(buffer,buffer+pak_length,cur_length-pak_length);
				pak_length = 0;
				cur_length -= pak_length;
				continue;
			}

			pak_length = 0;
			cur_length = 0;
		}

		

	}

	//Leave the multicast group
	char host[NI_MAXHOST];
	int result = getnameinfo((struct sockaddr*)&iff->ifa_addr_ip4, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL , 0 , NI_NUMERICHOST);
	if( result != 0){
		printf("ERROR:getnameinfo() failed: %s.\n",gai_strerror(result));
		return false;
	}
	struct ip_mreq group;
	group.imr_multiaddr.s_addr = inet_addr("224.0.0.10");
	group.imr_interface.s_addr = inet_addr(host);
	if(setsockopt(iff->socket4, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*)&group, sizeof(group)) < 0){
		printf("ERROR:Could not drop multicast group at ip4 for interface %s.\n", iff->name);
	}

	close(iff->socket4);
	printf("Stoped packet listener thread AF_INET for interface %s.\n",iff->name);
	
	return NULL;
}

void *hello_packet_thread_ip4(void *ptr){
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	struct eigrp_proccess *proc;
	interface *iff;

	proc = (struct eigrp_proccess *)ptr;

	//Prepare the hello packet once so we don't have to make it over and over
	int i;

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
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
