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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>
#include <arpa/inet.h>

#include "eigrp_prot.h"
#include "linkedlist.h"
#include "eigrp_structs.h"
#include "eigrp_base.h"
#include "packet_factory.h"
#include "vector.h"
#include "utils.h"
#include "config.h"
#include "telnet.h"

void fill_packet(packet *p,char *buffer, int length){
	memcpy(p->data,buffer,length);
	p->length = length;
}

route *create_route(){
	route *new_route = malloc(sizeof(route));
	memset(new_route,0,sizeof(route));
	new_route->is_proccess_generated = false;
	new_route->index = -1;
	new_route->rijk = 0;
	new_route->to_be_removed = false;
	new_route->is_external = false;
	memset(&new_route->dest,0,sizeof(struct sockaddr_storage));

	return new_route;
}

void eigrp_hello(packet *p,interface *iff,struct eigrp_proccess *proc,vector *tlvs){
	struct iphdr *ip;
	ip = (struct iphdr*)p->data;

	//struct eigrphdr *eigrp;
	//eigrp = (struct eigrphdr*)(p->data + ip->ihl*4);

	neighbour *n;
	n = hashtable_getitem(proc->neighbours,ip->saddr);
	if(n == NULL){
		printf("New neighbour canditate\n");

		//printf("IP:%s\n",ip4_tochar(n->interface->ifa_addr_ip4->sin_addr.s_addr));
		
		struct tlv_parameter_type *param = NULL;
		struct tlv_version_type *version = NULL;
		
		//first extract the tlv_param
		char* cur_index = p->data;
		cur_index += ip->ihl*4+sizeof(struct eigrphdr);	
		while(cur_index < p->data + p->length){
			char *index = cur_index;
			cur_index += (cur_index[3] | cur_index[2] << 8);

			int type = index[1] | index[0] << 8;
			if(type == 0x0001)
				param = (struct tlv_parameter_type *)index;
			if(type == 0x0004)
				version = (struct tlv_version_type *)index;
		}

		
		if(param == NULL){
			printf("Missing parameter tlv ignoring hello packet.\n");
			return;
		}
		
		if(version == NULL){
			printf("Missing version tlv ignoring hello packet.\n");
			return;
		}
		
		//Let's make a big if to check the tlv_parameters
		if(proc->k1 == param->k1 && proc->k2 == param->k2 &&
			proc->k3 == param->k3 && proc->k4 == param->k4 &&
			proc->k5 == param->k5 )
		{
			//Initialize new neighbour
			printf("All parameters matching.\n");
			neighbour *n = malloc(sizeof(neighbour));
			memset(&n->address,0,sizeof(struct sockaddr_storage));
			((struct sockaddr_in*)&n->address)->sin_addr.s_addr = ip->saddr;
			((struct sockaddr_in*)&n->address)->sin_family = AF_INET;
			n->interface = iff;
			vector_init(&n->routes);
			n->proc = proc;
			n->last_response = current_timestamp();
			n->holdtime = htons(param->holdtime)*1000;
			n->eigrp_version = htons(version->eigrp_version);
			n->eigrp_version = htons(version->eigrp_version);
			n->pending_ack = -1; 
			n->last_ack_sent = 0;
			n->last_packet_sent = 0;
			n->is_active = true;
			n->send_next_packet = true; //Don't wait for the first packet
			n->state = PENDING_STATE;
			n->eot = false;
			n->cr = false;
			n->discovery_time = current_timestamp();
			n->srtt = 0;
			n->init_seq = -1;

			struct sockaddr_in sin;
			sin.sin_family = AF_INET;
			sin.sin_port = 0;
			sin.sin_addr.s_addr = ip->saddr;

			n->sin = sin;
	
			linkedlist_init(&n->packet_queue);

			linkedlist_init(&n->update_tlv_queue);
			linkedlist_init(&n->query_tlv_queue);
			linkedlist_init(&n->reply_tlv_queue);

			n->reply_flag = 0;
			n->query_flag = 0;
			n->update_flag = 0;

			hashtable_additem(proc->neighbours,n,ip->saddr);

			//Create the update init packet

			//The packet is gonna be empty since the header is created at the end and we have no tlvs
			packetv4_param *packet = create_empty_packet(OPCODE_UPDATE,FLAG_INIT,n->sin);

			//Add it to the list so it get send orderly
			linkedlist_addtail(&n->packet_queue,packet);

			dual_nbrchange(proc, n, true, "new adjacency");
			telnet_new_peer(n);
		}
		
		
	}else{
		bool cr= false;
		int packet_seq=0;	
		char* cur_index = p->data;
		cur_index += ip->ihl*4+sizeof(struct eigrphdr);	
		while(cur_index < p->data + p->length){
			char *index = cur_index;
			cur_index += (cur_index[3] | cur_index[2] << 8);

			int type = index[1] | index[0] << 8;
			int len = index[3] | index[2] << 8;
			int pos = 4;
			if(type == 0x0003){
				while(pos < len){
					//if it's not 4 it refers to an other protocol (not ip4)
					if(index[pos] == 4){
						pos++;

						__u32 address;
						memcpy(&address, &index[pos], 4);
						pos +=4;

						if( address == n->interface->ifa_addr_ip4.sin_addr.s_addr){
							cr = true;
							break;
						}
					}else{
						pos += index[pos] + 1;
					}
				}

			}
			if(type == 0x0005){
				struct tlv_next_multicast *next_mul = NULL;
				next_mul = (struct tlv_next_multicast *)index;
				packet_seq = htonl(next_mul->seq_num);
				int i=0;i++;
			}
		}

		if(cr && packet_seq != 0){
			n->cr = true;
			n->cr_num = packet_seq;
		}

	}
}

struct in_addr get_destination_address(__u8 *offset, int prefix){
	int byte_len = ((prefix -1)/8)+1;
	
	struct in_addr addr;
	unsigned char *bytes = (unsigned char *) &addr;
	int i,k;
	for(i=0;i<4;i++){
		bytes[i] = 0;
	}
	k=byte_len-1;
	for(i=byte_len;i>0;i--){
		bytes[k--] = offset[i-1];
	}

	return addr;
}

unsigned long get_mtu(unsigned char *offset){
	return  (offset[0] << 16) | (offset[1] << 8) | (offset[2] & 0xFF);
}

void store_data_in_route_internal(route *new_route,tlv_ip4_internal *tlv_route,neighbour *n){
	new_route->sender = n;
	new_route->prefix = tlv_route->prefix;
	//Destination address is varriable
	struct in_addr ip_addr = get_destination_address(&tlv_route->pnt_var_addr1,tlv_route->prefix);
	((struct sockaddr_in*)&new_route->dest)->sin_addr = ip_addr;
	((struct sockaddr_in*)&new_route->dest)->sin_family = AF_INET;
	//Metrics
	new_route->mtu = get_mtu(&tlv_route->mtu_1);
	new_route->reliability = tlv_route->reliability;
	new_route->delay = classic_unscale_delay(htonl(tlv_route->scaled_delay));
	new_route->bandwidth = classic_unscale_bandwidth(htonl(tlv_route->scaled_bw));
	new_route->load = tlv_route->load;
	new_route->hop = tlv_route->hop_count;
	new_route->route_tag = tlv_route->route_tag;
}

void external_tlv(char *index, neighbour *n, int opcode){
	//Get the tlv
	tlv_ip4_external *tlv_route = (tlv_ip4_external *)index;
	//Create a route records and fill it.
	route *new_route = create_route();
	new_route->is_external = true;
	store_data_in_route_external(new_route,tlv_route,n);
	//Calculate reported_distance
	calculate_classic_route_metric(new_route->sender->proc,new_route);

	handle_route_changes(new_route,opcode,new_route->sender->proc);
	if(new_route->to_be_removed)
		free(new_route);	
}

void internal_tlv(char *index, neighbour *n, int opcode){
	//Get the tlv
	tlv_ip4_internal *tlv_route = (tlv_ip4_internal *)index;
	//Create a route records and fill it.
	route *new_route = create_route();
	new_route->is_external = false;
	store_data_in_route_internal(new_route,tlv_route,n);
	//Calculate reported_distance
	calculate_classic_route_metric(new_route->sender->proc,new_route);
	
	handle_route_changes(new_route,opcode,new_route->sender->proc);
	if(new_route->to_be_removed)
		free(new_route);
}

void store_data_in_route_external(route *new_route,tlv_ip4_external *tlv_route,neighbour *n){
	new_route->sender = n;
	new_route->prefix = tlv_route->prefix;
	//Destination address is varriable
	struct in_addr ip_addr = get_destination_address(&tlv_route->pnt_var_addr1,tlv_route->prefix);
	((struct sockaddr_in*)&new_route->dest)->sin_addr = ip_addr;
	((struct sockaddr_in*)&new_route->dest)->sin_family = AF_INET;
	//Metrics
	new_route->mtu = get_mtu(&tlv_route->mtu_1);
	new_route->reliability = tlv_route->reliability;
	new_route->delay = classic_unscale_delay(htonl(tlv_route->scaled_delay));
	new_route->bandwidth = classic_unscale_bandwidth(htonl(tlv_route->scaled_bw));
	new_route->load = tlv_route->load;
	new_route->hop = tlv_route->hop_count;
	new_route->route_tag = tlv_route->route_tag;

	new_route->orig_router_id = htonl(tlv_route->origin_router);
	new_route->orig_as_number = htonl(tlv_route->origin_as);
	new_route->admin_tag = htonl(tlv_route->admin_tag);
	new_route->external_metric = htonl(tlv_route->external_metric);
	new_route->external_prot = tlv_route->external_protocol;
	new_route->external_flags = tlv_route->external_flags;
}

void eigrp_query(packet *p,interface *iff,struct eigrp_proccess *proc,vector *tlvs){
	struct iphdr *ip;
	ip = (struct iphdr*)p->data;

	//struct eigrphdr *eigrp;
	//eigrp = (struct eigrphdr*)(p->data + ip->ihl*4);


	neighbour *n;
	n = hashtable_getitem(proc->neighbours,ip->saddr);
	if(n == NULL)return;

	char* cur_index = p->data;
	cur_index += ip->ihl*4+sizeof(struct eigrphdr);	
	while(cur_index < p->data + p->length){

		char *index = cur_index;
		cur_index += (cur_index[3] | cur_index[2] << 8);

		int type = index[1] | index[0] << 8;
		if(type == 0x0102){
			internal_tlv(index,n,OPCODE_QUERY);
		}
		if(type == 0x0103){
			external_tlv(index,n,OPCODE_QUERY);
		}

	}
}

void eigrp_reply(packet *p,interface *iff,struct eigrp_proccess *proc,vector *tlvs){
	struct iphdr *ip;
	ip = (struct iphdr*)p->data;

	//struct eigrphdr *eigrp;
	//eigrp = (struct eigrphdr*)(p->data + ip->ihl*4);


	neighbour *n;
	n = hashtable_getitem(proc->neighbours,ip->saddr);
	if(n == NULL)return;

	//Send the ack packet before we start processing the packet
	n->send_next_packet = true;

	char* cur_index = p->data;
	cur_index += ip->ihl*4+sizeof(struct eigrphdr);	
	while(cur_index < p->data + p->length){
		char *index = cur_index;
		cur_index += (cur_index[3] | cur_index[2] << 8);

		int type = index[1] | index[0] << 8;
		if(type == 0x0102){
			internal_tlv(index,n,OPCODE_REPLY);	
		}
		if(type == 0x0103){
			external_tlv(index,n,OPCODE_REPLY);
		}

	}
}

void eigrp_update(packet *p,interface *iff,struct eigrp_proccess *proc,vector *tlvs){
	struct iphdr *ip;
	ip = (struct iphdr*)p->data;

	struct eigrphdr *eigrp;
	eigrp = (struct eigrphdr*)(p->data + ip->ihl*4);

	neighbour *n;
	n = hashtable_getitem(proc->neighbours,ip->saddr);
	if(n == NULL)return;

	char* cur_index = p->data;
	cur_index += ip->ihl*4+sizeof(struct eigrphdr);

	while(cur_index < p->data + p->length){
		char *index = cur_index;
		cur_index += (cur_index[3] | cur_index[2] << 8);

		int type = index[1] | index[0] << 8;
		if(type == 0x0102){
			internal_tlv(index,n,OPCODE_UPDATE);	
		}
		if(type == 0x0103){
			external_tlv(index,n,OPCODE_UPDATE);
		}
	}

	if(flags_are_set(htonl(eigrp->flags), FLAG_ENDOFTABLE)){
		n->eot = true;
		//if(all_end_of_table_received(n->proc))
			//init_calculate_routes(n->proc);
	}
}

void eigrp_siaquery(packet *p,interface *iff,struct eigrp_proccess *proc,vector *tlvs){
	struct iphdr *ip;
	ip = (struct iphdr*)p->data;

	//struct eigrphdr *eigrp;
	//eigrp = (struct eigrphdr*)(p->data + ip->ihl*4);

	neighbour *n;
	n = hashtable_getitem(proc->neighbours,ip->saddr);
	if(n == NULL)return;

	//Send ack before processing the packet
	n->send_next_packet = true;

	packetv4_param *packet = create_empty_packet(OPCODE_SIAREPLY, 0, n->sin);

	//Sia-query is a per-destination packet but we process it like it was a normal packet
	char* cur_index = p->data;
	cur_index += ip->ihl*4+sizeof(struct eigrphdr);	
	while(cur_index < p->data + p->length){
		char *index = cur_index;
		cur_index += (cur_index[3] | cur_index[2] << 8);

		int type = index[1] | index[0] << 8;
		if(type == 0x0102){
			//Get the tlv
			tlv_ip4_internal *tlv_route = (tlv_ip4_internal *)index;
			route *new_route = create_route();
			new_route->is_external = false;
			store_data_in_route_internal(new_route,tlv_route,n);

			tlv_ip4_internal *route_tlv;

			if(!topology_route_exists(proc,&new_route->dest,new_route->prefix)){
				route *r = unreachable_route(new_route->dest,new_route->prefix,n,false);
				route_tlv = create_internal_route_tlv(r,0);
				free(r);
			}else{
				struct topology_route *tr = get_topology_network(proc, new_route->dest, new_route->prefix);
				int route_flag = 0;
				if(tr->route_state == ACTIVE_STATE) route_flag |= FLAG_ROUTEACTIVE;

				if(tr->successor == NULL){
					route *r = unreachable_route(tr->dest,tr->prefix,n,false);
					route_tlv = create_internal_route_tlv(r,route_flag);
					free(r);
				}else
					route_tlv = create_internal_route_tlv(tr->successor,route_flag);
							
			}

			//tlv assumes destination is 4 byte so we subtract it and add the correct
			int byte_len = ((new_route->prefix -1)/8)+1;
			addtlv(packet, route_tlv,sizeof(tlv_ip4_internal)-4+byte_len-3); //-3 is struct?
			
		}
		if(type == 0x0103){
			tlv_ip4_external *tlv_route = (tlv_ip4_external *)index;
			route *new_route = create_route();
			new_route->is_external = true;
			store_data_in_route_external(new_route,tlv_route,n);

			tlv_ip4_external *route_tlv;

			if(!topology_route_exists(proc,&new_route->dest,new_route->prefix)){
				route *r = unreachable_route(new_route->dest,new_route->prefix,n,true);
				route_tlv = create_external_route_tlv(r,0);
				free(r);
			}else{
				struct topology_route *tr = get_topology_network(proc, new_route->dest, new_route->prefix);
				int route_flag = 0;
				if(tr->route_state == ACTIVE_STATE) route_flag |= FLAG_ROUTEACTIVE;

				if(tr->successor == NULL){
					route *r = unreachable_route(tr->dest,tr->prefix,n,true);
					route_tlv = create_external_route_tlv(r,route_flag);
					free(r);
				}else
					route_tlv = create_external_route_tlv(tr->successor,route_flag);
							
			}

			//tlv assumes destination is 4 byte so we subtract it and add the correct
			int byte_len = ((new_route->prefix -1)/8)+1;
			addtlv(packet, route_tlv,sizeof(tlv_ip4_external)-4+byte_len-3); //-3 is struct?
		}
	}

	//Add it to the list so it get send orderly
	linkedlist_addtail(&n->packet_queue,packet);



}

void eigrp_siareply(packet *p,interface *iff,struct eigrp_proccess *proc,vector *tlvs){
	struct iphdr *ip;
	ip = (struct iphdr*)p->data;

	//struct eigrphdr *eigrp;
	//eigrp = (struct eigrphdr*)(p->data + ip->ihl*4);

	neighbour *n;
	n = hashtable_getitem(proc->neighbours,ip->saddr);
	if(n == NULL)return;

	//Sia-query is a per-destination packet but we process it like it was a normal packet
	char* cur_index = p->data;
	cur_index += ip->ihl*4+sizeof(struct eigrphdr);	
	while(cur_index < p->data + p->length){
		char *index = cur_index;
		cur_index += (cur_index[3] | cur_index[2] << 8);

		int type = index[1] | index[0] << 8;
		if(type == 0x0102){
			//Get the tlv
			tlv_ip4_internal *tlv_route = (tlv_ip4_internal *)index;
			route *new_route = create_route();
			new_route->is_external = false;
			store_data_in_route_internal(new_route,tlv_route,n);

			route *r  = get_route(new_route, n);
			r->sia_query_received = true;

			if(!flags_are_set(tlv_route->flags, FLAG_ROUTEACTIVE)){
				store_data_in_route_internal(new_route,tlv_route,n);
				//Calculate reported_distance
				calculate_classic_route_metric(new_route->sender->proc,new_route);
			}
			
		}
		if(type == 0x0103){
			tlv_ip4_external *tlv_route = (tlv_ip4_external *)index;
			route *new_route = create_route();
			new_route->is_external = true;
			store_data_in_route_external(new_route,tlv_route,n);

			route *r  = get_route(new_route, n);
			r->sia_query_received = true;

			if(!flags_are_set(tlv_route->flags, FLAG_ROUTEACTIVE)){
				store_data_in_route_external(new_route,tlv_route,n);
				//Calculate reported_distance
				calculate_classic_route_metric(new_route->sender->proc,new_route);
			}
		}
	}

}

void handle_packet_ipv4(packet *p,interface *iff){

	//Packet p is freed at the end of the faction
	//DO NOT free it a subfunction

	struct iphdr *ip;
	ip = (struct iphdr*)p->data;

	struct eigrphdr *eigrp;
	eigrp = (struct eigrphdr*)(p->data + ip->ihl*4);

	//First we see if the checksum is wrong to discard it
	int sum = checksum((char *)eigrp,p->length - ip->ihl*4);
	if(sum != 0){
		printf("Wrong checksum found %#4x \n", sum);
	}

	int id = htons(eigrp->autonomous_sys_number);
	struct eigrp_proccess *proc = get_eigrp_proccess(id,AF_INET);
	if(proc == NULL || !proc->running) return;

	//See if the packet is coming from an existing neighbour
	neighbour *n = hashtable_getitem(proc->neighbours,ip->saddr);

	printf("Received Packet for proccess %d of type %s, seq %d.\n",proc->proccess_id,to_string(eigrp->opcode),htonl(eigrp->seqnum));

	if(flags_are_set(htonl(eigrp->flags), FLAG_INIT)){
		printf("INIT FLAG DETECED\n");
		if(n != NULL && n->eot){
			printf("KILLING NEIGHBOR-----------------------\n");
			free_neighbour(n,"peer restarted");
		}
	}

	if(n == NULL){
		printf("Neighbour not found\n");
		//If a neighbour is not found but is a hello packet it will pass for proccessing
		if(eigrp->opcode != OPCODE_HELLO){
			//Is not inited yet as a neighbour and is sending non hello packets
			//drop it
			return;
		}
	}else{

		if(!n->is_active){
			printf("Inactive Neighour is talking again.\n");
			//Reinitialize him again
		}

		if(n->eot == false && !(flags_are_set(htonl(eigrp->flags), FLAG_ENDOFTABLE) || flags_are_set(htonl(eigrp->flags), FLAG_INIT))){
			return; //drop packet - sending non-init packets durining init
		}

		printf("Dt: %lld\n",current_timestamp()-n->last_response);
		n->last_response = current_timestamp();
		//Drop packet if it cointain cr flag and we don't have cr flag enabled
		if(flags_are_set(htonl(eigrp->flags), FLAG_CR)){
			if(n->cr && n->cr_num == htonl(eigrp->seqnum)){
				printf("CR flag setted, droping packet.\n");
				n->cr = false;
				return;
			}
		}

		int seqnum = htonl(eigrp->seqnum);
		if(seqnum != 0){

			if(seqnum <= n->pending_ack){
				//Duplicate packet send the last packet/ACK again and drop this one
				n->send_next_packet = true;
				return;
			} 

			if(eigrp->opcode == OPCODE_HELLO){
				printf("Skipping seq number this should contain a seq_tlv\n.");
			}else{
				n->pending_ack = seqnum;
			}
		}
		//If the packet sends the ack for the first packet in queued list remove it
		//so that the next could be send

		if(n->state == PENDING_STATE)
			if(n->init_seq == htonl(eigrp->acknum)){
				n->state = UP_STATE;

				packetv4_param *packet = create_empty_packet(OPCODE_UPDATE, FLAG_ENDOFTABLE, n->sin);

				int i;
				for(i=0;i<n->proc->connected_routes.size;i++){
					route *r = vector_get(&n->proc->connected_routes,i);
					if(r->index == n->interface->index)continue;
					//tlv assumes destination is 4 byte so we subtract it and add the correct
					if(r->is_external){
						tlv_ip4_external *route_tlv = create_external_route_tlv(r,0);
						int byte_len = ((r->prefix -1)/8)+1;
						addtlv(packet, route_tlv,sizeof(tlv_ip4_external)-4+byte_len-3); //-3 is struct?
						free(route_tlv);
					}else{
						tlv_ip4_internal *route_tlv = create_internal_route_tlv(r,0);
						int byte_len = ((r->prefix -1)/8)+1;
						addtlv(packet, route_tlv,sizeof(tlv_ip4_internal)-4+byte_len-3); //-3 is struct?
						free(route_tlv);
					}
				}

				//Add it to the list so it get send orderly
				linkedlist_addtail(&n->packet_queue,packet);
				
			}
			

		if(!linkedlist_isempty(&n->packet_queue)){
			packetv4_param *first = linkedlist_peekfirst(&n->packet_queue);
			if(htonl(eigrp->acknum) == first->seq_num && first->seq_num != 0){
				n->srtt = current_timestamp() - n->last_packet_sent;
				packetv4_param *sendedpacket = linkedlist_getfirst(&n->packet_queue);
				free(sendedpacket);
			}
		}

		//We removed the previous packet so now we can send the next one
		n->send_next_packet = true;
	}

	proc->stats.packets_received[eigrp->opcode]++;
	if(eigrp->acknum != 0)proc->stats.acks_received++;
	
	switch(eigrp->opcode){
		case 1: //update
			eigrp_update(p,iff,proc,NULL);
			break;
		case 2: //request
		break;
		case 3: //query
			eigrp_query(p,iff,proc,NULL);
			break;
		case 4: //reply
			eigrp_reply(p,iff,proc,NULL);
			break;
		break;
		case 5: //hello
			eigrp_hello(p,iff,proc,NULL);
			break;
		case 6: //reserved
		break;
		case 7:	//probe
		break; 
		case 8: //reserved
		break;
		case 9: //reserved
		break;
		case 10: //siaquery
			eigrp_siaquery(p,iff,proc,NULL);
			break;
		case 11: //siareply
			eigrp_siareply(p,iff,proc,NULL);
			break;
	}

	create_packets_from_queues(proc);

	//vector_free(&tlvs);
}

void handle_packet_ipv6(packet *p){

}
