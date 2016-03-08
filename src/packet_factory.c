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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
//#include <netinet.h>
#include <arpa/inet.h>


#include "config.h"
#include "utils.h"
#include "eigrp_structs.h"
#include "packet_factory.h"
#include "collection.h"

unsigned long classic_unscale_bandwidth(unsigned long scaled_bw){
	if(scaled_bw == 0)return 0;
	return (unsigned long)(((double)EIGRP_BANDWIDTH / (double)scaled_bw) * (double)EIGRP_CLASSIC_SCALE);
}

unsigned long long classic_unscale_delay(unsigned long long scaled_microseconds){
	if(scaled_microseconds == EIGRP_UNREACHABLE)return EIGRP_UNREACHABLE;
	return scaled_microseconds * 10 / (EIGRP_CLASSIC_SCALE ) ;
}

unsigned long classic_scale_bandwidth(unsigned long bw){
	if(bw == 0)return 0;
	return (unsigned long)EIGRP_CLASSIC_SCALE * EIGRP_BANDWIDTH / bw;
}

unsigned long long classic_scale_delay(unsigned long long microseconds){
	if(microseconds == EIGRP_UNREACHABLE)return EIGRP_UNREACHABLE;
	return (unsigned long)EIGRP_CLASSIC_SCALE  * microseconds / 10;
}

int fill_sequence_tlv(char *buffer, struct eigrp_proccess *proc){
	int len = 4;
	neighbour *n;

	hash_collection col;
	prepare_hashcollection(&col,proc->neighbours);
	while( (n = next(&col)) != NULL){
		if(!linkedlist_isempty(&n->packet_queue)){
			
			if(n->address.ss_family == AF_INET)
			{
				struct sockaddr_in *address = (struct sockaddr_in *)&n->address;
				buffer[len++] = sizeof(address->sin_addr.s_addr);
				memcpy(&buffer[len],&address->sin_addr.s_addr,sizeof(address->sin_addr.s_addr));
				len += sizeof(address->sin_addr.s_addr);
			}else{
				struct sockaddr_in6 *address = (struct sockaddr_in6 *)&n->address;
				buffer[len++] = sizeof(address->sin6_addr.s6_addr);
				memcpy(&buffer[len],address->sin6_addr.s6_addr,sizeof(address->sin6_addr.s6_addr));
				len += sizeof(address->sin6_addr.s6_addr);
			}
		}
	}
	


	//tlv type and lenght
	buffer[0] = 0x00;
	buffer[1] = 0x03;
	buffer[2] = (len >> 8)	& 0xFF; 
	buffer[3] = len 	& 0xFF;
	
	return len;
}

tlv_ip4_internal *create_internal_route_tlv(route *r, int flags){

	int byte_len = ((r->prefix -1)/8)+1;
	tlv_ip4_internal *tlv = malloc(sizeof(tlv_ip4_internal));
	memset(tlv,0,sizeof(tlv_ip4_internal));
	tlv->type = htons(0x0102);
	tlv->length = htons(25 + byte_len);
	tlv->nexthop = htonl(0x00000000);
	
	unsigned long long delay = 0;
	
	if(r->delay == EIGRP_UNREACHABLE || r->sender->interface->delay == EIGRP_UNREACHABLE)
		delay = EIGRP_UNREACHABLE;
	else{
		delay = (r->is_proccess_generated ? r->sender->interface->delay : r->sender->interface->delay + r->delay);
	}
	
	unsigned long bandwidth = MIN(r->bandwidth,r->sender->interface->bandwidth);
	
	tlv->scaled_delay = htonl(classic_scale_delay(delay));
	tlv->scaled_bw = htonl(classic_scale_bandwidth(bandwidth));

	tlv->mtu_3 = r->sender->interface->mtu & 0xFF;
	tlv->mtu_2 = (r->sender->interface->mtu >> 8) & 0xFF;
	tlv->mtu_1 = (r->sender->interface->mtu >> 16) & 0xFF;

	tlv->hop_count = (r->is_proccess_generated ? 0 : r->hop);
	tlv->reliability = r->reliability;
	tlv->load = r->load;
	tlv->route_tag = r->route_tag;
	tlv->flags = flags;
	tlv->prefix = r->prefix;
	unsigned long address = ((struct sockaddr_in*)&r->dest)->sin_addr.s_addr;
	if(byte_len>=1)tlv->pnt_var_addr1= address & 0xFF;
	if(byte_len>=2)tlv->pnt_var_addr2= (address >>8) & 0xFF;
	if(byte_len>=3)tlv->pnt_var_addr3= (address >>16) & 0xFF;
	if(byte_len>=4)tlv->pnt_var_addr4= (address >>24) & 0xFF;
	
	return tlv;
}

tlv_ip4_external *create_external_route_tlv(route *r, int flags){

	int byte_len = ((r->prefix -1)/8)+1;
	tlv_ip4_external *tlv = malloc(sizeof(tlv_ip4_external));
	memset(tlv,0,sizeof(tlv_ip4_external));
	tlv->type = htons(0x0103);
	tlv->length = htons(45 + byte_len);
	tlv->nexthop = htonl(0x00000000);
	
	unsigned long long delay = 0;
	if(r->delay == EIGRP_UNREACHABLE || r->sender->interface->delay == EIGRP_UNREACHABLE)
		delay = EIGRP_UNREACHABLE;
	else{
		delay = (r->is_proccess_generated ? r->sender->interface->delay : r->sender->interface->delay + r->delay);
	}
	
	unsigned long bandwidth = MIN(r->bandwidth,r->sender->interface->bandwidth);
	
	tlv->scaled_delay = htonl(classic_scale_delay(delay));
	tlv->scaled_bw = htonl(classic_scale_bandwidth(bandwidth));

	tlv->mtu_3 = r->sender->interface->mtu & 0xFF;
	tlv->mtu_2 = (r->sender->interface->mtu >> 8) & 0xFF;
	tlv->mtu_1 = (r->sender->interface->mtu >> 16) & 0xFF;

	tlv->hop_count = (r->is_proccess_generated ? 0 : r->hop);
	tlv->reliability = r->reliability;
	tlv->load = r->load;
	tlv->route_tag = r->route_tag;
	tlv->flags = flags;
	tlv->prefix = r->prefix;
	unsigned long address = ((struct sockaddr_in*)&r->dest)->sin_addr.s_addr;
	if(byte_len>=1)tlv->pnt_var_addr1= address & 0xFF;
	if(byte_len>=2)tlv->pnt_var_addr2= (address >>8) & 0xFF;
	if(byte_len>=3)tlv->pnt_var_addr3= (address >>16) & 0xFF;
	if(byte_len>=4)tlv->pnt_var_addr4= (address >>24) & 0xFF;

	tlv->origin_router = htonl(r->orig_router_id);
	tlv->origin_as = htonl(r->orig_as_number);
	tlv->admin_tag = htonl(r->admin_tag);
	tlv->external_metric = htonl(r->external_metric);
	tlv->external_protocol = r->external_prot;
	tlv->external_flags = r->external_flags;
	
	return tlv;
}

void addtlv(packetv4_param *packet, void* tlv,int len){
	if(packet->buffer_len + len > PACKET_LENGTH)
		return;
	memcpy(&packet->buffer[packet->buffer_len],tlv,len);	
	packet->buffer_len += len;
}

void auto_packet_split(neighbour *n,linkedlist *tlvs,int opcode,int flags){
	int mtu = n->interface->mtu;
	mtu *= 0.8;

	if(mtu < LEAST_MTU)
		mtu = LEAST_MTU;
	
	while(!linkedlist_isempty(tlvs)){
		packetv4_param *packet = create_empty_packet(opcode,flags, n->sin);

		while(!linkedlist_isempty(tlvs)){
			char *index = linkedlist_getfirst(tlvs);
			int type = index[1] | index[0] << 8;
			if(type == 0x0102){
				if(packet->buffer_len + sizeof(tlv_ip4_internal) > mtu) break;
				tlv_ip4_internal *param = (tlv_ip4_internal *)index;
				int byte_len = ((param->prefix -1)/8)+1;
				//tlv assumes destination is 1 byte so we subtract it and add the correct
				addtlv(packet,param,sizeof(tlv_ip4_internal)-4+byte_len-3); //-3 is struct?
				free(index);
			}
			if(type == 0x0103){
				if(packet->buffer_len + sizeof(tlv_ip4_external) > mtu) break;
				tlv_ip4_external *param = (tlv_ip4_external *)index;
				int byte_len = ((param->prefix -1)/8)+1;
				//tlv assumes destination is 1 byte so we subtract it and add the correct
				addtlv(packet,param,sizeof(tlv_ip4_external)-4+byte_len-3); //-3 is struct?
				free(index);
			}
		}

		linkedlist_addtail(&n->packet_queue,packet);
	}
}

packetv4_param *create_empty_packet(int opcode,int flags, struct sockaddr_in sin){
	//The packet is gonna be empty since the header is created at the end and we have no tlvs
	packetv4_param *packet = malloc(sizeof(packetv4_param));

	packet->buffer_len = sizeof(struct eigrphdr);
	packet->flags = flags;
	packet->sin = sin;
	packet->opcode = opcode;
	packet->seq_num = 0;

	return packet;
}

void create_eigrp_header(packetv4_param *packet, int packet_len, int opcode, int auto_sys_number, int seqnum, int acknum, int flags){
	struct eigrphdr *eigrphd = (struct eigrphdr*)packet->buffer;
	eigrphd->version = VERSION;
	eigrphd->opcode = opcode;
	eigrphd->checksum = 0;
	eigrphd->flags = htonl(flags);
	eigrphd->seqnum = htonl(seqnum);
	eigrphd->acknum = htonl(acknum);
	eigrphd->router_id = 0;
	eigrphd->autonomous_sys_number = htons(auto_sys_number);

	//Now that the packet is filled we should override the checksum
	eigrphd->checksum =  htons(checksum(packet->buffer,packet_len));
}

void create_hello_packet(packetv4_param *packet, struct eigrp_proccess *proc){
		
	struct tlv_parameter_type param_type;
	param_type.type = htons(0x0001);
	param_type.length = htons(0x000C);
	param_type.k1 = proc->k1;
	param_type.k2 = proc->k2;
	param_type.k3 = proc->k3;
	param_type.k4 = proc->k4;
	param_type.k5 = proc->k5;	
	param_type.k6 = proc->k6;
	param_type.holdtime = htons(proc->holdtime);

	addtlv(packet,&param_type,sizeof(struct tlv_parameter_type)); //-3 is struct?
	
	struct tlv_version_type version_type;
	version_type.type = htons(0x0004);
	version_type.length = htons(0x0008);
	version_type.os_version = htons(OS_VERSION);
	version_type.eigrp_version = htons(EIGRP_VERSION);

	addtlv(packet,&version_type,sizeof(struct tlv_version_type)); //-3 is struct?

	int packet_len = sizeof(struct eigrphdr) + sizeof(struct tlv_parameter_type) + sizeof(struct tlv_version_type);
	create_eigrp_header(packet, packet_len, OPCODE_HELLO, proc->proccess_id, 0 , 0, 0);

}

//At the function below the route structure has the values from the tlv received which means that when passing them further
//we have to find the values that will be passed based on the interface the route was found (not the one we will be sending
//the packet). E.x. acc_delay,min_bw, etc. If we DONT do it we will be adevertizing the route as our eigrp DOESN'T exists

void queue_sended_multicast_packet(struct eigrp_proccess *proc, packetv4_param *packet, int seq_num){
	neighbour *n;

	printf("Queueing Multicast Packet to neighbours\n");

	hash_collection col;
	prepare_hashcollection(&col,proc->neighbours);
	while( (n = next(&col)) != NULL){

		if(n->is_active == false){
			printf("Inactive Neighbour skipping\n");
			continue;
		}

		packetv4_param *new_packet = create_empty_packet(packet->opcode, packet->flags , n->sin);
		memcpy(new_packet->buffer,packet->buffer,packet->buffer_len);
		new_packet->buffer_len = packet->buffer_len;
		new_packet->seq_num = seq_num;

		linkedlist_addtail(&n->packet_queue,new_packet);
	}
}

void add_query_tlv_multicast(struct eigrp_proccess *proc, route *r, int flags){
	printf("Adding query tvl to multicast queue.\n");
	if(r->is_external){
		tlv_ip4_external *tvl = create_external_route_tlv(r, flags);
		linkedlist_addtail(&proc->query_tlv_queue,tvl);
	}else{
		tlv_ip4_internal *tvl = create_internal_route_tlv(r, flags);
		linkedlist_addtail(&proc->query_tlv_queue,tvl);
	}
	if(r->to_be_removed)free(r);
}

void add_update_tlv_multicast(struct eigrp_proccess *proc, route *r, int flags){
	printf("Adding update tvl to multicast queue.\n");
	if(r->is_external){
		tlv_ip4_external *tvl = create_external_route_tlv(r, flags);
		linkedlist_addtail(&proc->update_tlv_queue,tvl);
	}else{
		tlv_ip4_internal *tvl = create_internal_route_tlv(r, flags);
		linkedlist_addtail(&proc->update_tlv_queue,tvl);
	}
	if(r->to_be_removed)free(r);
}

void add_reply_tlv_neighbour(neighbour *n,route *r, int flags){
	printf("Adding reply n\n");
	if(r->is_external){
		tlv_ip4_external *tvl = create_external_route_tlv(r, flags);
		linkedlist_addtail(&n->reply_tlv_queue,tvl);
	}else{
		tlv_ip4_internal *tvl = create_internal_route_tlv(r, flags);
		linkedlist_addtail(&n->reply_tlv_queue,tvl);
	}
	if(r->to_be_removed)free(r);
}

void add_query_tlv_neighbour(neighbour *n,route *r, int flags){
	printf("Adding query n\n");
	if(r->is_external){
		tlv_ip4_external *tvl = create_external_route_tlv(r, flags);
		linkedlist_addtail(&n->query_tlv_queue,tvl);
	}else{
		tlv_ip4_internal *tvl = create_internal_route_tlv(r, flags);
		linkedlist_addtail(&n->query_tlv_queue,tvl);
	}
	if(r->to_be_removed)free(r);
}

void send_siaquery_neighbour(neighbour *n,route *r, int packet_flag, int route_flag){
	printf("Sending siaquery.\n");
	packetv4_param *packet = create_empty_packet(OPCODE_SIAQUERY,packet_flag, n->sin);
	
	if(r->is_external){
		tlv_ip4_external *tlv = create_external_route_tlv(r, route_flag);
		int byte_len = ((tlv->prefix -1)/8)+1;
		addtlv(packet,tlv,sizeof(tlv_ip4_external)-4+byte_len-3);
		linkedlist_addtail(&n->packet_queue,packet);
	}else{
		tlv_ip4_internal *tlv = create_internal_route_tlv(r, route_flag);
		int byte_len = ((tlv->prefix -1)/8)+1;
		addtlv(packet,tlv,sizeof(tlv_ip4_internal)-4+byte_len-3);
		linkedlist_addtail(&n->packet_queue,packet);
	}
	if(r->to_be_removed)free(r);
	printf("Siaquery added to packet queue.\n");
}

void send_siareply_neighbour(neighbour *n,route *r, int packet_flag, int route_flag){
	printf("ERROR:Not Implemented\n");
}

void create_mutlticast_packet(struct eigrp_proccess *proc,linkedlist *tlvs,int opcode,int flags){
	if(linkedlist_isempty(tlvs))return;
	
	struct sockaddr_in sin;
	
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("224.0.0.10");

	packetv4_param *packet = create_empty_packet(opcode,flags, sin);

	while(!linkedlist_isempty(tlvs)){
		char *index = linkedlist_getfirst(tlvs);
		int type = index[1] | index[0] << 8;
		if(type == 0x0102){
			tlv_ip4_internal *param = (tlv_ip4_internal *)index;
			int byte_len = ((param->prefix -1)/8)+1;
			//tlv assumes destination is 1 byte so we subtract it and add the correct
			addtlv(packet,param,sizeof(tlv_ip4_internal)-4+byte_len-3); //-3 is struct?
		}
		if(type == 0x0103){
			tlv_ip4_external *param = (tlv_ip4_external *)index;
			int byte_len = ((param->prefix -1)/8)+1;
			//tlv assumes destination is 1 byte so we subtract it and add the correct
			addtlv(packet,param,sizeof(tlv_ip4_external)-4+byte_len-3); //-3 is struct?
		}
		free(index);
	}

	linkedlist_addtail(&proc->multicast_queue,packet);
}

void create_packets_from_queues(struct eigrp_proccess *proc){
	neighbour *n;

	create_mutlticast_packet(proc,&proc->query_tlv_queue,OPCODE_QUERY,0);
	create_mutlticast_packet(proc,&proc->update_tlv_queue,OPCODE_UPDATE,0);

	hash_collection col;
	prepare_hashcollection(&col,proc->neighbours);
	while( (n = next(&col)) != NULL){
		auto_packet_split(n,&n->reply_tlv_queue,OPCODE_REPLY,n->reply_flag);
		auto_packet_split(n,&n->query_tlv_queue,OPCODE_QUERY,n->query_flag);
		auto_packet_split(n,&n->update_tlv_queue,OPCODE_UPDATE,n->update_flag);
		//Reset them after use
		n->reply_flag = 0;
		n->query_flag = 0;
		n->update_flag = 0;
	}
}

void create_packets_for_neighbour(neighbour *n){
	auto_packet_split(n,&n->reply_tlv_queue,OPCODE_REPLY,n->reply_flag);
	auto_packet_split(n,&n->query_tlv_queue,OPCODE_QUERY,n->query_flag);
	auto_packet_split(n,&n->update_tlv_queue,OPCODE_UPDATE,n->update_flag);
}
