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

#include "eigrp_structs.h"

#define PACKET_LENGTH 	2046

#define OS_VERSION 	0x0C04
#define EIGRP_VERSION 	0x0102

#define OPCODE_UPDATE	1
#define OPCODE_QUERY	3
#define OPCODE_REPLY	4
#define OPCODE_HELLO	5
#define OPCODE_SIAQUERY 10
#define OPCODE_SIAREPLY 11

#define FLAG_INIT 	0x01
#define FLAG_CR		0x02
#define FLAG_ENDOFTABLE 0x08
#define FLAG_ROUTEACTIVE 0x04

#define VERSION 	2

#define LEAST_MTU	500

#ifndef PACKETFACTORY_H_
#define PACKETFACTORY_H_

static char *string_codes[] __attribute__((unused)) = {"NONE","UPDATE","REQUEST","QUERY","REPLY","HELLO","RESERVED",
		"PROBE","RESERVED","RESERVED","SIA-QUERY","SIA-REPLY"};

#define to_string(x)	string_codes[x]

#endif
unsigned long classic_unscale_bandwidth(unsigned long bw);
unsigned long long classic_unscale_delay(unsigned long long scaled_microseconds);
unsigned long classic_scale_bandwidth(unsigned long bw);
unsigned long long classic_scale_delay(unsigned long long microseconds);
int fill_sequence_tlv(char *buffer, struct eigrp_proccess *proc);
tlv_ip4_internal *create_internal_route_tlv(route *r, int flags);
tlv_ip4_external *create_external_route_tlv(route *r, int flags);
void auto_packet_split(neighbour *n,linkedlist *tvls,int opcode,int flags);
void addtlv(packetv4_param *packet, void* tlv,int len);
packetv4_param *create_empty_packet(int opcode,int flags, struct sockaddr_in sin);
void create_eigrp_header(packetv4_param *packet, int packet_len, int opcode, int auto_sys_number, int seqnum, int acknum, int flags);
void create_hello_packet(packetv4_param *packet, struct eigrp_proccess *proc);
void send_update_all(struct eigrp_proccess *proc, vector tlvs, route *r);

void queue_sended_multicast_packet(struct eigrp_proccess *proc, packetv4_param *packet, int seq_number);

void add_query_tlv_multicast(struct eigrp_proccess *proc, route *r, int flags);
void add_update_tlv_multicast(struct eigrp_proccess *proc, route *r, int flags);
void add_reply_tlv_neighbour(neighbour *n,route *r, int flags);
void add_query_tlv_neighbour(neighbour *n,route *r, int flags);
void send_siaquery_neighbour(neighbour *n,route *r, int packet_flag, int route_flag);
void send_siareply_neighbour(neighbour *n,route *r, int packet_flag, int route_flag);

void create_packets_from_queues(struct eigrp_proccess *proc);
void create_packets_for_neighbour(neighbour *n);
