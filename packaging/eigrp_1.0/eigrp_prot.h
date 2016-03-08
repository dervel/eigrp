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

#include <stdbool.h>
#include <sys/types.h>
#include <asm/byteorder.h>
#include <netinet/ip.h>

#include "linkedlist.h"
#include "eigrp_structs.h"
#include "config.h"

#ifndef PACKET_H_
#define PACKET_H_

typedef struct incoming_packet_{
	char data[PACKET_LEN];
	int length;
} packet;
#endif

void fill_packet(packet *p,char *buffer, int lenght);
route *create_route();
void handle_packet_ipv4(packet *p, interface *iff);
void handle_packet_ipv6(packet *p);
void send_ip4_packet_multicast(packetv4_param *param, struct eigrp_proccess *proc);
void send_ip4_packet(packetv4_param *param, int socket);

void store_data_in_route_internal(route *new_route,tlv_ip4_internal *tlv_route,neighbour *n);
void store_data_in_route_external(route *new_route,tlv_ip4_external *tlv_route,neighbour *n);
