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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>

#include "vector.h"

struct netlink_route{
	struct sockaddr_storage dest;
	int prefix;
	struct sockaddr_storage gateway;
	unsigned char proto;
	unsigned int metric;
};

bool check_if_status(int index);
int route_add(struct sockaddr_storage *destination, struct sockaddr_storage *gateway,int prefix,__u32* metric);
int route_del(struct sockaddr_storage *destination, struct sockaddr_storage *gateway,int prefix,unsigned int metric);
int multipath_route_add(struct sockaddr_storage *destination,  vector *gateways,int prefix,unsigned int metric);
vector get_routes_by_table(int table, int family);
vector get_routes_by_protocol(int rtm_prot, int family);
int remove_routes_by_protocol(int protocol, int family);
int look_interface_changes();
void stop_interface_state_listener();
