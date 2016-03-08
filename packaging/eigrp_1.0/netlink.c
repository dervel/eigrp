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
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "libnetlink.h"
#include "netlink.h"
#include "utils.h"
#include "config.h"
#include "vector.h"
#include "eigrp_base.h"
#include "eigrp_main.h"

#define NL_PKT_BUF_SIZE 1024
#define RTNLGRP_MSGS (RTNLGRP_IPV4_IFADDR|RTNLGRP_IPV4_ROUTE|RTNLGRP_IPV6_IFADDR|RTNLGRP_IPV6_ROUTE)

static struct rtnl_handle rtnl_interface;

// This function forms the netlink packet to add a route to the kernel routing
// table
bool check_if_status(int index){
	struct rtnl_handle rth;

	// structure of the netlink packet. 
	struct{
		struct nlmsghdr n;
		struct ifinfomsg r;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));

    	if (rtnl_open(&rth, 0) < 0){
		printf("cannot open rtnetlink\n");
		return false;
	}

	// Initialisation of a few parameters 
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.n.nlmsg_type = RTM_GETLINK;

	req.r.ifi_index = index;

	int nbytes=0,reply_len=0;//ret, count=0;
	ssize_t counter = 5000;
	char reply_ptr[5000];
	char* buf = reply_ptr;
	struct ifinfomsg *iface;
	struct nlmsghdr *nlp;
	unsigned long bufsize ;

	nlp = malloc(sizeof(struct nlmsghdr));
	struct nlmsghdr *original_pointer = nlp;
	memset(nlp, 0, sizeof(struct nlmsghdr));

	int rbytes __attribute__((unused)) = rtnl_dump_request(&rth,RTM_GETLINK,&req,sizeof(req));

	for(;;){
		if( counter < sizeof(struct nlmsghdr)){
			printf("Reply is bugger than %lu\n", sizeof(reply_ptr));
			free(original_pointer);
			return false;
		}

		nbytes = recv(rth.fd, &reply_ptr[reply_len], counter, 0);

		if(nbytes < 0 ){
			printf("Error in recv\n");
			break;
		}
		
		if(nbytes == 0)
			printf("EOF in netlink\n");

		nlp = (struct nlmsghdr*)(&reply_ptr[reply_len]);
	
		if (nlp->nlmsg_type == NLMSG_DONE){
			// All data has been received.
			// Truncate the reply to exclude this message,
			// i.e. do not increase reply_len.
			break;
		}

		if (nlp->nlmsg_type == NLMSG_ERROR){
			printf("Error in msg\n");
			free(original_pointer);
			return false;
	}

		reply_len += nbytes;
		counter -= nbytes;
	}

	bufsize = reply_len;
	nlp = (struct nlmsghdr*)buf;
	
    	for (;NLMSG_OK(nlp, bufsize); nlp = NLMSG_NEXT(nlp, bufsize)){
		
		/* Get the route data */
        	iface = (struct ifinfomsg *) NLMSG_DATA(nlp);

		/* We only need the link of the specific index*/
		if (iface->ifi_index != index)
			continue;
	
        	if(iface->ifi_flags & IFF_RUNNING){
			free(original_pointer);
			rtnl_close(&rth);
			return true;
		}else{
			free(original_pointer);
			rtnl_close(&rth);
			return false;
		}

    	}

	free(original_pointer);
	rtnl_close(&rth);
	return false;
}

int route_add(struct sockaddr_storage *destination, struct sockaddr_storage *gateway,int prefix,__u32* metric){
	struct rtnl_handle rth;

	// structure of the netlink packet. 
	struct{
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	char mxbuf[256];
	struct rtattr * mxrta = (void*)mxbuf;
	//unsigned mxlock = 0;
	memset(&req, 0, sizeof(req));

	// Initialisation of a few parameters 
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWROUTE;
	req.r.rtm_family = destination->ss_family;
	req.r.rtm_table = get_eigrp_routing_table_number();
	req.r.rtm_dst_len = prefix;
	req.r.rtm_protocol = get_eigrp_routing_protocol_number();
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;
	mxrta->rta_type = RTA_METRICS;
	mxrta->rta_len = RTA_LENGTH(0);
	
	// RTA_DST and RTA_GW are the two esential parameters for adding a route
	// for ipv4, the length of the address is 4 bytes.
	if(destination->ss_family == AF_INET){
		struct sockaddr_in *dest = (struct sockaddr_in *)destination;
		struct sockaddr_in *gate = (struct sockaddr_in *)gateway;
		addattr_l(&req.n, sizeof(req), RTA_DST, &dest->sin_addr.s_addr, 4);
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gate->sin_addr.s_addr, 4);
	}else{
		struct sockaddr_in6 *dest = (struct sockaddr_in6 *)destination;
		struct sockaddr_in6 *gate = (struct sockaddr_in6 *)gateway;
		addattr_l(&req.n, sizeof(req), RTA_DST, &dest->sin6_addr.s6_addr, 16);
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gate->sin6_addr.s6_addr, 16);
	}
	
	addattr_l(&req.n, sizeof(req), RTA_PRIORITY, metric, 4);

	int status = 0;

	// opening the netlink socket to communicate with the kernel
	if (rtnl_open(&rth, 0) < 0){
		printf("cannot open rtnetlink\n");
		return -1;
	}

	// sending the packet to the kernel.
	status = rtnl_talk(&rth, &req.n, 0, 0, NULL);
	if (status < 0)
		return status;
	
	rtnl_close(&rth);
	return 0;
}

int route_del(struct sockaddr_storage *destination, struct sockaddr_storage *gateway,int prefix,unsigned int metric){
	struct rtnl_handle rth;

	// structure of the netlink packet. 
	struct{
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	char mxbuf[256];
	struct rtattr * mxrta = (void*)mxbuf;
	//unsigned mxlock = 0;
	memset(&req, 0, sizeof(req));

	// Initialisation of a few parameters 
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE;
	req.n.nlmsg_type = RTM_DELROUTE;
	req.r.rtm_family = destination->ss_family;
	req.r.rtm_table = get_eigrp_routing_table_number();
	req.r.rtm_dst_len = prefix;
	req.r.rtm_protocol = get_eigrp_routing_protocol_number();
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;
	mxrta->rta_type = RTA_METRICS;
	mxrta->rta_len = RTA_LENGTH(0);
	
	// RTA_DST and RTA_GW are the two esential parameters for adding a route
	// for ipv4, the length of the address is 4 bytes.
	if(destination->ss_family == AF_INET){
		struct sockaddr_in *dest = (struct sockaddr_in *)destination;
		struct sockaddr_in *gate = (struct sockaddr_in *)gateway;
		addattr_l(&req.n, sizeof(req), RTA_DST, &dest->sin_addr.s_addr, 4);
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gate->sin_addr.s_addr, 4);
	}else{
		struct sockaddr_in6 *dest = (struct sockaddr_in6 *)destination;
		struct sockaddr_in6 *gate = (struct sockaddr_in6 *)gateway;
		addattr_l(&req.n, sizeof(req), RTA_DST, &dest->sin6_addr.s6_addr, sizeof(dest->sin6_addr.s6_addr));
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gate->sin6_addr.s6_addr, sizeof(dest->sin6_addr.s6_addr));
	}

	addattr_l(&req.n, sizeof(req), RTA_PRIORITY, &metric, sizeof(metric));

	int status = 0;

	// opening the netlink socket to communicate with the kernel
	if (rtnl_open(&rth, 0) < 0){
		printf("cannot open rtnetlink\n");
		return -1;
	}

	// sending the packet to the kernel.
	status = rtnl_talk(&rth, &req.n, 0, 0, NULL);
	if (status < 0)
		return status;
	
	rtnl_close(&rth);
	return 0;
}

int multipath_route_add(struct sockaddr_storage *destination,  vector *gateways,int prefix, unsigned int metric){
	struct rtnl_handle rth;

	// structure of the netlink packet. 
	struct{
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));

	// Initialisation of a few parameters 
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWROUTE;
	req.r.rtm_family = destination->ss_family;
	req.r.rtm_table = get_eigrp_routing_table_number();
	req.r.rtm_dst_len = prefix;
	req.r.rtm_protocol = get_eigrp_routing_protocol_number();
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;
	
	// RTA_DST and RTA_GW are the two esential parameters for adding a route
	// for ipv4, the length of the address is 4 bytes.
	if(destination->ss_family == AF_INET){
		struct sockaddr_in *dest = (struct sockaddr_in *)destination;
		addattr_l(&req.n, sizeof(req), RTA_DST, &dest->sin_addr.s_addr, 4);

		addattr_l(&req.n, sizeof(req), RTA_PRIORITY, &metric, 4);

		char buf[NL_PKT_BUF_SIZE];		

		struct rtattr *rta = (void *)buf;
		struct rtnexthop *rtnh;
		
		rta->rta_type = RTA_MULTIPATH;
		rta->rta_len = RTA_LENGTH(0);
		rtnh = RTA_DATA(rta);

		int i;
		for(i=0;i<gateways->size;i++){
			struct sockaddr_in *gate = (struct sockaddr_in *)vector_get(gateways,i);

			rtnh->rtnh_len = sizeof(*rtnh);
			rtnh->rtnh_flags = 0;
			rtnh->rtnh_hops = gate->sin_port; //sockaddr_in.sin_port is used as the weight of the route, -1 is because rta adds plus one by it self
			rta->rta_len += rtnh->rtnh_len;

			char address[INET6_ADDRSTRLEN];
			ip_tochar(&address,vector_get(gateways,i));
			printf("Route through %s weight %d\n",address,rtnh->rtnh_hops);

			rta_addattr_l(rta, NL_PKT_BUF_SIZE, RTA_GATEWAY, &gate->sin_addr.s_addr, 4);
			rtnh->rtnh_len += (sizeof(struct rtattr) + 4);

			rtnh = RTNH_NEXT(rtnh);
		}
		addattr_l(&req.n, NL_PKT_BUF_SIZE, RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
	}
	
	//addattr_l(&req.n, sizeof(req), RTA_PRIORITY, metric, 4);

	int status = 0;

	// opening the netlink socket to communicate with the kernel
	if (rtnl_open(&rth, 0) < 0){
		printf("cannot open rtnetlink\n");
		return -1;
	}

	// sending the packet to the kernel.
	status = rtnl_talk(&rth, &req.n, 0, 0, NULL);
	if (status < 0)
		return status;
	
	rtnl_close(&rth);
	return 0;
}

vector get_routes_by_protocol(int rtm_prot, int family){

	vector routes;
	vector_init(&routes);

	struct{
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	}route_req;

	memset(&route_req, 0, sizeof(route_req));

	struct rtnl_handle rth;
    	if (rtnl_open(&rth, 0) < 0){
		printf("cannot open rtnetlink\n");
		return routes;
	}

	route_req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	route_req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	route_req.n.nlmsg_type = RTM_GETROUTE;

	route_req.r.rtm_family = family;
	route_req.r.rtm_table = get_eigrp_routing_table_number();
	route_req.r.rtm_dst_len = 0;
	route_req.r.rtm_src_len = 0;

	int nbytes=0,reply_len=0;//ret, count=0;
	ssize_t counter = 5000;
	char reply_ptr[5000];
	char* buf = reply_ptr;
	struct nlmsghdr *nlp;
	struct rtmsg *rtp;
	struct rtattr *rtap;
	int rtl;
	unsigned long bufsize ;

	nlp = malloc(sizeof(struct nlmsghdr));
	struct nlmsghdr *original_pointer = nlp;
	memset(nlp, 0, sizeof(struct nlmsghdr));
	
	int rbytes __attribute__((unused)) = rtnl_dump_request(&rth,RTM_GETROUTE,&route_req,sizeof(route_req));

	for(;;){
		if( counter < sizeof(struct nlmsghdr)){
			printf("Routing table is bigger than %lu\n", sizeof(reply_ptr));
			vector_free(&routes);
			free(original_pointer);
			return routes;
		}

		nbytes = recv(rth.fd, &reply_ptr[reply_len], counter, 0);

		if(nbytes < 0 ){
			printf("Error in recv\n");
			break;
		}
		
		if(nbytes == 0)
			printf("EOF in netlink\n");
		nlp = (struct nlmsghdr*)(&reply_ptr[reply_len]);
	
		if (nlp->nlmsg_type == NLMSG_DONE){
			// All data has been received.
			// Truncate the reply to exclude this message,
			// i.e. do not increase reply_len.
			break;
		}

		if (nlp->nlmsg_type == NLMSG_ERROR){
			printf("Error in msg\n");
			vector_free(&routes);
			free(original_pointer);
			return routes;
	}

		reply_len += nbytes;
		counter -= nbytes;
	}

	bufsize = reply_len;
	nlp = (struct nlmsghdr*)buf;
	
    	for (;NLMSG_OK(nlp, bufsize); nlp = NLMSG_NEXT(nlp, bufsize)){
		
		/* Get the route data */
        	rtp = (struct rtmsg *) NLMSG_DATA(nlp);

		/* We only need route from the specific protocol*/
		if (rtp->rtm_protocol != rtm_prot)
			continue;
	
        	/* Get attributes of route_entry */
        	rtap = (struct rtattr *) RTM_RTA(rtp);

        	/* Get the route atttibutes len */
        	rtl = RTM_PAYLOAD(nlp);
        	/* Loop through all attributes */

		struct netlink_route *route = malloc(sizeof(struct netlink_route));
		memset(route,0,sizeof(struct netlink_route));
		route->proto = rtp->rtm_protocol;
		route->prefix = rtp->rtm_dst_len;

        	for ( ; RTA_OK(rtap, rtl);rtap = RTA_NEXT(rtap, rtl)){
			
			if(rtap->rta_type == RTA_DST){
				if(family == AF_INET){
					memcpy(&((struct sockaddr_in*)&route->dest)->sin_addr.s_addr,RTA_DATA(rtap),4);
					route->dest.ss_family = AF_INET;
				}else{
					memcpy(&((struct sockaddr_in6*)&route->dest)->sin6_addr.s6_addr,RTA_DATA(rtap),16);
					route->dest.ss_family = AF_INET6;
				}
			}
			if(rtap->rta_type == RTA_GATEWAY){
				if(family == AF_INET){
					memcpy(&((struct sockaddr_in*)&route->gateway)->sin_addr.s_addr,RTA_DATA(rtap),4);
					route->gateway.ss_family = AF_INET;
				}else{
					memcpy(&((struct sockaddr_in6*)&route->gateway)->sin6_addr.s6_addr,RTA_DATA(rtap),16);
					route->gateway.ss_family = AF_INET6;
				}
			}
			if(rtap->rta_type == RTA_PRIORITY){
				route->metric = *(unsigned long *) RTA_DATA(rtap);
			}

        	}

		vector_add(&routes,route);

    	}

	free(original_pointer);
	rtnl_close(&rth);
	return routes;
}

vector get_routes_by_table(int table,int family){

	vector routes;
	vector_init(&routes);

	struct{
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	}route_req;

	memset(&route_req, 0, sizeof(route_req));

	struct rtnl_handle rth;
    	if (rtnl_open(&rth, 0) < 0){
		printf("cannot open rtnetlink\n");
		return routes;
	}

	route_req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	route_req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	route_req.n.nlmsg_type = RTM_GETROUTE;

	route_req.r.rtm_family = family;
	route_req.r.rtm_table = table;
	route_req.r.rtm_dst_len = 0;
	route_req.r.rtm_src_len = 0;

	int nbytes=0,reply_len=0;//ret, count=0;
	ssize_t counter = 5000;
	char reply_ptr[5000];
	char* buf = reply_ptr;
	struct nlmsghdr *nlp;
	struct rtmsg *rtp;
	struct rtattr *rtap;
	int rtl;
	unsigned long bufsize ;

	nlp = malloc(sizeof(struct nlmsghdr));
	memset(nlp, 0, sizeof(struct nlmsghdr));
	
	int rbytes __attribute__((unused)) = rtnl_dump_request(&rth,RTM_GETROUTE,&route_req,sizeof(route_req));

	for(;;){
		if( counter < sizeof(struct nlmsghdr)){
			printf("Routing table is bigger than %lu\n", sizeof(reply_ptr));
			vector_free(&routes);
			return routes;
		}

		nbytes = recv(rth.fd, &reply_ptr[reply_len], counter, 0);

		if(nbytes < 0 ){
			printf("Error in recv\n");
			break;
		}
		
		if(nbytes == 0)
			printf("EOF in netlink\n");
	
		nlp = (struct nlmsghdr*)(&reply_ptr[reply_len]);
	
		if (nlp->nlmsg_type == NLMSG_DONE){
			// All data has been received.
			// Truncate the reply to exclude this message,
			// i.e. do not increase reply_len.
			break;
		}

		if (nlp->nlmsg_type == NLMSG_ERROR){
			printf("Error in msg\n");
			vector_free(&routes);
			return routes;
	}

		reply_len += nbytes;
		counter -= nbytes;
	}

	bufsize = reply_len;
	nlp = (struct nlmsghdr*)buf;
	
    	for (;NLMSG_OK(nlp, bufsize); nlp = NLMSG_NEXT(nlp, bufsize)){
		
		/* Get the route data */
        	rtp = (struct rtmsg *) NLMSG_DATA(nlp);

		/* We only need route from the specific protocol*/
		if (rtp->rtm_table != table)
			continue;
	
        	/* Get attributes of route_entry */
        	rtap = (struct rtattr *) RTM_RTA(rtp);

        	/* Get the route atttibutes len */
        	rtl = RTM_PAYLOAD(nlp);
        	/* Loop through all attributes */

		struct netlink_route *route = malloc(sizeof(struct netlink_route));
		route->proto = rtp->rtm_protocol;
		route->prefix = rtp->rtm_dst_len;

        	for ( ; RTA_OK(rtap, rtl);rtap = RTA_NEXT(rtap, rtl)){
			
			if(rtap->rta_type == RTA_DST){
				struct sockaddr_storage dest;
				if(family == AF_INET){
					((struct sockaddr_in*)&dest)->sin_addr.s_addr = (unsigned long) RTA_DATA(rtap);
					dest.ss_family = AF_INET;
				}else{
					memcpy(&((struct sockaddr_in6*)&dest)->sin6_addr.s6_addr,RTA_DATA(rtap),16);
					dest.ss_family = AF_INET6;
				}
				route->dest = dest;
			}
			if(rtap->rta_type == RTA_GATEWAY){
				struct sockaddr_storage dest;
				if(family == AF_INET){
					((struct sockaddr_in*)&dest)->sin_addr.s_addr = (unsigned long) RTA_DATA(rtap);
					dest.ss_family = AF_INET;
				}else{
					memcpy(&((struct sockaddr_in6*)&dest)->sin6_addr.s6_addr,RTA_DATA(rtap),16);
					dest.ss_family = AF_INET6;
				}
				route->gateway = dest;
			}
			if(rtap->rta_type == RTA_PRIORITY){
				route->metric = *(unsigned long *) RTA_DATA(rtap);
			}

        	}

		vector_add(&routes,route);

    	}

	rtnl_close(&rth);

	return routes;
}

int remove_routes_by_protocol(int protocol,int family){
	vector routes = get_routes_by_protocol(protocol,family);
	
	int i;
	for(i=0;i<routes.size; i++){
		struct netlink_route *route;
		route = vector_get(&routes,i);

		route_del(&route->dest, &route->gateway,(int)route->prefix,route->metric);
		free(route);
	}

	vector_free(&routes);

	return i;
}

//Interface up/down state check
static bool running = true;
int handle(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg){
	struct ifinfomsg *iface;

	switch(n->nlmsg_type){
		case RTM_NEWLINK:

			iface = NLMSG_DATA(n);

			//int len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

			int index = iface->ifi_index;

			if(iface->ifi_flags & IFF_RUNNING)
				interface_up(index);
			if(!(iface->ifi_flags & IFF_RUNNING ))
				interface_down(index);
			
			break;
		case RTM_DELLINK:
			printf("Interface Down\n");
			break;
		
	}
	
	if(running){
		return 0;
	}else{
		return -1;
	}
}

int look_interface_changes(){

	if (rtnl_open(&rtnl_interface, RTNLGRP_LINK) < 0){
		printf("cannot open rtnetlink\n");
		return -1;
	}

	int status = rtnl_listen(&rtnl_interface,handle,0);

	rtnl_close(&rtnl_interface);
	printf("RTNL OFF\n");
	return status;
}

void stop_interface_state_listener(){
	rtnl_close(&rtnl_interface);
	running = false;
}

//TEST FUNCTIONS
static int counter = 5;
int test_handle(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg){
	struct ifinfomsg *iface;
	struct rtattr *attribute;
	char *ifname;

	switch(n->nlmsg_type){
		case RTM_NEWLINK:

			iface = NLMSG_DATA(n);

			int len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

			for(attribute = IFLA_RTA(iface);RTA_OK(attribute,len);attribute = RTA_NEXT(attribute,len)){
				switch(attribute->rta_type){
					case IFLA_IFNAME:
						ifname = RTA_DATA(attribute);
					break;
				}
						
			}

			if(iface->ifi_flags & IFF_RUNNING)
				printf("Interface %s is UP\n",ifname);
			if(!(iface->ifi_flags & IFF_RUNNING ))
				printf("Interface %s is DOWN\n",ifname);
			
			break;
		case RTM_DELLINK:
			printf("Interface Down\n");
			break;
		default:
			printf("ID:%d\n",n->nlmsg_type);
		
	}
	counter--;
	return counter;
}

int test_look_interface_changes(){

	struct rtnl_handle rth;
	if (rtnl_open(&rth, RTNLGRP_LINK) < 0){
		printf("cannot open rtnetlink\n");
		return -1;
	}
	
	int status = rtnl_listen(&rth,test_handle,0);

	rtnl_close(&rth);
	return status;
}
