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

#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>


#include "config.h"
#include "eigrp_base.h"
#include "eigrp_prot.h"
#include "eigrp_main.h"
#include "eigrp_ip4.h"
#include "eigrp_ip6.h"
#include "vector.h"
#include "utils.h"
#include "hashtable.h"
#include "eigrp_structs.h"
#include "packet_factory.h"
#include "collection.h"
#include "netlink.h"
#include "libtelnet.h"
#include "telnet.h"
#include "config_controller.h"

#define EIGRP_PROT_NUM 88
#define DEFAULT_NEIGHBOURS_HASHTABLE_SIZE 40
#define CONNECTED_ROUTE 999


static hash_table_t *proccesses_ip4;
static hash_table_t *proccesses_ip6;
static hash_table_t *interfaces;
static pthread_t interface_state_listener;
static globals *global_vars;
static bool proccesses_initialized;

int get_router_id(){
	int router_id = 0;
	struct ifaddrs *addrs, *tmp, *next_obj;	
	getifaddrs(&addrs);
	next_obj = addrs;

	while(next_obj){
		tmp = next_obj;
		next_obj = next_obj->ifa_next;

		int family = tmp->ifa_addr->sa_family;

		if(family == AF_INET){
			struct sockaddr_in *addr = (struct sockaddr_in*)tmp->ifa_addr;
			if(router_id < addr->sin_addr.s_addr)
				router_id = addr->sin_addr.s_addr;
		}
	}
	
	freeifaddrs(addrs);

	return router_id;
}

bool is_ready(){
	return proccesses_initialized;
}

void pre_init(){
	//Global variables
	global_vars = malloc(sizeof(globals));
	global_vars->key_chains = create_hash_table(50);
	vector_init(&global_vars->static_routes_ip4);
	vector_init(&global_vars->static_routes_ip6);
	global_vars->router_id = get_router_id();
	global_vars->proccesses_ip4 = 0;
	global_vars->proccesses_ip6 = 0;
	global_vars->maxid_ip4 = 0;
	global_vars->maxid_ip6 = 0;
	proccesses_initialized = false;

	
}

void post_init(){

	printf("--Initializing Key Chains--\n");
	hash_collection col;
	prepare_hashcollection(&col,get_running_config()->keychain_list);
	keychain_info *chain_info;
	while( (chain_info = next(&col)) != NULL){
		init_keychain(chain_info);
		hashtable_free(chain_info->keys);
		free(chain_info);
	}
	hashtable_free(get_running_config()->keychain_list);

	printf("--Initializing Interfaces--\n");
	hash_collection col2;
	prepare_hashcollection(&col2,get_running_config()->interface_list);
	iff_info *if_info;
	while( (if_info = next(&col2)) != NULL){
		init_interface(if_info);
	}

	//Initialize eigrp proccesses
	printf("--Initializing Proccesses--\n");
	//Create an optimal hashtable for eigrp usage

	int proccesses_ip4 = get_global_vars()->proccesses_ip4;
	int maxid_ip4 = get_global_vars()->maxid_ip4;
	int proccesses_ip6 = get_global_vars()->proccesses_ip6;

	if(proccesses_ip4 < 50)
		proccesses_ip4 = 50;
	else if(proccesses_ip4 / maxid_ip4 > 0.75)
		proccesses_ip4 = maxid_ip4;

/*	if(proccesses_ip6 < 50)*/
/*		proccesses_ip6 = 50;*/
/*	else if(proccesses_ip6 / maxid_ip6 > 0.75)*/
/*		proccesses_ip6 = maxid_ip6;*/

	init_proccess_hashtable(proccesses_ip4,proccesses_ip6);

	hash_collection col3;
	proccess *proc;

	prepare_hashcollection(&col3,get_running_config()->proccess_list_ip4);	
	while((proc=next(&col3))!= NULL){
		init_eigrp_proccess(proc,AF_INET);
	}

/*	prepare_hashcollection(&col3,proccess_list_ip6);	*/
/*	while((proc=next(&col3))!= NULL){*/
/*		init_eigrp_proccess(proc,AF_INET6);*/
/*	}*/

	init_telnet_server();
	proccesses_initialized = true;
}

globals *get_global_vars(){
	return global_vars;
}

key_chain *get_key_chain(char *name){
	return hashtable_getitem(global_vars->key_chains,hash(name));
}

interface *get_interface(int index){
	return hashtable_getitem(interfaces,index);
}

hash_table_t *get_interfaces(){
	return interfaces;
}

hash_table_t *get_proccesses(int family){
	if(family == AF_INET)
		return proccesses_ip4;
	else if(family == AF_INET6)
		return proccesses_ip6;
	else
		return NULL;
}

void init_proccess_hashtable(int num_ip4,int num_ip6){
	proccesses_ip4 = create_hash_table(num_ip4);
	proccesses_ip6 = create_hash_table(num_ip6);
}

struct eigrp_proccess *get_eigrp_proccess(int id,int family){

	struct eigrp_proccess *proc = NULL;
	if(family == AF_INET){
		proc = hashtable_getitem(proccesses_ip4,id);
	}else{
		proc = hashtable_getitem(proccesses_ip6,id);
	}
	if(proc == NULL)
		printf("BASE:Requested a NULL proccess. ID:%d\n",id);

	return proc;
}

route *unreachable_route(struct sockaddr_storage dest,int prefix,neighbour *n,bool external){
	
	route *r = create_route();
	r->dest = dest;
	r->prefix = prefix;
	r->sender = n;
	r->delay = EIGRP_UNREACHABLE;
	r->bandwidth = 0;
	r->load = 0;
	r->reliability = 0;
	r->hop = 0;
	r->to_be_removed = true;
	r->is_external = external;

	return r;
}

void init_interfaces_hashtable(){
	interfaces = create_hash_table(50);
}

route *get_route(route *r, neighbour *n){
	int i;

	for(i=0;i<n->routes.size;i++){

		route *r1 = vector_get(&n->routes, i);
		if(r->dest.ss_family != r1->dest.ss_family)continue;

		if(r->dest.ss_family == AF_INET){
			struct sockaddr_in *dest = (struct sockaddr_in*)&r->dest;
			struct sockaddr_in *dest1 = (struct sockaddr_in*)&r1->dest;
			if(dest->sin_addr.s_addr == dest1->sin_addr.s_addr && r1->prefix == r->prefix)return r1;
		}else{
			struct sockaddr_in6 *dest = (struct sockaddr_in6*)&r->dest;
			struct sockaddr_in6 *dest1 = (struct sockaddr_in6*)&r1->dest;
			if(compare_ip6_addr(&dest->sin6_addr, &dest1->sin6_addr) == 0)return r1;
		}
	}
	return NULL;
}

int count_feasible_successors(struct topology_route *tr,bool external){
	int i,count_external=0,count_internal=0;
	for(i=0;i<tr->routes.size;i++){
		route *r = vector_get(&tr->routes,i);
		if(r->is_external){
			if(r->reported_distance <= tr->feasible_distance_external)count_external++;
		}else{
			if(r->reported_distance <= tr->feasible_distance_internal)count_internal++;
		}
	}
	if(external){return count_external;
	}else{ return count_internal;}
}

unsigned long calculate_classic_metric(struct eigrp_proccess *proc,unsigned int bandwidth,int delay,int mtu ,int load,int rel){
	if(delay == EIGRP_UNREACHABLE)
		return EIGRP_INACCESSIBLE;

	int reliability = 1;
	unsigned int bw = (256 * (unsigned long)EIGRP_BANDWIDTH / bandwidth);
	unsigned int dl = 256 * (delay /10); // delay
	if(proc->k5 != 0){
		reliability = (proc->k5 / (rel + proc->k4 ));
	}

	unsigned long metric = (
			proc->k1 * bw + 
			((proc->k2 * bw)/(256-load)) +
			(proc->k3 * dl)
		     ) * reliability;

	return metric;
}

void calculate_classic_route_metric(struct eigrp_proccess *proc, route *newroute){
	unsigned long metric = calculate_classic_metric(proc,newroute->bandwidth,newroute->delay,newroute->mtu,newroute->load,newroute->reliability);	
	//Reported Distance
	newroute->reported_distance = metric;
	//Feasible Distance
	//Bandwidth
	int if_bw = newroute->sender->interface->bandwidth;		
	int min_bw = newroute->bandwidth < if_bw ? newroute->bandwidth : if_bw;
	//Delay
	unsigned long if_delay = newroute->sender->interface->delay;
	unsigned long acc_delay=0;
	if(if_delay == EIGRP_UNREACHABLE || newroute->delay == EIGRP_UNREACHABLE){
		acc_delay = EIGRP_UNREACHABLE;
	}else{
		acc_delay = if_delay + newroute->delay;
	}
	//Mtu
	int if_mtu = newroute->sender->interface->mtu;
	int min_mtu = newroute->mtu < if_mtu ? newroute->mtu : if_mtu;
	//Load
	int if_load = newroute->sender->interface->load;
	int max_load = newroute->load > if_load ? newroute->load : if_load;
	//Reliability
	int if_rel = newroute->sender->interface->reliability;
	int min_rel = newroute->reliability < if_rel ? newroute->reliability : if_rel;

	if(newroute->is_proccess_generated){
		newroute->feasible_distance = metric;
	}else{
		unsigned long feasible_distance = calculate_classic_metric(proc,min_bw,acc_delay,min_mtu ,max_load,min_rel);
		newroute->feasible_distance = feasible_distance;
	}
}

unsigned long get_ip_hash_result( struct sockaddr_storage *dest){
	unsigned long hash_result;
	if(dest->ss_family == AF_INET){
		hash_result = ((struct sockaddr_in *)dest)->sin_addr.s_addr;
	}else{
		unsigned char *addr = ((struct sockaddr_in6 *)dest)->sin6_addr.s6_addr;
		hash_result = hash_unsigned(addr);
	}
	return hash_result;
}

//The idea behind this is to use the network as an identifier, however we can have the
//same network with different prefixes. So we use 2 hashtables to find the route
//One searches the network and the other searches the prefix
struct topology_route* get_topology_network(struct eigrp_proccess* proc, struct sockaddr_storage dest,int prefix){

	struct topology_support* network_table;
	
	unsigned long hash_result = get_ip_hash_result(&dest);

	network_table = hashtable_getitem(proc->topology_support, hash_result);

	if(network_table == NULL){
		printf("Creatng network table\n");
		struct topology_support* new_network_table = malloc(sizeof (struct topology_support));
		new_network_table->topology_route = create_hash_table(32);
		
		hashtable_additem(proc->topology_support, new_network_table , hash_result);
		network_table = new_network_table;
	}
	struct topology_route *prefix_route = hashtable_getitem(network_table->topology_route, prefix);
	if(prefix_route == NULL){
		printf("Creatng prefix table\n");
		struct topology_route *tr = malloc(sizeof(struct topology_route));
		memset(tr,0,sizeof(struct topology_route));
		//Init topology_route
		vector_init(&tr->routes);
		tr->feasible_distance_external = 0xFFFFFFFF; //set the metric to infinate
		tr->feasible_distance_internal = 0xFFFFFFFF; //set the metric to infinate
		tr->feasible_distance = 0xFFFFFFFF; //set the metric to infinate
		tr->dest = dest;
		tr->prefix = prefix;
		tr->proc = proc;
		tr->route_state = PASSIVE_STATE;
		tr->successor = NULL;
		tr->ioj = 1;
		//end topology_route init

		hashtable_additem(network_table->topology_route, tr, prefix);
		prefix_route = tr;
	}
	return prefix_route;
}

void topology_route_change_flag(struct topology_route *tr, int new_state){
	telnet_dest_state_change(tr, new_state);
	tr->ioj = new_state;
}

bool topology_route_exists(struct eigrp_proccess* proc, struct sockaddr_storage *dest,int prefix){
	struct topology_support* network_table = hashtable_getitem(proc->topology_support, get_ip_hash_result(dest));
	if(network_table == NULL) return false;
	struct topology_route *prefix_route = hashtable_getitem(network_table->topology_route, prefix);
	return (prefix_route == NULL ? false : true);
}

void remove_route_entry(struct topology_route *tr, route *new_successor){
	//Remove the old entry from the routing table
	if(tr->successor != NULL)
		telnet_remove_successor(tr->successor);
	if(tr->successor != NULL && !tr->successor->is_proccess_generated)
		route_del(&tr->dest, &tr->successor->sender->address, tr->prefix, tr->old_successor_metric);
}

void set_new_successor(struct topology_route *tr, route *new_successor){

	char address[INET6_ADDRSTRLEN];
	ip_tochar(&address, &new_successor->sender->address);
	printf("Neightbour Address:%s\n",address);
	remove_route_entry(tr,new_successor);

	if(new_successor->is_external){
		tr->feasible_distance = tr->feasible_distance_external;
	}else{
		tr->feasible_distance = tr->feasible_distance_internal;
	}

	telnet_install_route(new_successor);
		
	tr->successor = new_successor;
	//Add the new entry
	if(!tr->successor->is_proccess_generated){
		if(tr->proc->lb_enabled){ //Load balancing enabled
			vector gateways; //Vector holds gateways for the route
			vector_init(&gateways);
			int i;
			for(i=0;i<tr->routes.size;i++){
				route *r = vector_get(&tr->routes,i);
				if(new_successor->is_external != r->is_external)continue; //Skip is the route isn't external/internal as the successor
				if(r->reported_distance >= tr->feasible_distance)continue; //Skip is the route isn't a feasible successor
				if(tr->proc->lb_min && tr->successor->feasible_distance != r->feasible_distance) continue; //If we use equal loadbalancing skip the routes with different FD
				if(r->reported_distance <= tr->successor->feasible_distance * tr->proc->variance){ //Route will be added the FD is smaller than the successors FD * variance
					if(new_successor->dest.ss_family == AF_INET){
						struct sockaddr_storage *gateway = malloc(sizeof(struct sockaddr_storage));
						memcpy(gateway,&r->sender->address,sizeof(struct sockaddr_storage));
						struct sockaddr_in *gate = (struct sockaddr_in*)gateway;
						//Find the weight of the route
						gate->sin_port = (tr->successor->feasible_distance * tr->proc->variance)/r->reported_distance;
						vector_add(&gateways,gateway);
					}
				}
			}
			//multipath_route_add(&dest, &gateways, 24);
			multipath_route_add(&tr->dest, &gateways,tr->prefix,tr->feasible_distance);
			for(i=0;i<tr->routes.size;i++){
				free(vector_get(&gateways,i));
			}
			vector_free(&gateways);
		}else{
			route_add(&tr->dest, &tr->successor->sender->address, tr->prefix, (__u32*)&tr->successor->feasible_distance);
			tr->old_successor_metric = tr->successor->feasible_distance;
		}
	}
}

route *find_feasible_successor(struct topology_route *tr,bool external){
	route *new_successor = NULL;
	int lowest_distance = 0xFFFFFFFF;
	int i;
	int feasible_distance = 0;

	if(external){feasible_distance = tr->feasible_distance_external;}
	else{feasible_distance = tr->feasible_distance_internal;}

	for(i=0;i<tr->routes.size;i++){
		route *r = vector_get(&tr->routes,i);

		if(r->delay == EIGRP_UNREACHABLE)continue;
		if(r->bandwidth == 0)continue;
		if(r->is_external != external)continue;

		if(r->is_proccess_generated){
			printf("Route From: self, reported distance:%d\n",r->reported_distance);
		}else{
			char address[INET6_ADDRSTRLEN];
			ip_tochar(&address, &r->sender->address);
		
			printf("Route From: %s, reported distance:%d\n",address,r->reported_distance);
		}

		calculate_classic_route_metric(tr->proc,r);

		if(r->reported_distance < feasible_distance && r->feasible_distance < lowest_distance){
			lowest_distance = r->feasible_distance;
			new_successor = r;
		}
		if(r->is_proccess_generated && r->feasible_distance <= lowest_distance){
			lowest_distance = r->feasible_distance;
			new_successor = r;
		}
	}

	return new_successor;
}

route *find_new_successor(struct topology_route *tr){
	route *new_successor = NULL;
	
	//Look for an internal route first
	new_successor = find_feasible_successor(tr,false);
	if(new_successor != NULL){
		tr->feasible_distance = tr->feasible_distance_internal;
		telnet_find_fs(tr, new_successor);
		return new_successor;
	}

	//If an internal route successor was not found look at the external routes
	new_successor = find_feasible_successor(tr,true);

	if(new_successor != NULL){
		tr->feasible_distance = tr->feasible_distance_external;
		telnet_find_fs(tr, new_successor);
		return new_successor;
	}

	telnet_find_fs(tr, NULL);
	return NULL;
}

void find_least_feasible_distance(struct topology_route *tr){
	int i;
	unsigned int least_router_distance_internal = 0xFFFFFFFF; //Least distance of this router to the destination
	unsigned int least_router_distance_external = 0xFFFFFFFF; //Least distance of this router to the destinatio

	for(i=0;i<tr->routes.size;i++){
		route *record = vector_get(&tr->routes, i);
		calculate_classic_route_metric(tr->proc,record);
		if(record->is_external){
			if(record->feasible_distance < least_router_distance_external)
				least_router_distance_external = record->feasible_distance;
		}else{
			if(record->feasible_distance < least_router_distance_internal)
				least_router_distance_internal = record->feasible_distance;
		}
	}

	tr->feasible_distance_external = least_router_distance_external;
	tr->feasible_distance_internal = least_router_distance_internal;
	
}

void set_waiting_for_reply(struct topology_route *tr,neighbour *n){
	int i,counter=0;
	for(i=0;i<tr->routes.size;i++){
		route *r = vector_get(&tr->routes,i);
		if(!r->sender->is_active || r->is_proccess_generated || !r->sender->interface->is_up || r->sender->state == PENDING_STATE || ip_equals(&n->address,&r->sender->address))
			r->rijk = 0; //FSM(8)
		else {
			r->rijk =1;
			counter++;
		}
	}
	telnet_reply_count(counter);
}

bool if_all_replies_received(struct topology_route *tr){
	int i;
	for(i=0;i<tr->routes.size;i++){		
		route *r = vector_get(&tr->routes,i);
		if(r->is_proccess_generated || r->sender->state == PENDING_STATE)continue;
		if(r->rijk == 1)
			return false;
	}
	telnet_all_replies_received(tr);
	return true;
}

void set_neighbour_routes_unreachable(neighbour *n){
	int i;

	for(i=0;i<n->routes.size;i++){
		route *r = vector_get(&n->routes,i);
		r->delay = EIGRP_UNREACHABLE;
	}
}

void recalculate_routes(neighbour *n){

	char address[INET6_ADDRSTRLEN];
	ip_tochar(&address, &n->address);
	printf("Recalculating routes for neighbor %s.\n",address);
	int i;

	for(i=0;i<n->routes.size;i++){
		route *r = vector_get(&n->routes,i);
		r->to_be_removed = true;
		r->delay = EIGRP_UNREACHABLE;

		struct topology_route *tr = get_topology_network(n->proc,r->dest,r->prefix);
		
		if(ip_equals(&tr->successor->sender->address, &n->address)){
			//Try to find a new successor, if no successors available set route to active
			route *successor = find_new_successor(tr);
			if(successor != NULL){
				//FSM(2)
				char address[INET6_ADDRSTRLEN];
				ip_tochar(&address, &successor->sender->address);
				printf("Setting new:%s\n",address);
				set_new_successor(tr, successor);
				//New successor send info
				add_update_tlv_multicast(n->proc,successor,0);
				continue;		
			}else{
				remove_route_entry(tr,tr->successor);
				//FSM(4)
				set_route_to_active(tr,1,tr->successor);
			}
		}
	}

	create_packets_from_queues(n->proc);

}

void remove_route_from_neighbour(route *r){
	neighbour *n = r->sender;
	int i;
	for(i=0;i<n->routes.size;i++){
		route *r1 = vector_get(&n->routes,i);
		if(ip_equals(&r1->dest, &r->dest) && r1->prefix == r->prefix){
			vector_delete(&n->routes,i);
			return;
		}
	}
}

void remove_topology_route(struct topology_route *tr){

	char address[INET6_ADDRSTRLEN];
	ip_tochar(&address,&tr->dest);
	telnet_no_routes(tr);
	printf("Removing route %s\n",address);
	
	pthread_cancel(tr->active_route_control);
	pthread_detach(tr->active_route_control);
	
	int i;
	for(i=0;i<tr->routes.size;i++){
		route *r = vector_get(&tr->routes,i);
		remove_route_from_neighbour(r);
		free(r);
	}

	struct topology_support* network_table = hashtable_getitem(tr->proc->topology_support, get_ip_hash_result(&tr->dest));
	hashtable_removeitem(network_table->topology_route, tr->prefix);
	vector_free(&tr->routes);
	free(tr);
}

void proccess_active_state_route(struct topology_route *tr){
	route *new_successor;
	char address[INET6_ADDRSTRLEN];
	ip_tochar(&address,&tr->dest);
	printf("Processing route %s/%d, flag:%d\n",address,tr->prefix,tr->ioj);
	pthread_cancel(tr->active_route_control);
	pthread_join(tr->active_route_control,NULL);
	if(tr->ioj == 0){
		//find_least_feasible_distance(tr);
		new_successor = find_new_successor(tr);
		if(new_successor == NULL){
			//FSM(11)
			//No successor was found
			set_route_to_active(tr,1,tr->successor);			
		}else{
			//FSM(14)
			tr->route_state = PASSIVE_STATE;
			topology_route_change_flag(tr, 1);
			//We don't send a reply
			//Set the new_successor
			set_new_successor(tr, new_successor);
			//add_update_tlv_multicast(tr->proc,tr->successor,0);

		}
	}else if(tr->ioj == 1){
		//find_least_feasible_distance(tr);
		new_successor = find_new_successor(tr);
		if(new_successor == NULL){
			//FSM(0) - killing route
			route *unreachable = unreachable_route(tr->dest,tr->prefix,tr->successor->sender,tr->successor->is_external);
			add_update_tlv_multicast(tr->proc,unreachable,0);
			remove_topology_route(tr);
		}else{
			//FSM(15)
			tr->route_state = PASSIVE_STATE;
			topology_route_change_flag(tr, 1);
			set_new_successor(tr, new_successor);
			//add_update_tlv_multicast(tr->proc,tr->successor,0);
		}
	}else if(tr->ioj == 2){
		new_successor = find_new_successor(tr);
		if(new_successor == NULL){
			//FSM(12)
			//No successor was found
			set_route_to_active(tr,3,tr->successor);
			//Query packet is queued throught the set_route_to_active call
		}else{
			//FSM(16)
			tr->route_state = PASSIVE_STATE;
			topology_route_change_flag(tr, 1);
			//Send the reply at our previous successor
			//add_reply_tlv_neighbour(tr->successor->sender,new_successor,0);
			//Set the new_successor
			set_new_successor(tr, new_successor);
			//add_update_tlv_multicast(tr->proc,tr->successor,0);
		}
	}else if(tr->ioj == 3){
		find_least_feasible_distance(tr);
		new_successor = find_new_successor(tr);
		if(new_successor == NULL){
			//FSM(0) - killing route
			route *unreachable = unreachable_route(tr->dest,tr->prefix,tr->successor->sender,tr->successor->is_external);
			unreachable->to_be_removed = false;		
			add_reply_tlv_neighbour(tr->successor->sender,unreachable,0);
			add_update_tlv_multicast(tr->proc,unreachable,0);
			remove_topology_route(tr);
			free(unreachable);
		}else{
			//FSM(13)
			tr->route_state = PASSIVE_STATE;
			topology_route_change_flag(tr, 1);
			//Send the reply at our previous successor
			add_reply_tlv_neighbour(tr->successor->sender,new_successor,0);
			//Set the new_successor
			set_new_successor(tr, new_successor);
			//add_update_tlv_multicast(tr->proc,tr->successor,0);
		}
	}else{
		printf("I fucked up the flag.\n");
	}

	//create_packets_from_queues(tr->proc);
}

void *stuck_in_active(void *ptr){
	int i,k,l;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED,NULL);

	struct topology_route *tr =(struct topology_route *)ptr;

	/*for(i=0;i<tr->routes.size;i++){
		route *r = vector_get(&tr->routes,i);
		r->sia_query_received = false;
	}*/

	sleep_millis(10 * 1000);
	pthread_testcancel();


	/*
		i = 0		initial period
		i = 1-3		1st 2nd 3rd period where sia queries are sent
		i = 4		set neighbor as unreachable

	*/
	for(i=0;i<5;i++){

		char address[INET6_ADDRSTRLEN];
		ip_tochar(&address, &tr->dest);
		printf("Loop %d stuck in active for route %s\n",i,address);

		if(tr->route_state == PASSIVE_STATE){
			pthread_exit(NULL);
		}

		
		for(k=0;k<tr->routes.size;k++){
			route *r = vector_get(&tr->routes,k);

			//If the neighbour doesn't reply to a sia-query set all dest as unreachable
			if(i>1 && i<4 && !r->is_proccess_generated && !r->sia_query_received){
				set_neighbour_routes_unreachable(r->sender);
				recalculate_routes(r->sender);
				r->rijk = 0;	
			}

			if(i > 0 && i<4){
				for(l=0;l<tr->routes.size;l++){
					route *r = vector_get(&tr->routes,l);
					if(r->is_proccess_generated)continue;
					r->sia_query_received = false;
					if(i<4 && r->rijk == 1){
						send_siaquery_neighbour(r->sender,r,0,0);
					}
				}
			}

			//If the neighbors hasn't sent a reply yet set all his routes as unreachable
			if(i == 4 && !r->is_proccess_generated && r->rijk == 1){
				set_neighbour_routes_unreachable(r->sender);
				recalculate_routes(r->sender);
				r->rijk = 0;
			}
		}

		if(if_all_replies_received(tr)){
			proccess_active_state_route(tr);
			create_packets_from_queues(tr->proc);
			pthread_exit(NULL);
		}

		for(k=0;k<45;k++){
			sleep(2);
			pthread_testcancel();
		}

	}

	printf("INFO:Stuck in active exited.\n");
	//pthread_detach(pthread_self());
	pthread_exit(NULL);
	return NULL;
}

void set_route_to_active(struct topology_route *tr, int flag,route *r){
	tr->route_state = ACTIVE_STATE;
	telnet_route_active(tr);
	topology_route_change_flag(tr, flag);
	set_waiting_for_reply(tr,r->sender);

	struct eigrp_proccess *proc = tr->proc;
	char address[INET6_ADDRSTRLEN];
	ip_tochar(&address,&r->dest);
	printf("Route %s/%d went to ACTIVE flag %d\n",address,r->prefix,flag);

	if(if_all_replies_received(tr)){
		printf("No neighbours available proccessing route rightaway\n");
		proccess_active_state_route(tr);
		//create_packets_from_queues(proc);
		return;
	}

	if(flag == 3 || flag == 1)
		add_query_tlv_multicast(proc,r,0);

	int ret = pthread_create(&tr->active_route_control,NULL ,stuck_in_active ,(void*)tr);
	if(ret){
		printf("Error creating active route control thread\n");				
	}
}

bool all_end_of_table_received(struct eigrp_proccess *proc){
	
	neighbour *n = NULL;

	hash_collection col;
	prepare_hashcollection(&col,proc->neighbours);
	while( (n = next(&col)) != NULL){
		if(n->eot == false)return false;
	}

	return true;
}

void reply_received(struct topology_route *tr, neighbour *n){
	int i;
	for(i=0;i<tr->routes.size;i++){
		route *r = vector_get(&tr->routes,i);
		if(ip_equals(&r->sender->address, &n->address)){
			char address[INET6_ADDRSTRLEN];
			ip_tochar(&address,&r->dest);
			char address1[INET6_ADDRSTRLEN];
			ip_tochar(&address1,&n->address);
			printf("Reply for route %s/%d received from neighbor %s\n",address,r->prefix,address1);
			r->rijk = 0;
			return;
		}
	}
}

void reply_received_link_down(struct topology_route *tr, int index){
	int i;
	for(i=0;i<tr->routes.size;i++){
		route *r = vector_get(&tr->routes,i);
		if(r->sender->interface->index == index){
			r->rijk = 0;
		}
	}
}

/*
	This functions adds/changes the routes that we receive from packets. As so we will use it to handle the route
	state.

	Also FSM(x) indicator references the http:/tools.ietf.org/html/draft-savage-eigrp-02 page 13 state transition events
*/

bool handle_route_changes(route *new_route, int opcode, struct eigrp_proccess *proc){
	char address[INET6_ADDRSTRLEN];
	ip_tochar(&address,&new_route->dest);
	printf("Handling route %s/%u delay %llu\n",address,new_route->prefix,new_route->delay);

	bool free_route = false;

	if(opcode == CONNECTED_ROUTE){

		struct topology_route *tr = get_topology_network(proc,new_route->dest,new_route->prefix);
		free_route = add_route_record(tr,new_route,proc);
		find_least_feasible_distance(tr);
		route *new_successor = find_new_successor(tr);
		if(new_successor == NULL){
			remove_topology_route(tr);
		}else{
			tr->route_state = PASSIVE_STATE;
			tr->ioj = 1;
			set_new_successor(tr, new_successor);
		}
		return free_route;
	}

	if(opcode == OPCODE_QUERY){
		if(!topology_route_exists(proc,&new_route->dest,new_route->prefix)){
			route *r = unreachable_route(new_route->dest,new_route->prefix,new_route->sender,new_route->is_external);
			add_reply_tlv_neighbour(new_route->sender,r,0);
			return true;
		}
		struct topology_route *tr = get_topology_network(proc,new_route->dest,new_route->prefix);
		topology_search(tr);
		packet_handling("rcvquery",new_route);
		free_route = add_route_record(tr,new_route,proc);
		if(tr->route_state == PASSIVE_STATE){
			printf("Route is Passive\n");
			//FSM(1)
			//If is not the successor
			if(!ip_equals(&tr->successor->sender->address, &new_route->sender->address)){
				//Send the reply
				add_reply_tlv_neighbour(new_route->sender,tr->successor, 0);
				return free_route; //Return so that we don't send a reply since it has already been sended
			}else{ //Is the successor
				printf("FSM(3)-QUERY\n");
				if(new_route->delay == EIGRP_UNREACHABLE || new_route->reported_distance > tr->feasible_distance){
					route *successor = find_new_successor(tr);
					if(successor != NULL){
						//FSM(0) - just change the neighbours
						set_new_successor(tr, successor);
						//New successor send info
						add_update_tlv_multicast(tr->proc,successor,0);
						add_reply_tlv_neighbour(new_route->sender,tr->successor,0);		
					}else{
						//FSM(3)
						set_route_to_active(tr,3,new_route);
						return free_route; //Route entered active state return so we that we don't send a reply
					}
				}//else{
				//We still have the old successor but the metrics changed so we send the ones
				//add_update_tlv_multicast(tr->proc,tr->successor,0);
				//}
			}
			//We send a reply since this is a query
			//add_reply_tlv_neighbour(new_route->sender,tr->successor,0);
		}else{ //Route is in active state

			if(tr->successor == NULL){
				tr->successor = new_route;
				set_route_to_active(tr,3,new_route);
				return free_route;
			}	

			//Is the successor
			//FSM(5)
			if(ip_equals(&tr->successor->sender->address, &new_route->sender->address)){
				if(tr->ioj == 0 || tr->ioj == 1)
					topology_route_change_flag(tr, 2);
			}else{ //Is not the successor
				//FSM(6)
				route *r = unreachable_route(new_route->dest,new_route->prefix,new_route->sender,new_route->is_external);
				add_reply_tlv_neighbour(new_route->sender,r,FLAG_ROUTEACTIVE);
			}

		}
	}

	if(opcode == OPCODE_UPDATE){
		struct topology_route *tr = get_topology_network(proc,new_route->dest,new_route->prefix);
		free_route = add_route_record(tr,new_route,proc);
		topology_search(tr);
		packet_handling("rcvupdate",new_route);
		if(tr->route_state == PASSIVE_STATE){

			//FSM(0) - new route
			if(tr->successor == NULL){
				if(new_route->delay == EIGRP_UNREACHABLE || new_route->bandwidth == 0){
					remove_topology_route(tr);
				}else{
					find_least_feasible_distance(tr);
					set_new_successor(tr, new_route);
					add_update_tlv_multicast(tr->proc,tr->successor,0);
				}
				return free_route;
			}

			if(ip_equals(&tr->successor->sender->address, &new_route->sender->address)){
				if(new_route->delay == EIGRP_UNREACHABLE || new_route->reported_distance > tr->feasible_distance){
					//find_least_feasible_distance(tr);					
					route *successor = find_new_successor(tr);
					if(successor != NULL){
						//FSM(2)
						set_new_successor(tr, successor);
						//New successor send info
						add_update_tlv_multicast(tr->proc,successor,0);
						return free_route;				
					}else{
						//FSM(4)
						set_route_to_active(tr,1,new_route);
						return free_route;
					}
				}else{
					//FSM(2)
					if(new_route->reported_distance != tr->feasible_distance)
						add_update_tlv_multicast(tr->proc,tr->successor,0);
				}
				//This will refresh the metric on the routing table
				if(tr->old_successor_metric != tr->successor->feasible_distance){
					//FSM(2)
					route *successor = find_new_successor(tr);
					set_new_successor(tr, successor);
					add_update_tlv_multicast(tr->proc,tr->successor,0);
					return free_route;
				}
				
			}else{
				set_new_successor(tr, tr->successor);
			}
			
		}else{
			//FSM(7)
			//The changes are recorded above no query or update are sended though
		}
	}

	//FSM(8)
	if(opcode == OPCODE_REPLY){
		if(!topology_route_exists(proc,&new_route->dest,new_route->prefix)){
			char address[INET6_ADDRSTRLEN];
			ip_tochar(&address,&new_route->dest);
			printf("No record for network %s/%d no further proccessing will be done.\n",address,new_route->prefix);
			new_route->to_be_removed = true;			
			return true;
		}
		struct topology_route *tr = get_topology_network(proc,new_route->dest,new_route->prefix);
		topology_search(tr);
		packet_handling("rcvreply",new_route);
		free_route = add_route_record(tr,new_route,proc);
		if(tr->route_state == ACTIVE_STATE){
			reply_received(tr,new_route->sender);
			if(if_all_replies_received(tr)){
				//We have heard from all neightbour, now we can find a new successor
				proccess_active_state_route(tr);
			}
		}
	}

	printf("Creating Packets.\n");

	return free_route;
}

bool proccess_uses_if(struct eigrp_proccess *proc, int if_index){
	int i;
	for(i=0;i<proc->ifs.size;i++){
		interface *iff = vector_get(&proc->ifs,i);
		if(iff->index == if_index) return true;
	}
	return false;
}

bool check_if_interface_exists(int index){
	interface *iff = get_interface(index);
	return (iff == NULL ? false : true);
}

void interface_down(int index){

	int i,k;
	route *r, *successor;
	interface *iff;
	struct eigrp_proccess *proc;
	struct topology_route *prefix_route;
	struct topology_support* support;
	neighbour *n;

	printf("IF DOWN method was called\n");
	if(!check_if_interface_exists(index))return;

	iff = get_interface(index);

	if(iff->is_up == false){
		printf("Interface %s id alreay down\n",iff->name);
		return;
	}
	
	iff->is_up = false;
	iff->running = false;
	
	//Foreach Proccess
	hash_collection col;

	for(k=0;k<2;k++){
		if(k==0)prepare_hashcollection(&col,proccesses_ip4);
		if(k==1)prepare_hashcollection(&col,proccesses_ip6);

		while( (proc = next(&col)) != NULL ){
			//Foreach Advertized Route
			for(i=0;i<proc->connected_routes.size;i++){
				r = vector_get(&proc->connected_routes, i);
				if(r->index == index){
					r->delay = EIGRP_UNREACHABLE;
					vector_delete(&proc->connected_routes, i);
					i--;
				}
			}
			//Foreach topology route
			hash_collection col1;
			prepare_hashcollection(&col1,proc->topology_support);	

			//Network
			while((support=next(&col1)) != NULL){
				//Prefix

				hash_collection col2;
				prepare_hashcollection(&col2,support->topology_route);

				while((prefix_route=next(&col2)) != NULL){
					if(prefix_route->successor != NULL && prefix_route->successor->sender->interface->index == index){
						if(prefix_route->route_state == ACTIVE_STATE){

							//FSM(8) FSM(9)
							reply_received_link_down(prefix_route,index);

							//FSM(9)
							if(prefix_route->ioj == 1){
								topology_route_change_flag(prefix_route, 0);
							}
							//FSM(10)
							if(prefix_route->ioj == 3){
								topology_route_change_flag(prefix_route, 2);
							}

							if(if_all_replies_received(prefix_route)){
								//We have heard from all neightbour, now we can find a new successor
								proccess_active_state_route(prefix_route);
							}
						}else{
							if(prefix_route->successor->is_proccess_generated){
								successor = find_new_successor(prefix_route);
								if(successor != NULL){
									//FSM(2)
									set_new_successor(prefix_route, successor);
									//New successor send info
									add_update_tlv_multicast(prefix_route->proc,successor,0);			
								}else{
									//FSM(4)
									set_route_to_active(prefix_route,1,prefix_route->successor);
								}
							}
						}
					}
				}

			}

			//Foreach Neighbour
			hash_collection col3;
			prepare_hashcollection(&col3,proc->neighbours);
			printf("Neighbours:%d\n",proc->neighbours->real_size);
			while( (n=next(&col3)) != NULL ){
				if(n->interface->index == index)
					free_neighbour(n,"peer restarted");
			}

			create_packets_from_queues(proc);
		}

	}
}

void interface_up(int index){
	int i,k;
	interface *iff;
	struct eigrp_proccess *proc;
	//struct topology_route *tr;

	printf("IF UP method was called.\n");

	if(!check_if_interface_exists(index))return;

	//We will need the iff to pull the delay value
	iff = get_interface(index);

	if(iff->is_up){
		printf("Interface %s already up returning.\n",iff->name);
		return;
	}

	iff->is_up = true;

	re_init_interface(iff);

	//Foreach Proccess
	hash_collection col;

	for(k=0;k<2;k++){
		if(k==0)prepare_hashcollection(&col,proccesses_ip4);
		if(k==1)prepare_hashcollection(&col,proccesses_ip6);

		while( (proc = next(&col)) != NULL ){
			for(i=0;i<proc->connected_routes.size;i++){
				route *r = vector_get(&proc->connected_routes, i);
				if(r->index == iff->index)
					r->delay = iff->delay;
			}
			create_packets_from_queues(proc);
		}
	}
}

void interface_metric_changed(int if_index,int value_index,int value){
	interface *iff;
	struct eigrp_proccess *proc;
	struct topology_route *prefix_route;//,*tr;
	struct topology_support* support;

	iff = get_interface(if_index);

	switch(value_index){
		case 0:
			iff->mtu = value;
			break;
		case 1:
			iff->bandwidth = value;
			break;
		case 2:
			iff->delay = value;
			break;
		case 3:
			iff->load = value;
			break;
		case 4:
			iff->reliability = value;
			break;
	}
	//Foreach Proccess
	hash_collection col;
	int k;

	for(k=0;k<2;k++){
		if(k==0)prepare_hashcollection(&col,proccesses_ip4);
		if(k==1)prepare_hashcollection(&col,proccesses_ip6);

		while( (proc = next(&col)) != NULL ){
		
			//Foreach topology route
			hash_collection col2;
			prepare_hashcollection(&col2,proc->topology_support);
			//Network
			while((support=next(&col2)) != NULL){
				//Prefix
				hash_collection col3;
				prepare_hashcollection(&col3,support->topology_route);

				while((prefix_route=next(&col3)) != NULL){
					if(prefix_route->successor->sender->interface->index == if_index){
						if(prefix_route->route_state == PASSIVE_STATE){
							calculate_classic_route_metric(proc,prefix_route->successor); //Update entry
							if(prefix_route->successor->reported_distance > prefix_route->feasible_distance){
								route *successor = find_new_successor(prefix_route);
								if(successor != NULL){
									//FSM(2)
									set_new_successor(prefix_route, successor);
									//New successor send info
									add_update_tlv_multicast(prefix_route->proc,successor,0);
									continue;		
								}else{
									//FSM(4)
									set_route_to_active(prefix_route,1,prefix_route->successor);
									continue;
								}
							}
							//FSM(2)
							add_update_tlv_multicast(prefix_route->proc,prefix_route->successor,0);
						}else{

							reply_received_link_down(prefix_route,if_index);						

							//FSM(9)
							if(prefix_route->ioj == 1){
								topology_route_change_flag(prefix_route, 0);
							
							}
							//FSM(10)
							if(prefix_route->ioj == 3){
								topology_route_change_flag(prefix_route, 2);
							}

							if(if_all_replies_received(prefix_route)){
								//We have heard from all neightbour, now we can find a new successor
								proccess_active_state_route(prefix_route);
							}
						}
					}else{
						//FSM(7)
						//Changes are recorded but no update is sent
					}
				}

			}
			create_packets_from_queues(proc);

		}
	}
}

bool add_route_record(struct topology_route* tr, route *new_route,struct eigrp_proccess *proc){

	char address[INET6_ADDRSTRLEN];
	ip_tochar(&address,&new_route->dest);
	char address1[INET6_ADDRSTRLEN];
	ip_tochar(&address1,&new_route->sender->address);

	int i;
	for(i=0;i<tr->routes.size;i++){
		route *record = vector_get(&tr->routes,i);
		if(ip_equals(&new_route->sender->address,&record->sender->address)){
			//I was gonna orgininally replace it, but we are just gonna overwrite the values - simpler

			record->delay = new_route->delay;
			record->bandwidth = new_route->bandwidth;
			record->mtu = new_route->mtu;
			record->hop = new_route->hop;
			record->reliability = new_route->reliability;
			record->load = new_route->load;

			record->reported_distance = new_route->reported_distance;
			//dest,prefix and sender are the same

			calculate_classic_route_metric(proc,record);
			new_route->to_be_removed = true;
			printf("XX: Route %s from %s will be removed\n",address,address1);
			return true;
		}
	}
	
	calculate_classic_route_metric(proc,new_route);

	//If the route is unreachable DO NOT add it at the topology metrics
	//if(new_route->delay == EIGRP_UNREACHABLE || new_route->bandwidth == 0){
		//return true;
	//}
	new_route->to_be_removed = false;
	//Add the route to the topology table
	vector_add(&tr->routes, new_route);
	//Add the route to neighbour as a reference
	vector_add(&new_route->sender->routes,new_route);
	printf("XX: Route %s from %s will NOT be removed\n",address,address1);
	return false;
}

void remove_route_record(struct topology_route* tr, route *remove){
	int k;	
	for(k=0;k<tr->routes.size;k++){
		route *record = vector_get(&tr->routes,k);		
		if(ip_equals(&record->sender->address, &remove->sender->address)){
			vector_delete(&tr->routes,k);
			break;
		}
	}
}

void route_recalculate(struct topology_route *tr){
	printf("Found route with changes\n");
	//First check if we have a successor
	if(tr->successor != NULL){
		//if the successor is active we exit, this function is called each time a new route
		//is inserted but that doesn't mean we have to recalculate everything if the successor
		//is working fine
		if(tr->successor->sender->is_active && tr->successor->delay != EIGRP_UNREACHABLE){
			tr->was_changed = false;
			return;
		}
	
	}

	//No successors found for the route, we will have to recalculate new ones	
	find_least_feasible_distance(tr);

	//Now that we have the least distance pass the records a 2nd time to find the successors
	//We are trying to find the 2 minimum cost paths - Hope the code doesn't look too ugly here
	route *primary_route = NULL;//successor
	int i;
	for(i=0;i<tr->routes.size;i++){
		route *record = vector_get(&tr->routes, i);
		//If the neighbour went inactive for some reason skip him
		if(!record->sender->is_active)
			continue;

		if(record->delay == EIGRP_UNREACHABLE)
			continue;

		//If it's upstream ignore it
		if(record->reported_distance < tr->feasible_distance)
			continue;

		if(primary_route == NULL)
			primary_route = record;
			continue;

		if(primary_route->reported_distance > record->reported_distance){
			primary_route = record;
			continue;
		}
	}

	//At this point we searched all record and we should have our successor and feasible successor
	tr->successor = primary_route;

	//Add the new route to the routing table
	printf("passing new routing information.\n");
	if(tr->successor != NULL){
		printf("Metric %d",tr->successor->feasible_distance);
		route_add(&tr->dest,&tr->successor->sender->address,tr->prefix,(__u32*)&tr->successor->feasible_distance);
	}

	tr->route_state = PASSIVE_STATE;
}

void calculate_changes_if_needed(struct eigrp_proccess* proc){
	
	hash_collection col;
	prepare_hashcollection(&col,proc->topology_support);
 
	//We need to check if any of the route had any changes

	
	//Network
	struct topology_support* support;
	while((support=next(&col)) != NULL){
		//Prefix
		struct topology_route *prefix_route;

		hash_collection col2;
		prepare_hashcollection(&col2,support->topology_route);

		while((prefix_route=next(&col2)) != NULL){
			if(prefix_route->route_state == ACTIVE_STATE){
				char address[INET6_ADDRSTRLEN];
				ip_tochar(&address,&prefix_route->dest);
				printf("Changing Route %s\n",address);
				route_recalculate(prefix_route);
			}
		}

	}
}

void remove_routes_from_neighbour(neighbour *n){
	printf("Removing routes:%d.\n",n->routes.size);
	int i;

	for(i=0;i<n->routes.size;i++){
		route *r = vector_get(&n->routes,i);

		if(r->delay != EIGRP_UNREACHABLE){
			char address[INET6_ADDRSTRLEN];
			ip_tochar(&address,&n->address);
			char address1[16];
			ip_tochar(&address1,&r->dest);
			printf("WARN:Removing a route from neighbour %s to dest %s:%d with a non-unreachable value.\n",address,address1,r->prefix);
		}
		
		struct topology_route *tr = get_topology_network(n->proc,r->dest,r->prefix);
		remove_route_record(tr,r);

		free(r);

	}
}

bool vector_contains(vector *v, char *string){
	int i;
	for(i=0;i<v->size;i++){
		if(equals(vector_get(v,i), string))
			return true;
	}
	return false;
}

bool packet_queues_empty(struct eigrp_proccess *proc){
	neighbour *n;

	hash_collection col;
	prepare_hashcollection(&col,proc->neighbours);
	while( (n = next(&col)) != NULL){
		if(!linkedlist_isempty(&n->packet_queue)) return false;
	}
	
	return true;
}

int get_interface_index_ip(struct sockaddr_storage *address, int prefix){
	
	interface *iff;

	hash_collection col;
	prepare_hashcollection(&col,interfaces);
	while( (iff = next(&col)) != NULL){

		if(address->ss_family == AF_INET){
			if(iff->ifa_addr_ip4.sin_addr.s_addr == 0)continue;
			int if_prefix = subnet_to_prefix(iff->ifa_netmask_ip4.sin_addr.s_addr);
			if(if_prefix < -1) return -1;
			if(prefix < if_prefix) continue;

			//Remove the host part and compare
			unsigned long network = (((struct sockaddr_in*)address)->sin_addr.s_addr) << (32-if_prefix);
			unsigned long if_network = iff->ifa_addr_ip4.sin_addr.s_addr << (32-if_prefix);
			if(network == if_network){
				return iff->index;
			}
		}else{
			//TODO: Find a matching interface for the address
		}
	}

	return -1;
}

void register_connected_route(struct eigrp_proccess *proc,net_info *adv_net){

	char address[INET6_ADDRSTRLEN];
	ip_tochar(&address,&adv_net->network);

	if(adv_net->external){
		printf("%s/%d is an external route and should not be here\n",address,adv_net->prefix);
		return;
	}

	//Interface Index
	int if_index = get_interface_index_ip(&adv_net->network,adv_net->prefix);
	if(if_index == -1){
		printf("Could not find a matching interface for network %s.\n",address);
		return;
	}
	interface *iff = get_interface(if_index);
	if(iff == NULL){
		printf("Error iff is null, connected route\n");
	}

	printf("Found a match for %s/%d through %s.\n",address,adv_net->prefix,iff->name);

	//Create the route struct
	route *connected_route = create_route();
	connected_route->is_proccess_generated = true;
	connected_route->index = if_index;
	connected_route->rijk = 0;
	//---------------------------
	connected_route->sender = iff->self;
	connected_route->prefix = adv_net->prefix;
	connected_route->dest = adv_net->network;
	//Metrics
	connected_route->mtu = iff->mtu;
	connected_route->reliability = iff->reliability;
	connected_route->delay = iff->delay;
	connected_route->bandwidth = iff->bandwidth;
	connected_route->load = iff->load;
	connected_route->hop = 0;
	connected_route->route_tag = 0;
	connected_route->is_external = false;
	//---------------------------

	calculate_classic_route_metric(proc,connected_route);
	//Add the route struct to the topology_table
	bool free_route = handle_route_changes(connected_route,CONNECTED_ROUTE,proc);
	if(free_route){
		free(connected_route);
	}else{
		vector_add(&proc->connected_routes,connected_route);
	}

}
void register_static_route(struct eigrp_proccess *proc,net_info *adv_net,int trigger_if){

	char address[INET6_ADDRSTRLEN];
	ip_tochar(&address,&adv_net->network);

	if(!adv_net->external){
		printf("%s/%d is an internal route and should not be here\n",address,adv_net->prefix);
		return;
	}

	struct sockaddr_storage forward_addr;
	forward_addr.ss_family = adv_net->network.ss_family;
	int result;
	if(forward_addr.ss_family == AF_INET){
		result = inet_pton(adv_net->network.ss_family,adv_net->forward,&((struct sockaddr_in*)&forward_addr)->sin_addr);
	}else{
		result = inet_pton(adv_net->network.ss_family,adv_net->forward,&((struct sockaddr_in6*)&forward_addr)->sin6_addr);
	}

	//If forward isn't an address it's probly an interface
	interface *iff = NULL;
	int if_index = -1;
	if(result == 0){
		//Find the interface
		hash_collection col;
		prepare_hashcollection(&col,interfaces);
		while( (iff=next(&col)) != NULL){
			if(equals(iff->name,adv_net->forward)){
				break;
			}
		}

		//No matching interface name
		if(iff == NULL){
			printf("Could not find the interface %s to forward route %s/%d\n",adv_net->forward,address,adv_net->prefix);
			return;
		}

		if_index = iff->index;
	}else{
		if_index = get_interface_index_ip(&forward_addr,adv_net->prefix);
		iff = get_interface(if_index);

		if(iff == NULL){
			printf("Could not find the network %s to forward route %s/%d\n",adv_net->forward,address,adv_net->prefix);
			return;
		}
	}

	if(if_index != trigger_if && trigger_if != -1)return;

	if(iff == NULL){
		printf("Error iff is null, static route\n");
	}

	//Create the route struct
	route *connected_route = create_route();
	connected_route->is_proccess_generated = true;
	connected_route->index = if_index;
	connected_route->rijk = 0;
	//---------------------------
	connected_route->sender = iff->self;
	connected_route->prefix = adv_net->prefix;
	connected_route->dest = adv_net->network;
	//Metrics
	connected_route->mtu = iff->mtu;
	connected_route->reliability = iff->reliability;
	connected_route->delay = iff->delay;
	connected_route->bandwidth = iff->bandwidth;
	connected_route->load = iff->load;
	connected_route->hop = 0;
	connected_route->route_tag = 0;
	connected_route->is_external = true;
	//---------------------------

	//Add the route to the directly connected_rotues - Is used when interface does up/down
	calculate_classic_route_metric(proc,connected_route);
	//Add the route struct to the topology_table
	bool free_route = handle_route_changes(connected_route,CONNECTED_ROUTE,proc);
	if(free_route){
		free(connected_route);
	}else{
		vector_add(&proc->connected_routes,connected_route);
	}
}

void init_values(struct eigrp_proccess *proc,int i,proccess *proc_info){	

	proc->running = true;

	proc->k1=proc_info->k1;
	proc->k2=proc_info->k2;
	proc->k3=proc_info->k3;
	proc->k4=proc_info->k4;
	proc->k5=proc_info->k5;
	proc->k6=proc_info->k6;

	proc->proccess_id=i;
	proc->router_id=1;
	proc->hello_interval = 5;
	proc->holdtime = proc->hello_interval * 3;

	vector_init(&proc->ifs);
	vector_init(&proc->connected_routes);

	linkedlist_init(&proc->multicast_queue);
	linkedlist_init(&proc->query_tlv_queue);
	linkedlist_init(&proc->update_tlv_queue);

	proc->seq_num = 1;

	proc->lb_min = proc_info->lb_min;
	proc->lb_enabled = proc_info->lb_enabled;
	proc->variance = proc_info->variance;

	proc->neighbours = create_hash_table(DEFAULT_NEIGHBOURS_HASHTABLE_SIZE);
	proc->topology_support = create_hash_table(30);

	int k;
	for(k=0;k<12;k++){
		proc->stats.packets_received[k] = 0;
		proc->stats.packets_sent[k] = 0;
	}
	proc->stats.acks_sent = 0;
	proc->stats.acks_received = 0;

}


int init_eigrp_proccess(proccess *proc_info,int family){

	struct eigrp_proccess *proc;
	int i,id = proc_info->id;
	net_info *adv_net;
	interface *iff;

	//Here we will be skipping the get function cause we are initializing
	proc = get_eigrp_proccess(id,family);
	if(proc != NULL){
		printf("Trying to initialize an already initialized proccess: %d\n",id);
		return -1;
	}

	printf("Initializing Eigrp Proccess %d\n" , id);
	proc = malloc(sizeof(struct eigrp_proccess));

	//Init Basic Values
	init_values(proc, id,proc_info);
	proc->redistribute_static = proc_info->redistribute_static;

	hash_collection col;
	prepare_hashcollection(&col,interfaces);
	while((iff = next(&col)) != NULL){

		if(vector_contains(&proc_info->passive_ifs, iff->name)){
			continue;
		}else{
			vector_add(&proc->ifs, iff);
		}
	}
	
	for(i=0;i<proc_info->advertised_networks.size;i++){
		adv_net = vector_get(&proc_info->advertised_networks,i);
		register_connected_route(proc,adv_net);
	}

	if(proc->redistribute_static){
		vector *static_routes;
		if(family == AF_INET){
			static_routes = &global_vars->static_routes_ip4;
		}else{
			static_routes = &global_vars->static_routes_ip6;
		}

		for(i=0;i<static_routes->size;i++){
			adv_net = vector_get(static_routes,i);
			register_static_route(proc,adv_net,-1);
		}
	}

	if(family == AF_INET){
		int ret = pthread_create(&proc->hello_sender,NULL ,hello_packet_thread_ip4 ,(void*)proc);
		if(ret){
			printf("Error creating hello thread for proccess %d ip4.\n", proc->proccess_id);
			free(proc);
			return -1;
		}

		//This is the thread tasked with sending the packets so they arrive with the correct order(seq,ack)
		//also tasked with looking if the neighbour is still active since it handles the packets recved
		ret = pthread_create(&proc->packet_sender,NULL ,send_ipv4_packets ,(void*)proc);
		if(ret){
			printf("Error creating sender thread for proccess %d ip4.\n", proc->proccess_id);
			free(proc);				
			return -1;
		}

		hashtable_additem(proccesses_ip4,proc,id);
	}else{
		int ret = pthread_create(&proc->hello_sender,NULL ,hello_packet_thread_ip6 ,(void*)proc);
		if(ret){
			printf("Error creating hello thread for proccess %d ip6.\n", proc->proccess_id);
			free(proc);
			return -1;
		}

		//This is the thread tasked with sending the packets so they arrive with the correct order(seq,ack)
		//also tasked with looking if the neighbour is still active since it handles the packets recved
		ret = pthread_create(&proc->packet_sender,NULL ,send_ipv6_packets ,(void*)proc);
		if(ret){
			printf("Error creating sender thread for proccess %d ip6.\n", proc->proccess_id);
			free(proc);				
			return -1;
		}

		hashtable_additem(proccesses_ip6,proc,id);
	}

	printf("Eigrp proccess %d working on %d interfaces.\n",proc->proccess_id,proc->ifs.size);

	return 0;
}

bool is_initialized_eigrp(int i,int family){
	
	struct eigrp_proccess *proc = get_eigrp_proccess(i,family);
	if(proc == NULL) return false;
	else return true;
}

int get_socket_mtu(int socket,int family,char *name){
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = family;
	strcpy(ifr.ifr_name,name);
	if(ioctl(socket, SIOCGIFMTU, &ifr) < 0){
		return -1;
	}
	return ifr.ifr_mtu;
}

int re_init_interface(interface *iff){

	char address[INET6_ADDRSTRLEN];

	sleep(3);
	printf("Setting up interface %s for use.\n",iff->name);

	struct ifaddrs *addrs, *tmp, *next_obj;

	getifaddrs(&addrs);
	next_obj = addrs;

	while(next_obj){
		tmp = next_obj;
		next_obj = next_obj->ifa_next;

		if(!compare(tmp->ifa_name, iff->name)){
			continue;
		}

		int family = tmp->ifa_addr->sa_family;

		//If it is NOT one of the follow families then continue
		if(!(family == AF_INET || family == AF_INET6))
			continue;

		if(family == AF_INET){
			//Address
			memcpy(&iff->ifa_addr_ip4,tmp->ifa_addr,sizeof(struct sockaddr));
			//Mask
			memcpy(&iff->ifa_netmask_ip4,tmp->ifa_netmask,sizeof(struct sockaddr));
		}else if(family == AF_INET6){
			//Address
			memcpy(&iff->ifa_addr_ip6,tmp->ifa_addr,sizeof(struct sockaddr));
			//Mask
			memcpy(&iff->ifa_netmask_ip6,tmp->ifa_netmask,sizeof(struct sockaddr));
		}
	}
	
	freeifaddrs(addrs);

	iff->running = true;

	/*
		INIT FOR IP4
	*/

	if(iff->ifa_addr_ip4.sin_addr.s_addr != 0){

		if(init_ip4(iff)){
			iff->ip4_init = true;
		}
	}

	/*
		INIT FOR IP6
	

	if(iff->ifa_addr_ip6.sin6_addr.s6_addr != 0){

		if(init_ip6(iff)){
			iff->ip6_init = true;
		}
	}*/

	hash_collection col;
	struct eigrp_proccess *proc;
	int i,k,family;

	for(k=0;k<2;k++){
		if(k==0){
			prepare_hashcollection(&col,proccesses_ip4);
			family = AF_INET;
		}
		if(k==1){
			prepare_hashcollection(&col,proccesses_ip6);
			family = AF_INET6;
		}

		while( (proc=next(&col)) != NULL ){
			proccess *proc_info = get_proccess_info(proc->proccess_id,family);
			if(proc_info == NULL)continue;
			for(i=0;i<proc_info->advertised_networks.size;i++){

				net_info *adv_net = vector_get(&proc_info->advertised_networks,i);

				//Find again an interface capable of routing to the network
				int if_index = get_interface_index_ip(&adv_net->network,adv_net->prefix);
				if(if_index == -1){
					ip_tochar(&address,&adv_net->network);
					printf("Could not find a matching interface for network %s.\n",address);
					continue;
				}

				//If the index of that network is interface we are currently re initializing register the routes at eigrp
				if(if_index == iff->index){
					ip_tochar(&address,&adv_net->network);
					printf("Adding connected route %s/%d.\n",address,adv_net->prefix);
					register_connected_route(proc,adv_net);
				}
			}

			if(proc->redistribute_static){
				vector *static_routes;
				if(family == AF_INET){
					static_routes = &global_vars->static_routes_ip4;
				}else{
					static_routes = &global_vars->static_routes_ip6;
				}

				for(i=0;i<static_routes->size;i++){
					net_info *adv_net = vector_get(static_routes,i);
					register_static_route(proc,adv_net,iff->index);
				}
			}
		}

	}

	return 0;
}

int init_interface(iff_info *info){
	//char host[NI_MAXHOST];
	//int ret;

	interface *new_if = malloc(sizeof(interface));
	memset(new_if,0,sizeof(interface));
	new_if->socket4 = 0;
	new_if->socket6 = 0;
	new_if->name = info->name;
	new_if->index = info->index;
	new_if->ip4_init = false;
	new_if->ip6_init = false;
	memset(&new_if->ifa_addr_ip4,0,sizeof(struct sockaddr_in));
	memset(&new_if->ifa_netmask_ip4,0,sizeof(struct sockaddr_in));
	memset(&new_if->ifa_addr_ip6,0,sizeof(struct sockaddr_in6));
	memset(&new_if->ifa_netmask_ip6,0,sizeof(struct sockaddr_in6));
	new_if->delay = info->delay;
	new_if->bandwidth = info->bandwidth;
	new_if->is_up = true;
	new_if->proccess_encryption =create_hash_table(info->eigrp_encryption->real_size);

	hash_collection col;
	prepare_hashcollection(&col,info->eigrp_encryption);
	
	encrypt_info *encrypt;
	while( (encrypt = next(&col)) != NULL){
		process_keys *proc_keys = malloc(sizeof(process_keys));
		proc_keys->eigrp_id = encrypt->eigrp_id;
		
		key_chain *keychain = hashtable_getitem(global_vars->key_chains,hash(encrypt->keychain_name));
		if(keychain == NULL){
			printf("Key chain %s could not be found\n",encrypt->keychain_name);
			free(proc_keys);
			continue;
		}
		proc_keys->keychain = keychain;

		hashtable_additem(new_if->proccess_encryption,proc_keys,proc_keys->eigrp_id);
	}

	struct ifaddrs *addrs, *tmp, *next_obj;	
	getifaddrs(&addrs);
	next_obj = addrs;

	while(next_obj){
		tmp = next_obj;
		next_obj = next_obj->ifa_next;

		if(!compare(tmp->ifa_name, new_if->name)){
			continue;
		}

		int family = tmp->ifa_addr->sa_family;

		//If it is NOT one of the follow families then continue
		if(!(family == AF_INET || family == AF_INET6))
			continue;

		if(family == AF_INET){
			//Address
			memcpy(&new_if->ifa_addr_ip4,tmp->ifa_addr,sizeof(struct sockaddr));
			//Mask
			memcpy(&new_if->ifa_netmask_ip4,tmp->ifa_netmask,sizeof(struct sockaddr));
		}else if(family == AF_INET6){
			//Address
			memcpy(&new_if->ifa_addr_ip6,tmp->ifa_addr,sizeof(struct sockaddr));
			//Mask
			memcpy(&new_if->ifa_netmask_ip6,tmp->ifa_netmask,sizeof(struct sockaddr));
		}
	}
	
	freeifaddrs(addrs);

	new_if->running = true;
	new_if->reliability = 255;
	new_if->load = 1;

	bool ip4error __attribute__((unused))= false;
	bool ip6error __attribute__((unused))= false;

	/*
		INIT FOR IP4
	*/

	if(new_if->ifa_addr_ip4.sin_addr.s_addr != 0){

		if(init_ip4(new_if)){
			new_if->ip4_init = true;
		}
	}

	/*
		INIT FOR IP6

	if(new_if->ifa_addr_ip6.sin6_addr.s6_addr != 0){

		if(init_ip6(new_if)){
			new_if->ip6_init = true;
		}
	}*/


	new_if->is_up = check_if_status(new_if->index);


	//Make Self Neighbour - used ONLY for directly connected routes to pull info
	struct neighbour_ *n = malloc(sizeof(struct neighbour_));
	memset(&n->address,0,sizeof(struct sockaddr_storage));
	struct sockaddr_in *address = (struct sockaddr_in *)&n->address;
	address->sin_addr.s_addr = 0;
	address->sin_family = AF_INET;
	n->interface = new_if;
	n->proc = NULL;
	n->eot = true;
	n->is_active = true;
	vector_init(&n->routes);

	new_if->self = n;

	printf("Interface %s index:%d is ready for use.\n",new_if->name,new_if->index);
	hashtable_additem(interfaces,new_if,new_if->index);

	return 0;
}

int init_keychain(keychain_info *info){

	key_chain *new_keychain = malloc(sizeof(key_chain));
	new_keychain->name = info->name;
	int hash_size = info->keys->real_size;
	if(hash_size<10)hash_size = 10;
	new_keychain->keys = create_hash_table(hash_size);

	hash_collection col;
	prepare_hashcollection(&col,info->keys);
	key_info *k;

	while( (k = next(&col)) != NULL){
		key *new_key = malloc(sizeof(key));
		new_key->indentifier = k->indentifier;
		new_key->password = k->password;
		hashtable_additem(new_keychain->keys,new_key,new_key->indentifier);

		free(k);
	}

	hashtable_additem(global_vars->key_chains,new_keychain,hash(new_keychain->name));
	return 0;
}

void *if_change( void *ptr){
	look_interface_changes();
	return NULL;
}

// FREE/FINALIZE STUFF

void start_interface_state_listener(){
	int ret = pthread_create(&interface_state_listener ,NULL ,if_change , NULL);
	if(ret){
		printf("Error creating interface state listener.\n");
		return;
	}
}

void free_neighbour(neighbour *n, char *reason){
	printf("Starting Freeing.\n");
	n->is_active = false;
	if(n->proc->running){
		dual_nbrchange(n->proc, n, false, reason);
		telnet_neighbour_down(n);
		recalculate_routes(n);
		remove_routes_from_neighbour(n);
	}
	vector_free(&n->routes);
	hashtable_removeitem(n->proc->neighbours,get_ip_hash_result(&n->address));
	packetv4_param *packet;
	while(	(packet=linkedlist_getfirst(&n->packet_queue)) != NULL )
		free(packet);
	linkedlist_free(&n->packet_queue);
	linkedlist_free(&n->update_tlv_queue);
	linkedlist_free(&n->query_tlv_queue);
	linkedlist_free(&n->reply_tlv_queue);
	free(n);
	printf("Freeing Done.\n");
}

void free_topology_route(struct topology_route *tr){
	int i;
	for(i=0;i<tr->routes.size;i++){
		route *r = vector_get(&tr->routes,i);
		free(r);
	}
	vector_free(&tr->routes);
	free(tr);
}

void shutdown_proccess(int i,int family){
	printf("Shutting Down Eigrp Proccess %d.\n",i);
	struct eigrp_proccess *proc;

	proc = get_eigrp_proccess(i,family);	

	proc->running = false;

	hash_collection col,col1;

	int res;
	if((res = pthread_cancel(proc->packet_sender))){
		printf("ERR:Could not find thread\n");
	}

	pthread_join(proc->hello_sender,NULL);
	pthread_detach(proc->packet_sender);

	prepare_hashcollection(&col,proc->topology_support);
	struct topology_support *ts;
	while( (ts=next(&col)) != NULL){
		prepare_hashcollection(&col1,ts->topology_route);
		struct topology_route *tr;
		while( (tr=next(&col1)) != NULL){
			free_topology_route(tr);
		}
		hashtable_free(ts->topology_route);
		free(ts);
	}

	prepare_hashcollection(&col,proc->neighbours);
	neighbour *n;
	while( (n=next(&col)) != NULL){
		free_neighbour(n,"eigrp shutting down");
	}
	hashtable_free(proc->neighbours);

	vector_free(&proc->connected_routes);

	hashtable_free(proc->topology_support);

	linkedlist_free(&proc->multicast_queue);
	linkedlist_free(&proc->query_tlv_queue);
	linkedlist_free(&proc->update_tlv_queue);
}

void pre_shutdown_interface(interface *iff){
	iff->running = false;
	if(iff->ip4_init){
		pthread_cancel(iff->packet_listener4);
		pthread_detach(iff->packet_listener4);
	}
	if(iff->ip6_init){
		pthread_cancel(iff->packet_listener6);
		pthread_detach(iff->packet_listener6);
	}
}

void post_shutdown_interface(interface *iff){
	hash_collection col;
	prepare_hashcollection(&col,iff->proccess_encryption);
	process_keys *keys;
	while ( (keys=next(&col)) != NULL ){
		free(keys);
	}
	hashtable_free(iff->proccess_encryption);

	//free(iff->name);
	vector_free(&iff->self->routes);
	free(iff->self);
	free(iff);
}

void shutdown_eigrp(){
	printf("Shutting Down Eigrp.\n");

	hash_collection col;

	prepare_hashcollection(&col,interfaces);
	interface *iff;
	while((iff=next(&col)) != NULL){
		pre_shutdown_interface(iff);
	}
	printf("Stopped Receiveing Packets\n");
	
	prepare_hashcollection(&col,proccesses_ip4);
	
	struct eigrp_proccess* proc;
	while((proc=next(&col)) != NULL){
		shutdown_proccess(proc->proccess_id,AF_INET);
		vector_free(&proc->ifs);
		free(proc);
	}
	hashtable_free(proccesses_ip4);
	printf("EIGRP IPv4 Processes Stopped\n");

	prepare_hashcollection(&col,proccesses_ip6);
	while((proc=next(&col)) != NULL){
		shutdown_proccess(proc->proccess_id,AF_INET6);
		vector_free(&proc->ifs);
		free(proc);
	}
	hashtable_free(proccesses_ip6);
	printf("EIGRP IPv6 Processes Stopped\n");

	int i;
	for(i=0;i<global_vars->static_routes_ip4.size;i++){
		net_info *adv_net = vector_get(&global_vars->static_routes_ip4,i);
		free(adv_net->forward);
		free(adv_net);
	}
	for(i=0;i<global_vars->static_routes_ip6.size;i++){
		net_info *adv_net = vector_get(&global_vars->static_routes_ip6,i);
		free(adv_net->forward);
		free(adv_net);
	}

	//Free global vars
	vector_free(&global_vars->static_routes_ip4);
	vector_free(&global_vars->static_routes_ip6);
	hash_collection col1;
	prepare_hashcollection(&col,global_vars->key_chains);
	key_chain *keychain;
	while ( (keychain=next(&col)) != NULL){
		prepare_hashcollection(&col1,keychain->keys);
		key *key;
		while ( (key=next(&col1)) != NULL){
			free(key);
		}
		hashtable_free(keychain->keys);
		free(keychain);
	}
	hashtable_free(global_vars->key_chains);
	free(global_vars);

	printf("Freed global varriables\n");

	prepare_hashcollection(&col,interfaces);
	while((iff=next(&col)) != NULL){
		post_shutdown_interface(iff);
	}
	hashtable_free(interfaces);
	printf("Interfaces Finilized\n");

	stop_interface_state_listener();
	pthread_cancel(interface_state_listener);
	pthread_detach(interface_state_listener);
	printf("Stopped interface state listener\n");

	stop_telnet();
	printf("Stopped Telnet\n");

	free_lists();
	printf("Configuration Options Finilized\n");

	printf("Shutting Down Eigrp Finished.\n");
	stop();
}

