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

#include "eigrp_structs.h"
#include "collection.h"

struct eigrp_proccess *get_eigrp_proccess(int id,int family);
interface *get_interface(int index);
hash_table_t *get_interfaces();
hash_table_t *get_proccesses(int family);
route *get_route(route *r, neighbour *n);
key_chain *get_key_chain(char *name);
bool is_ready();
int count_feasible_successors(struct topology_route *tr,bool external);
route *unreachable_route(struct sockaddr_storage dest,int prefix,neighbour *n,bool external);
struct topology_route* get_topology_network(struct eigrp_proccess* proc, struct sockaddr_storage dest,int prefix);
bool topology_route_exists(struct eigrp_proccess* proc, struct sockaddr_storage *dest,int prefix);
bool handle_route_changes(route *new_route, int opcode, struct eigrp_proccess *proc);
bool add_route_record(struct topology_route* tr, route *new_route, struct eigrp_proccess *proc);
void remove_route_record(struct topology_route* tr, route *remove);
void calculate_changes_if_needed(struct eigrp_proccess* proc);
void remove_and_recalculate_routes(neighbour *n);
bool packet_queues_empty(struct eigrp_proccess *proc);
unsigned long calculate_classic_metric(struct eigrp_proccess *proc,unsigned int bandwidth,int delay,int mtu ,int load,int rel);
void calculate_classic_route_metric(struct eigrp_proccess *proc, route *newroute);
bool all_end_of_table_received(struct eigrp_proccess *proc);
void init_calculate_routes(struct eigrp_proccess *proc);
int get_socket_mtu(int socket,int family,char *name);
void interface_up(int index);
void interface_down(int index);
void set_route_to_active(struct topology_route *tr, int flag, route *r);
void *stuck_in_active(void *ptr);
void proccess_active_state_route(struct topology_route *tr);
globals *get_global_vars();
void pre_init();
void post_init();
//INIT FUNCTIONS
int re_init_interface(interface *iff);
void init_interfaces_hashtable();
int init_telnet_server();
void init_proccess_hashtable(int num_ip4, int num_ip6);
void init_interface_vector();
int init_interface(iff_info *info);
int init_keychain(keychain_info *info);
int init_eigrp_proccess(proccess *proc,int family);
void start_interface_state_listener();

bool is_initialized_eigrp(int i, int family);
void shutdown_eigrp(void);
void free_neighbour(neighbour *n, char *reason);

//TEST FUNCTION
void send_query();
