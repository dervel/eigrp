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
#include "utils.h"

struct telnet_command{
	int code;
	char name[20];
	int parent;
	bool privilege;
	bool end;
	void (*execute) (char *token, sbuffer *buffer);
};

struct debug_info{
	bool fsm;
	bool neighbors;
	bool nsf;
	bool packets;
	bool transmit;
};

struct telnet_info{
	bool authed;
	bool connected;
	struct debug_info debug; 
};
//DUAL MESSAGES
void dual_nbrchange(struct eigrp_proccess *proc, neighbour *n,bool active, char *msg);
void topology_search(struct topology_route *tr);
void packet_handling(char *state,route *r);
void telnet_find_fs(struct topology_route *tr, route *successor);
void telnet_install_route(route *r);
void telnet_route_active(struct topology_route *tr);
void telnet_reply_count(int count);
void telnet_all_replies_received(struct topology_route *tr);
void telnet_remove_successor(route *r);
void telnet_no_routes(struct topology_route *tr);
void telnet_dest_state_change(struct topology_route *tr, int new_state);
void telnet_neighbour_down(neighbour *n);
void telnet_new_peer(neighbour *n);

//New
void handle_command(const char *b, int len);

void show_ip_eigrp_topology(char *line, sbuffer *buffer);
void show_ip_eigrp_neighbors(char *line, sbuffer *buffer);
void show_ip_eigrp_interfaces(char *line, sbuffer *buffer);
void show_ip_eigrp_traffic(char *line, sbuffer *buffer);
void show_key_chain(char *line, sbuffer *buffer);
void debug_eigrp_fsm(char *line, sbuffer *buffer);
void debug_eigrp_neighbors(char *line, sbuffer *buffer);
void debug_eigrp_packets(char *line, sbuffer *buffer);
void no_debug_eigrp_fsm(char *line, sbuffer *buffer);
void no_debug_eigrp_neighbors(char *line, sbuffer *buffer);
void no_debug_eigrp_packets(char *line, sbuffer *buffer);
void configure_terminal(char *line, sbuffer *buffer);
void enable(char *line, sbuffer *buffer);
void disable(char *line, sbuffer *buffer);
int enable_password_input(char *line, sbuffer *buffer);

void show_ip_eigrp_interfaces_print(sbuffer *buffer, struct eigrp_proccess *proc);
void show_ip_eigrp_neighbors_print(sbuffer *buffer, struct eigrp_proccess *proc);
void show_ip_eigrp_traffic_print(sbuffer *buffer, struct eigrp_proccess *proc);
void show_ip_eigrp_topology_print(sbuffer *buffer, struct eigrp_proccess *proc);
void show_key_chain_print(sbuffer *buffer, key_chain *chain);
//

void telnet_event_handler(telnet_t *telnet, telnet_event_t *ev, void *user_data);
int init_telnet_server();
void *telnet_thread(void *ptr);
void stop_telnet();
