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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "config.h"
#include "telnet.h"
#include "config_controller.h"
#include "eigrp_structs.h"
#include "utils.h"
#include "eigrp_base.h"
#include "packet_factory.h"
#include "eigrp_main.h"

#define TELNET_MODE 0
#define CONFIG_MODE 1
#define INPUT_MODE 2

static bool running;
static pthread_t telnet;
static telnet_client *telnet_c;

static struct telnet_info tinfo;
struct telnet_command command_list[] = {
	{1,"debug",0,true,false,},
	{2,"eigrp",1,true,false,},
	{4,"show",0,false,false,},
	{5,"ip",4,false,false,},
	{6,"eigrp",5,false,false,},
	{7,"interfaces",6,false,true,show_ip_eigrp_interfaces},
	{8,"neighbors",6,false,true,show_ip_eigrp_neighbors},
	{9,"traffic",6,false,true,show_ip_eigrp_traffic},
	{10,"topology",6,false,true,show_ip_eigrp_topology},
	{11,"key",4,true,false,},
	{12,"chain",11,true,true,show_key_chain},
	{14,"fsm",2,true,true,debug_eigrp_fsm},
	{15,"neighbors",2,true,true,debug_eigrp_neighbors},
	{16,"packets",2,true,true,debug_eigrp_packets},
	{17,"no",0,true,false,},
	{18,"debug",17,true,false,},
	{19,"eigrp",18,true,false,},
	{20,"fsm",19,true,true,no_debug_eigrp_fsm},
	{21,"neighbors",19,true,true,no_debug_eigrp_neighbors},
	{22,"packets",19,true,true,no_debug_eigrp_packets},
	{23,"configure",0,true,false,},
	{24,"terminal",23,true,true,configure_terminal},
	{25,"enable",0,false,true,enable},
	{26,"disable",0,true,true,disable}

};

static int mode = TELNET_MODE;
static bool authenticated = false;
static int (*input_function) (char *str, sbuffer *buffer);
static profile prof;

bool telnet_options_help(sbuffer *buffer, char *token, int lastcommand_id){

	if(token == NULL)return false;
	if(strlen(token) == 0)return false;
	
	char last = token[strlen(token)-1];
	if(last == '?'){
		char *search = strsep(&token,"?");

		struct telnet_command* ptr = command_list;
		struct telnet_command* endPtr = command_list + sizeof(command_list) /sizeof(command_list[0]);

		while(ptr < endPtr){
			if(ptr->parent == lastcommand_id 
			&& oneway_compare(search,ptr->name) && (!ptr->privilege || authenticated == ptr->privilege))
			{
				int i = sprintf(buffer->s, "%s ",ptr->name);
				bwrite(buffer,buffer->s,i);
			}
			ptr++;
		}

		bwrite(buffer,"\n",1);
		return true;

	}else{
		return false;
	}
}

int telnet_find_error_location(char *token, int lastcommand_id){
		int i;
		for(i=0;i<strlen(token);i++){

			struct telnet_command* ptr = command_list;
			struct telnet_command* endPtr = command_list + sizeof(command_list) /sizeof(command_list[0]);
			bool matched = false;
			while(ptr < endPtr){
				if(ptr->parent == lastcommand_id 
				&& strncmp(token,ptr->name,i+1)==0)
				{
					matched = true;
				}
				ptr++;
			}
			if(!matched)break;
		}
		
		return i;
}

void handle_command(const char *b, int len){
	char *token;
	char *hostname = get_running_config()->hostname;
	//Do not copy the last 2 character as they are part of telnet and not the actual command
	char *line = malloc(len);
	char *original_pointer = line;
	memcpy(line,b,len);
	line[len-2] = 0;

	//Buffer for the message returned	
	sbuffer buffer;
	init_sbuffer(&buffer);

	if(mode == TELNET_MODE){

		//Parse line from here
		bool endcommand = false;
		struct telnet_command *last_command = NULL;
		bool duplicate = false;
		int lastcommand_id = 0; //root
		bool error =false;
		int error_loc = 0;
		bool help_called = false;
		do{
			token = strsep(&line," ");

			if(telnet_options_help(&buffer, token, lastcommand_id)){
				help_called = true;
				break;
			}
		
			struct telnet_command *tmp = NULL;
			struct telnet_command* ptr = command_list;
			struct telnet_command* endPtr = command_list + sizeof(command_list)/sizeof(command_list[0]);

			while(ptr < endPtr){
				if(ptr->parent == lastcommand_id 
				&& oneway_compare(token,ptr->name))
				{
					if(tmp != NULL){
						duplicate = true;
					}
				
					tmp = ptr;
				}
				ptr++;
			}

			//Ambiguous command
			if(duplicate)break;

			//After scanning all commands
			if(tmp != NULL){
				if(tmp->end){
					endcommand = true;
				}
				last_command = tmp;
				lastcommand_id = tmp->code;
			}else{
				error = true;
				error_loc += telnet_find_error_location(token,lastcommand_id);
				break;		
			}

			if(token != NULL){
				error_loc += strlen(token) + 1;
			}

			if(line == NULL)break;
	
		}while(!endcommand);


		if(help_called){
			//Do nothing, just prevent it from being shown as an error
		}else if(duplicate){
			int n = sprintf(buffer.s,"%% Ambiguous command: \"%s\"\n",original_pointer);
			bwrite(&buffer,buffer.s,n);
		}else if(last_command != NULL && last_command->end){
			if(last_command->execute == NULL){
				printf("Error:Function not assigned for command id %d\n", last_command->code);				
			}else
				last_command->execute(line,&buffer);
		}else{
			//Point out there the error is
			if(last_command == NULL){
				text_arrowpointer(&buffer,strlen(hostname)+1+error_loc);
				bwrite(&buffer, "%% Invalid input detected at '^' marker.\n", 41);
			}else if(error){
				text_arrowpointer(&buffer,strlen(hostname)+1+error_loc);
				bwrite(&buffer, "%% Invalid input detected at '^' marker.\n", 41);
			}else if(!last_command->end){
				bwrite(&buffer,"%% Incomplete command.\n",23);
			}else{
				//Should never reach here, but will be left to catch other errors
				text_arrowpointer(&buffer,strlen(hostname)+1+error_loc);
				bwrite(&buffer, "%% Invalid input detected at '^' marker.\n", 41);
			}
		}

	}else if(mode == INPUT_MODE){
		int res = input_function(line,&buffer);
		if(res < 0)printf("INPUT_FUNCTION retruned error code %d\n",res);

	}else{ //CONFIGURATION MODE
		int res = config_telnet(line, &prof, &buffer);
		if(res == END_CODE) mode = TELNET_MODE;

	}

	//Append newline+router name at the end
	if(mode == TELNET_MODE){
		bwrite(&buffer, hostname,strlen(hostname));
		authenticated ? bwrite(&buffer,"#",1) : bwrite(&buffer,">",1);
	}
	
	
	//Send the response to the client
	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);

	//Free the allocated memory (the line pointer get moved to end)
	free(original_pointer);
}

//Line Preparing
void show_ip_eigrp_interfaces_print(sbuffer *buffer, struct eigrp_proccess *proc){
	int n = sprintf(buffer->s,"IP-EIGRP Interfaces for process %d\n\n\t\t\tXmit Queue\tMean\tPacing Time\tMulticast\tPending\nInterfaces\tPeers\tUn/Reeliable\tSRTT\tUn/Reliable\tFlow Timer\tRoutes\n", proc->proccess_id);
	bwrite(buffer,buffer->s,n);

	hash_collection col;
	prepare_hashcollection(&col,get_interfaces());
	interface *iff;
	while( (iff=next(&col)) != NULL){
		//Finding peers
		int peers =0;
		hash_collection col1;
		prepare_hashcollection(&col1,proc->neighbours);
		neighbour *n;
		while( (n = next(&col1)) != NULL){
			if(iff->index == n->interface->index)peers++;
		}
		//Xmit Queues
		int reliable_packets = proc->multicast_queue.size;
		int k = sprintf(buffer->s,"%s\t\t%d\t\t%d/%d\t%d\t\t%d/%d\t%d\t\t%d\n",iff->name,peers,0,reliable_packets,1234,0,10,0,0);
		bwrite(buffer,buffer->s,k);
	}
}

void show_ip_eigrp_neighbors_print(sbuffer *buffer, struct eigrp_proccess *proc){
	int i = sprintf(buffer->s,"IP-EIGRP Neighbors for process %d\n\nAddress\t\tInterface\tHoldtime\tUptime\tQ\tSeq\tSRTT\tRTO\n\t\t\t\t(secs)\t\t(h:m:s)\tCount\tNum\t(ms)\t(ms)\n",proc->proccess_id);
	bwrite(buffer,buffer->s,i);
	hash_collection col;
	prepare_hashcollection(&col,proc->neighbours);
	neighbour *n;
	while( (n=next(&col)) != NULL){
		char time[9];
		time_format(&time,current_timestamp()-n->discovery_time);
		char address[INET6_ADDRSTRLEN];
		ip_tochar(&address,&n->address);
		int k = sprintf(buffer->s,"%s\t%s\t\t%lld\t\t%s\t%d\t%d\t%lld\t%d\n",address,n->interface->name,n->holdtime/1000,time,n->packet_queue.size,n->pending_ack,n->srtt%1000,0);
		bwrite(buffer,buffer->s,k);
	}
}

void show_ip_eigrp_traffic_print(sbuffer *buffer, struct eigrp_proccess *proc){
	int i = snprintf(buffer->s,sizeof(buffer->s),
		"IP-EIGRP Traffic Statistics for process %d\n"
		"  Hellos sent/received: %d/%d\n"
		"  Updates sent/received: %d/%d\n"
		"  Queries sent/received: %d/%d\n"
		"  Replies sent/received: %d/%d\n"
		"  Acks sent/received: %d/%d\n"
		"  SIA-Queries sent/received: %d/%d\n"
		"  SIA-Replies sent/received: %d/%d\n"
		,proc->proccess_id,
		proc->stats.packets_sent[OPCODE_HELLO],proc->stats.packets_received[OPCODE_HELLO],
		proc->stats.packets_sent[OPCODE_UPDATE],proc->stats.packets_received[OPCODE_UPDATE],
		proc->stats.packets_sent[OPCODE_QUERY],proc->stats.packets_received[OPCODE_QUERY],
		proc->stats.packets_sent[OPCODE_REPLY],proc->stats.packets_received[OPCODE_REPLY],
		proc->stats.acks_sent,proc->stats.acks_received,
		proc->stats.packets_sent[OPCODE_SIAQUERY],proc->stats.packets_received[OPCODE_SIAQUERY],
		proc->stats.packets_sent[OPCODE_SIAREPLY],proc->stats.packets_received[OPCODE_SIAREPLY]
			);
	bwrite(buffer,buffer->s,i);
	
}

void show_ip_eigrp_topology_print(sbuffer *buffer, struct eigrp_proccess *proc){
	int i = sprintf(buffer->s,
	"IP-EIGRP Topology Table for process %d\n\n"
	"Codes: P - Passive, A - Active, U - Update, Q - Query, R - Reply,\n"
	"\tr - Reply status\n\n",proc->proccess_id);
	bwrite(buffer,buffer->s,i);

	//Network
	hash_collection col;
	prepare_hashcollection(&col,proc->topology_support);
	struct topology_support* support;
	while((support=next(&col)) != NULL){
		//Prefix
		struct topology_route *tr;
		hash_collection col2;
		prepare_hashcollection(&col2,support->topology_route);

		while((tr=next(&col2)) != NULL){
			char *code = (tr->route_state == PASSIVE_STATE ? "P" : "A");
			int successors = count_feasible_successors(tr,tr->successor->is_external);
			char address[INET6_ADDRSTRLEN];
			ip_tochar(&address,&tr->dest);
			int k = sprintf(buffer->s,"%s %s/%d, %d successors, FD is %d\n", code, address, tr->prefix, successors, tr->feasible_distance);
			bwrite(buffer,buffer->s,k);
			for(i=0;i<tr->routes.size;i++){
				route *r = vector_get(&tr->routes,i);
				if(tr->successor->is_external != r->is_external)continue;
				if(r->reported_distance > tr->successor->feasible_distance && tr->route_state == PASSIVE_STATE)continue;
				if(r->is_proccess_generated){
					k = sprintf(buffer->s,"\tvia Connected, %s\n", r->sender->interface->name);
					bwrite(buffer,buffer->s,k);
				}else{
					ip_tochar(&address,&r->sender->address);
					if(tr->route_state == PASSIVE_STATE){
						if(r->delay == EIGRP_UNREACHABLE || r->bandwidth == 0)continue;
						k = sprintf(buffer->s,"\tvia %s (%d/%d), %s\n", address, r->feasible_distance, r->reported_distance, r->sender->interface->name);
						bwrite(buffer,buffer->s,k);
					}else{
						k = sprintf(buffer->s,"\tvia %s (%d/%d), %s", address, r->feasible_distance, r->reported_distance, r->sender->interface->name);
						bwrite(buffer,buffer->s,k);
						if(r->rijk == 1){
							k = sprintf(buffer->s,", r");
							bwrite(buffer,buffer->s,k);
						}
						k = sprintf(buffer->s,"\n");
						bwrite(buffer,buffer->s,k);
					}					
					
				}
			}
		}
	}
}

void show_key_chain_print(sbuffer *buffer, key_chain *chain){
	int i = sprintf(buffer->s, "Key-chain %s:\n",chain->name);
	bwrite(buffer,buffer->s,i);

	hash_collection col;
	prepare_hashcollection(&col,chain->keys);
	key *k;
	while( (k=next(&col)) != NULL){
		i = sprintf(buffer->s, "\tkey %ld -- text \"%s\"\n"
		"\t\taccept lifetime (always valid) - (always valid) [valid now]\n"
		"\t\tsend lifetime (always valid) - (always valid) [valid now]\n"
		, k->indentifier,k->password);
		bwrite(buffer,buffer->s,i);
	}
}

//Direct Commands
void show_ip_eigrp_topology(char *line, sbuffer *buffer){
	char *token;
	token = strsep(&line," ");

	if(token == NULL){
		hash_collection col;
		prepare_hashcollection(&col,get_proccesses(AF_INET));
		struct eigrp_proccess *proc;
		while( (proc=next(&col)) != NULL){
			show_ip_eigrp_topology_print(buffer,proc);
		}
	}
	if(token){
		//Show topology for specific proccess
		int ret = strtol(token,0,10);
		if(ret != 0){
			struct eigrp_proccess *proc = get_eigrp_proccess(ret,AF_INET);
			if(proc != NULL){
				show_ip_eigrp_topology_print(buffer,proc);
			}
		}
	}
}

void show_ip_eigrp_neighbors(char *line, sbuffer *buffer){
	char *token;
	token = strsep(&line," ");

	if(token == NULL){
		hash_collection col;
		prepare_hashcollection(&col,get_proccesses(AF_INET));
		struct eigrp_proccess *proc;
		while( (proc=next(&col)) != NULL){
			show_ip_eigrp_neighbors_print(buffer,proc);
		}
	}
	if(token){
		//Show neighbors for specific proccess
		int ret = strtol(token,0,10);
		if(ret != 0){
			struct eigrp_proccess *proc = get_eigrp_proccess(ret,AF_INET);
			if(proc != NULL){
				show_ip_eigrp_neighbors_print(buffer,proc);
			}
		}
	}
}

void show_ip_eigrp_interfaces(char *line, sbuffer *buffer){
	char *token;
	token = strsep(&line," ");

	if(token == NULL){
		hash_collection col;
		prepare_hashcollection(&col,get_proccesses(AF_INET));
		struct eigrp_proccess *proc;
		while( (proc=next(&col)) != NULL){
			show_ip_eigrp_interfaces_print(buffer,proc);
		}
	}
	if(token){
		//Show interfaces for specific proccess
		int ret = strtol(token,0,10);
		if(ret != 0){
			struct eigrp_proccess *proc = get_eigrp_proccess(ret,AF_INET);
			if(proc != NULL){
				show_ip_eigrp_interfaces_print(buffer,proc);
			}
		}
	}
}

void show_ip_eigrp_traffic(char *line, sbuffer *buffer){
	char *token;
	token = strsep(&line," ");

	if(token == NULL){
		hash_collection col;
		prepare_hashcollection(&col,get_proccesses(AF_INET));
		struct eigrp_proccess *proc;
		while( (proc=next(&col)) != NULL){
			show_ip_eigrp_traffic_print(buffer,proc);
		}
	}
	if(token){
		//Show traffic for specific proccess
		int ret = strtol(token,0,10);
		if(ret != 0){
			struct eigrp_proccess *proc = get_eigrp_proccess(ret,AF_INET);
			if(proc != NULL){
				show_ip_eigrp_traffic_print(buffer,proc);
			}
		}
	}
}

void show_key_chain(char *line, sbuffer *buffer){
	char *token;
	token = strsep(&line," ");

	if(token == NULL){
		hash_collection col;
		prepare_hashcollection(&col,get_global_vars()->key_chains);
		key_chain *chain;
		while( (chain=next(&col)) != NULL){
			show_key_chain_print(buffer,chain);
		}
	}
	if(token){
		key_chain *chain = get_key_chain(token);
		//Show key chain for specific proccess
		if(chain != NULL){
			show_key_chain_print(buffer,chain);
		}
	}
}

void debug_eigrp_fsm(char *line, sbuffer *buffer){
	tinfo.debug.fsm = true;
	int n = sprintf(buffer->s,"EIGRP FSM Events/Action debugging is on\n");
	bwrite(buffer,buffer->s,n);
}

void debug_eigrp_neighbors(char *line, sbuffer *buffer){
	tinfo.debug.neighbors = true;
	int n = sprintf(buffer->s,"EIGRP Neighbors debugging is on\n");
	bwrite(buffer,buffer->s,n);
}

void debug_eigrp_packets(char *line, sbuffer *buffer){
	tinfo.debug.packets = true;
	int n = sprintf(buffer->s,"EIGRP Packets debugging is on\n");
	bwrite(buffer,buffer->s,n);
}

void no_debug_eigrp_fsm(char *line, sbuffer *buffer){
	tinfo.debug.fsm = false;
	int n = sprintf(buffer->s,"EIGRP FSM Events/Action debugging is off\n");
	bwrite(buffer,buffer->s,n);
}

void no_debug_eigrp_neighbors(char *line, sbuffer *buffer){
	tinfo.debug.neighbors = false;
	int n = sprintf(buffer->s,"EIGRP Neighbors debugging is off\n");
	bwrite(buffer,buffer->s,n);
}

void no_debug_eigrp_packets(char *line, sbuffer *buffer){
	tinfo.debug.packets = false;
	int n = sprintf(buffer->s,"EIGRP Packets debugging is off\n");
	bwrite(buffer,buffer->s,n);
}

void configure_terminal(char *line, sbuffer *buffer){
	memset(&prof,0,sizeof(profile));
	mode = CONFIG_MODE;
	int n = sprintf(buffer->s,"Enter configuration commands, one per line.\n%s(config)#",get_running_config()->hostname);
	bwrite(buffer,buffer->s,n);
}
void enable(char *line, sbuffer *buffer){

	if(get_running_config()->password == NULL){
		authenticated = true;
		return;
	}

	int n = sprintf(buffer->s,"Password: ");
	bwrite(buffer,buffer->s,n);

	mode = INPUT_MODE;
	input_function = enable_password_input;
}

void disable(char *line, sbuffer *buffer){
	authenticated = false;
}

int enable_password_input(char *line, sbuffer *buffer){
	char *encrypted_password = get_running_config()->password;

	char *salt_end = strrchr(encrypted_password,'$');
	int len = salt_end - encrypted_password + 1;

	char *salt = malloc(len);
	memcpy(salt,encrypted_password,len);

	char *result = crypt(line,salt);
	free(salt);

	if(equals(result, get_running_config()->password)){
		authenticated = true;
		mode = TELNET_MODE;
		return 0;
	}else{
		int n = sprintf(buffer->s,"Password: ");
		bwrite(buffer,buffer->s,n);
		return 0;
	}
}

//DEBUGGING COMMANDS
void dual_nbrchange(struct eigrp_proccess *proc, neighbour *n,bool active, char *msg){

	if(!tinfo.connected)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char address[INET6_ADDRSTRLEN];
	char timestamp[20];
	char *activestr;

	ip_tochar(&address,&n->address);
	str_now(&timestamp);
	activestr = (active ? "up" : "down" );

	int i = sprintf(buffer.s,"\n%s: DUAL-5-NBRCHANGE: IP-EIGRP(0) %u: Neighbor %s (%s) is %s: %s",timestamp, proc->proccess_id,address,n->interface->name,activestr,msg);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);

}

void topology_search(struct topology_route *tr){
	if(!tinfo.connected)return;
	if(!tinfo.debug.fsm)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char address[INET6_ADDRSTRLEN];
	char timestamp[20];

	ip_tochar(&address,&tr->dest);
	str_now(&timestamp);

	char *active = (tr->route_state == PASSIVE_STATE ? "not " : "");
	int i = sprintf(buffer.s,"\n%s: DUAL: dest(%s) %sactive",timestamp,address,active);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);
}

void packet_handling(char *state,route *r){
	if(!tinfo.connected)return;
	if(!tinfo.debug.fsm)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char route_address[INET6_ADDRSTRLEN];
	char neighbor_address[INET6_ADDRSTRLEN];
	char timestamp[20];

	ip_tochar(&route_address,&r->dest);
	ip_tochar(&neighbor_address,&r->sender->address);
	str_now(&timestamp);

	int i = sprintf(buffer.s,"\n%s: DUAL: %s: %s via %s metric %u/%u",timestamp, state, route_address,neighbor_address,r->reported_distance,r->feasible_distance);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);
}

void telnet_find_fs(struct topology_route *tr, route *successor){
	if(!tinfo.connected)return;
	if(!tinfo.debug.fsm)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char route_address[INET6_ADDRSTRLEN];
	char neighbor_address[INET6_ADDRSTRLEN];
	char timestamp[20];
	int feasible_distance;
	int reported_distance;

	if(successor != NULL){
		feasible_distance = successor->feasible_distance;
		reported_distance = successor->reported_distance;
	}else{
		feasible_distance = EIGRP_UNREACHABLE;
		reported_distance = EIGRP_UNREACHABLE;
	}

	ip_tochar(&route_address,&tr->dest);
	str_now(&timestamp);

	int i = sprintf(buffer.s,"\n%s: DUAL: Find FS for dest %s/%d. FD is %u, RD is %u",timestamp, route_address,tr->prefix,feasible_distance,reported_distance);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);

	sbuffer buffer2;
	init_sbuffer(&buffer2);

	int k;
	for(i=0;i<tr->routes.size;i++){
		route *r = vector_get(&tr->routes,i);
				
		ip_tochar(&neighbor_address,&r->sender->address);
		k = sprintf(buffer2.s,"\n%s: DUAL:     %s metric %u/%u",timestamp, neighbor_address,r->feasible_distance,r->reported_distance);
		bwrite(&buffer2,buffer2.s,k);
			
	}

	telnet_printf(telnet_c->client,buffer2.buffer,buffer2.len);
}

void telnet_install_route(route *r){
	if(!tinfo.connected)return;
	if(!tinfo.debug.fsm)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char route_address[INET6_ADDRSTRLEN];
	char neighbor_address[INET6_ADDRSTRLEN];
	char timestamp[20];

	ip_tochar(&route_address,&r->dest);
	ip_tochar(&neighbor_address,&r->sender->address);
	str_now(&timestamp);

	int i = sprintf(buffer.s,"\n%s: DUAL: RT installed %s/%d via %s",timestamp, route_address,r->prefix,neighbor_address);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);
}

void telnet_route_active(struct topology_route *tr){
	if(!tinfo.connected)return;
	if(!tinfo.debug.fsm)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char route_address[INET6_ADDRSTRLEN];
	char timestamp[20];
	ip_tochar(&route_address,&tr->dest);
	str_now(&timestamp);


	int i = sprintf(buffer.s,"\n%s: DUAL: Dest %s/%d entering active state",timestamp, route_address,tr->prefix);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);
}

void telnet_reply_count(int count){
	if(!tinfo.connected)return;
	if(!tinfo.debug.fsm)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char timestamp[20];
	str_now(&timestamp);	

	int i = sprintf(buffer.s,"\n%s: DUAL: reply count is %u",timestamp, count);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);

}

void telnet_all_replies_received(struct topology_route *tr){
	if(!tinfo.connected)return;
	if(!tinfo.debug.fsm)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char timestamp[20];
	str_now(&timestamp);
	char route_address[INET6_ADDRSTRLEN];
	ip_tochar(&route_address,&tr->dest);

	int i = sprintf(buffer.s,"\n%s: DUAL: All replies received for %s/%d",timestamp, route_address, tr->prefix);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);
}

void telnet_remove_successor(route *r){
	if(!tinfo.connected)return;
	if(!tinfo.debug.fsm)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char timestamp[20];
	str_now(&timestamp);
	char route_address[INET6_ADDRSTRLEN];
	ip_tochar(&route_address,&r->dest);
	char neighbor_address[INET6_ADDRSTRLEN];
	ip_tochar(&neighbor_address,&r->sender->address);

	int i = sprintf(buffer.s,"\n%s: DUAL: Removing dest %s/%d, nexthop %s",timestamp, route_address, r->prefix, neighbor_address);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);
}

void telnet_no_routes(struct topology_route *tr){
	if(!tinfo.connected)return;
	if(!tinfo.debug.fsm)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char timestamp[20];
	str_now(&timestamp);
	char route_address[INET6_ADDRSTRLEN];
	ip_tochar(&route_address,&tr->dest);

	int i = sprintf(buffer.s,"\n%s: DUAL: No routes. Flushing dest %s/%d",timestamp, route_address, tr->prefix);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);
}

void telnet_dest_state_change(struct topology_route *tr, int new_state){
	if(!tinfo.connected)return;
	if(!tinfo.debug.fsm)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char timestamp[20];
	str_now(&timestamp);

	int i = sprintf(buffer.s,"\n%s: DUAL: Going from state %d to %d",timestamp, tr->ioj, new_state);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);
}

void telnet_neighbour_down(neighbour *n){
	if(!tinfo.connected)return;
	if(!tinfo.debug.neighbors)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char timestamp[20];
	str_now(&timestamp);
	char neighbor_address[INET6_ADDRSTRLEN];
	ip_tochar(&neighbor_address,&n->address);


	int i = sprintf(buffer.s,"\n%s: EIGRP: Neighbor %s went down on %s",timestamp, neighbor_address, n->interface->name);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);
}

void telnet_new_peer(neighbour *n){
	if(!tinfo.connected)return;
	if(!tinfo.debug.neighbors)return;

	sbuffer buffer;
	init_sbuffer(&buffer);

	char timestamp[20];
	str_now(&timestamp);
	char neighbor_address[INET6_ADDRSTRLEN];
	ip_tochar(&neighbor_address,&n->address);


	int i = sprintf(buffer.s,"\n%s: EIGRP: New peer %s",timestamp, neighbor_address);
	bwrite(&buffer,buffer.s,i);

	telnet_printf(telnet_c->client,buffer.buffer,buffer.len);
}

//Telnet Functions

void stop_telnet(){
	running = false;
	tinfo.connected = false;
	pthread_join(telnet,NULL);
}

static void _send(int sock, const char *buffer, size_t size){
	int rs;
	while(size > 0){
		if((rs = send(sock,buffer,size,0)) == -1){
			if(errno != EINTR && errno != ECONNRESET){
				printf("send() failed:%s\n",strerror(errno));
			} else{
				return;
			}
		}else if(rs==0){
			printf("send() unexpectedly returned 0\n");
		}
		buffer += rs;
		size -= rs;
	}
}

void telnet_event_handler(telnet_t *telnet, telnet_event_t *ev, void *user_data){
	//telnet_client *user = (telnet_client*)user_data;

	switch(ev->type){
		case TELNET_EV_DATA:
			handle_command(ev->data.buffer, ev->data.size);
			break;
		case TELNET_EV_SEND:
			_send(telnet_c->sock, ev->data.buffer, ev->data.size);
			break;
		case TELNET_EV_IAC:
		case TELNET_EV_WILL:
		case TELNET_EV_WONT:
		case TELNET_EV_DO:
		case TELNET_EV_DONT:
		case TELNET_EV_SUBNEGOTIATION:
		case TELNET_EV_COMPRESS:
		case TELNET_EV_ZMP:
		case TELNET_EV_TTYPE:
		case TELNET_EV_ENVIRON:
		case TELNET_EV_MSSP:
		case TELNET_EV_WARNING:
		case TELNET_EV_ERROR:
			break;
		
	}
}

int init_telnet_server(){
	int ret;

	ret = pthread_create(&telnet,NULL ,telnet_thread ,NULL);
	if(ret){
		printf("ERROR:Error starting telnet.\n");
	}

	return 0;
}

void *telnet_thread(void *ptr){

	int rs;
	int listen_sock;
	char buffer[512];
	socklen_t addrlen;
	struct sockaddr_in addr;
	struct pollfd pfd1[1];
	memset(&tinfo,0,sizeof(struct telnet_info));

	running = true;

	static const telnet_telopt_t my_telopts[] = {
		{ TELNET_TELOPT_ECHO,      TELNET_WILL, TELNET_DO },
		{ -1, 0, 0 }
	};

	while(running){

		tinfo.authed = false;		
		if((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
			printf("Error creating telnet.\n");
			return NULL;
		}

		rs = 1;
		setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (void*)&rs, sizeof(rs));

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(get_telnet_port());

		if(bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1){
			printf("ERR: Could not bind socket.\n");
			return NULL;
		}

		if(listen(listen_sock, 1) == -1){
			printf("Error listening.\n");
			return NULL;
		}

		memset(pfd1, 0,sizeof(pfd1));
		pfd1[0].fd = listen_sock;
		pfd1[0].events = POLLIN;
		addrlen = sizeof(addr);
		
		telnet_c = malloc(sizeof(telnet_client));

		while(poll(pfd1,1,100) != -1 && running){
			if(pfd1[0].revents & POLLIN){
				if((telnet_c->sock = accept(listen_sock, (struct sockaddr*)&addr, &addrlen)) == -1){
					printf("Error accept().\n");
					return NULL;
				}else{
					break;
				}
			}
		}

		if(!running)break;
		
		printf("TELNET CONNECTION RECEIVED.\n");
		authenticated = false;
		close(listen_sock);

		telnet_c->client = telnet_init(my_telopts,telnet_event_handler,0,telnet_c);
		tinfo.connected = true;
		
		sbuffer b;
		init_sbuffer(&b);
		char *hostname = get_running_config()->hostname;
		bwrite(&b, hostname,strlen(hostname));
		tinfo.authed ? bwrite(&b,"#",1) : bwrite(&b,">",1);
		telnet_printf(telnet_c->client,b.buffer,b.len);

		struct pollfd pfd;
		memset(&pfd, 0,sizeof(struct pollfd));
		pfd.fd = telnet_c->sock;
		pfd.events = POLLIN;// | POLLHUP | POLLRDNORM;
		char buff[10]; // Just to pass as paramters doesn't get used

		while(running){
			poll(&pfd,1,100);

			if(recv(telnet_c->sock,buff,10, MSG_PEEK | MSG_DONTWAIT) == 0){
				printf("TELNET CLIENT DISCONNECTED\n");
				break;
			}
			if(pfd.revents & POLLIN){
				if((rs =recv(telnet_c->sock, buffer, sizeof(buffer),0)) > 0){
					telnet_recv(telnet_c->client, buffer, rs);
				}

			}
			
		}

		/*while(pfd.revents == 0 && running){
			if(poll(&pfd,1,100) > 0){
				if(recv(telnet_c->sock,buff,10, MSG_PEEK | MSG_DONTWAIT) == 0){
					printf("TELNET CLIENT DISCONNECTED\n");
					break;
				}

				if((rs =recv(telnet_c->sock, buffer, sizeof(buffer),0)) > 0){
					telnet_recv(telnet_c->client, buffer, rs);
				}

			}

			
		}*/
		tinfo.connected = false;
		telnet_free(telnet_c->client);
		close(telnet_c->sock);


	}

	free(telnet_c);

	return NULL;

}
