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
//#define _XOPEN_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <limits.h>
#include <arpa/inet.h>

#include "config.h"
#include "eigrp_structs.h"
#include "config_controller.h"
#include "eigrp_base.h"
#include "hashtable.h"
#include "vector.h"
#include "collection.h"
#include "utils.h"

static struct config running_config;

struct config *get_running_config(){
	return &running_config;
}

static struct sub_command global_node[] = {
	{1,"interface",0,true,interface_com},
	{2,"router",0,false,},
	{3,"eigrp",2,true,router_eigrp_com},
	{4,"key",0,false,},
	{5,"chain",4,true,key_chain_com},
	{6,"end",0,true,end_com}
};

static struct sub_command root_node[] = {
	{1,"hostname",0,true,hostname_com},
	{2,"ip",0,false,},
	{3,"route",2,true,ip_route_com},
	{4,"enable",0,false,},
	{5,"secret",4,true,enable_secret_com},

	//These are duplicates of the global node they don't conflict.
	//They are placed here so they are being seen when using '?' at root node
	{100,"interface",0,true,interface_com},
	{101,"router",0,false,},
	{102,"eigrp",101,true,router_eigrp_com},
	{103,"key",0,false,},
	{104,"chain",103,true,key_chain_com},
	{105,"end",0,true,end_com}
};

static struct sub_command interface_node[] = {
	{1,"bandwidth",0,true,interface_bandwidth_com},
	{2,"delay",0,true,interface_delay_com},
	{3,"ip",0,false,},
	{4,"authentication",3,false,},
	{5,"mode",4,false,},
	{6,"eigrp",5,true,interface_auth_mode_com},
	{7,"key-chain",4,false,},
	{8,"eigrp",7,true,interface_auth_keychain_com},
	{9,"exit",0,true,exit_com}
};

static struct sub_command keychain_node[] = {
	{1,"key",0,true,key_com},
	{2,"exit",0,true,exit_com}
};

static struct sub_command key_node[] = {
	{1,"key-string",0,true,key_keystring_com},
	{2,"exit",0,true,key_exit_com}
};

static struct sub_command routereigrp_node[] = {
	{1,"redistribute",0,false,},
	{2,"static",1,true,eigrprouter_redistribute_static_com},
	{3,"network",0,true,eigrprouter_network_com},
	{4,"passive-interface",0,true,eigrprouter_passiveinterface_com},
	{5,"traffic-share",0,false,},
	{6,"balanced",5,true,eigrprouter_trafficbalanced_com},
	{7,"min",5,false,},
	{8,"across-interfaces",7,true,eigrprouter_trafficmin_com},
	{9,"variance",0,true,eigrprouter_variance_com},
	{10,"mertic",0,false,},
	{11,"weights",10,true,eigrprouter_metricweights_com},
	{12,"exit",0,true,exit_com}
};

int config_controller_init(){

	//Initialize the struct to hold the config
	memset(&running_config,0,sizeof(struct config));
	
	running_config.proccess_list_ip4 = create_hash_table(30);
	running_config.proccess_list_ip6 = create_hash_table(30);
	running_config.interface_list = create_hash_table(30);
	running_config.keychain_list = create_hash_table(10);
	init_interfaces_hashtable(); //Calls function from eigrp_base.c

	running_config.hostname = "Router";
	running_config.password = NULL;

	

	return 0;
}

proccess *get_proccess_info(int id, int family){
	if(family == AF_INET)
		return hashtable_getitem(running_config.proccess_list_ip4,id);
	else if(family == AF_INET6)
		return hashtable_getitem(running_config.proccess_list_ip6,id);
	else
		return NULL;
}

iff_info *get_interface_info(int index){
	return hashtable_getitem(running_config.interface_list,index);
}

bool options_help(sbuffer *buffer, char *token, int lastcommand_id, struct sub_command *active, unsigned long size){

	if(token == NULL)return false;
	if(strlen(token) == 0)return false;
	
	char last = token[strlen(token)-1];
	if(last == '?'){
		char *search = strsep(&token,"?");

		struct sub_command* ptr = active;
		struct sub_command* endPtr = active + size /sizeof(active[0]);

		while(ptr < endPtr){
			if(ptr->parent == lastcommand_id 
			&& oneway_compare(search,ptr->name))
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

int find_error_location(char *token, int lastcommand_id,struct sub_command *active, unsigned long size){
		int i;
		for(i=0;i<strlen(token);i++){

			struct sub_command* ptr = active;
			struct sub_command* endPtr = active + size/sizeof(active[0]);
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

int handle_line(char *line, profile *prof, sbuffer *buffer){
	printf("%s\n",line);
	if(strlen(line) == 0)
		return 0;

	char *token;
	
	char *hostname = get_running_config()->hostname;
	char *original_pointer = line;
	bool endcommand = false;
	struct sub_command *last_command = NULL;
	bool duplicate = false;
	bool first_pass = true;
	int lastcommand_id = 0; //root
	bool error =false;
	int error_loc = 0;
	bool help_called = false;
	unsigned long subcommand_size = 0;

	//Select the corresponding node commands
	struct sub_command *active;
	switch(prof->active_node){
		case NONE:
			active = root_node;
			subcommand_size = sizeof(root_node);
			break;
		case INTERFACE:
			active = interface_node;
			subcommand_size = sizeof(interface_node);
			break;
		case KEYCHAIN:
			active = keychain_node;
			subcommand_size = sizeof(keychain_node);
			break;
		case KEY:
			active = key_node;
			subcommand_size = sizeof(key_node);
			break;
		case ROUTER:
			active = routereigrp_node;
			subcommand_size = sizeof(routereigrp_node);
			break;
		case IPV6:
			break;

	}

	do{
		token = strsep(&line," ");

		if(options_help(buffer, token, lastcommand_id, active,subcommand_size)){
			help_called = true;
			break;
		}
		
		//Look at the current node
		struct sub_command *tmp = NULL;
		struct sub_command* ptr = active;
		struct sub_command* endPtr = active + subcommand_size/sizeof(active[0]);

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

		//If we didn't find a match at current node look at the global node
		if(first_pass && tmp == NULL){
			first_pass = false;
			active = global_node;
			subcommand_size = sizeof(global_node);

			struct sub_command* ptr = active;
			struct sub_command* endPtr = active + subcommand_size/sizeof(active[0]);

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
			
		}
		first_pass = false;

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
			error_loc += find_error_location(token,lastcommand_id,active,subcommand_size);
			break;		
		}

		if(token != NULL){
			error_loc += strlen(token) + 1;
		}

		if(line == NULL)break;
	
	}while(!endcommand);

	//
	if(!duplicate && last_command != NULL && last_command->end){
		if(last_command->execute == NULL){
			printf("Error:Function not assigned for command id %d\n", last_command->code);				
		}else{
			int res = last_command->execute(line,buffer,prof);
			if(res > 0){
				error = true;
				error_loc += res;
			}else if(res < 0){
				if(res == END_CODE) return END_CODE;
				if(res == -1){
					duplicate = true;
				}
			}
		}
	}


	if(help_called){
		//Do nothing, just prevent it from being shown as an error
	}else if(duplicate){
		int n = sprintf(buffer->s,"%% Ambiguous command: \"%s\"\n",original_pointer);
		bwrite(buffer,buffer->s,n);
	}else if(error){
		//Point out there the error is
		if(last_command == NULL){
			text_arrowpointer(buffer,strlen(hostname)+1+error_loc);
			bwrite(buffer, "%% Invalid input detected at '^' marker.\n", 41);
		}else if(error){
			text_arrowpointer(buffer,strlen(hostname)+1+error_loc);
			bwrite(buffer, "%% Invalid input detected at '^' marker.\n", 41);
		}else if(!last_command->end){
			bwrite(buffer,"%% Incomplete command.\n",23);
		}else{
			//Should never reach here, but will be left to catch other errors
			text_arrowpointer(buffer,strlen(hostname)+1+error_loc);
			bwrite(buffer, "%% Invalid input detected at '^' marker.\n", 41);
		}
	}

	return 0;
}

int config_telnet(char *line, profile *prof, sbuffer *buffer){

	int res = handle_line(line, prof, buffer);
	if(res == END_CODE) return END_CODE;

	char *hostname = get_running_config()->hostname;
	bwrite(buffer, hostname,strlen(hostname));

	int n = 0;
	switch(prof->active_node){
		case NONE:
			n = sprintf(buffer->s,"(config)");
			break;
		case INTERFACE:
			n = sprintf(buffer->s,"(config-if)");
			break;
		case KEYCHAIN:
			n = sprintf(buffer->s,"(config-keychain)");
			break;
		case KEY:
			n = sprintf(buffer->s,"(config-keychain-key)");
			break;
		case ROUTER:
			n = sprintf(buffer->s,"(config-router)");
			break;
		case IPV6:
			break;
	}
	bwrite(buffer,buffer->s,n);
	bwrite(buffer,"#",1);
	return 0;
}

int parse_config_file(char *path){

	//Open and read the text file
	FILE *f = fopen(path, "rb");
	if(f == NULL){
		syslog(LOG_INFO, "Could not find config file at \"%s\"", path);
		return -1;
	}

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char buffer[fsize];
	fread(buffer, fsize, 1, f);
	fclose(f);

	buffer[fsize] = 0;

	//Read the buffer (config file) line-by-line
	char *buffer_ptr = buffer;
	char *line = NULL;
	int read_mode = SINGLE_LINE;

	//Used for storing data during multiline reads
	sbuffer multiline_buffer;
	init_sbuffer(&multiline_buffer);

	//

	profile prof;
	memset(&prof,0,sizeof(profile));

	printf("--Parsing Configuration File--\nRouter(config)#");

	//Parsing file
	do{
		line = strsep(&buffer_ptr,"\n");

		if(strlen(line) == 0)
			continue;
		
		if(read_mode == SINGLE_LINE){
			sbuffer retmsg;
			init_sbuffer(&retmsg);
			config_telnet(line,&prof,&retmsg);
			
			char str[retmsg.len];
			memcpy(str,retmsg.buffer,retmsg.len);
			printf("%s",str);
		}else{
			//read data then pass them
			//switch back to single line
		}

	}while(buffer_ptr != NULL);

	printf("end\nParssing config file finished.\n");


	return 0;
}

void free_proccess_info(hash_table_t *proccess_list){
	hash_collection col;
	prepare_hashcollection(&col,proccess_list);
	proccess *proc;
	while( (proc=next(&col))!= NULL ){
		int i;
		for(i=0;i<proc->advertised_networks.size;i++){
			net_info *adv_net = vector_get(&proc->advertised_networks,i);
			free(adv_net);
		}
		vector_free(&proc->advertised_networks);
		vector_free(&proc->passive_ifs);
		free(proc);
	}
	hashtable_free(proccess_list);	
}

void free_interface_info(hash_table_t *interface_list){
	hash_collection col;
	prepare_hashcollection(&col,interface_list);
	iff_info *iff;
	while( (iff=next(&col))!= NULL ){
		hash_collection col1;
		prepare_hashcollection(&col1,iff->eigrp_encryption);
		encrypt_info *keys;
		while( (keys=next(&col1))!= NULL ){
			free(keys);
		}
		hashtable_free(iff->eigrp_encryption);
		free(iff->name);
		free(iff);
	}
	hashtable_free(interface_list);
}

void free_lists(){
	free_proccess_info(running_config.proccess_list_ip4);
	free_proccess_info(running_config.proccess_list_ip6);
	free_interface_info(running_config.interface_list);
	if(running_config.password != NULL)free(running_config.password);
	free(running_config.hostname);
}

//Command execute functions
int hostname_com(char *line, sbuffer *buffer, profile *prof){
	char *name = strsep(&line," ");
	if(name != NULL){
		char *new = malloc(strlen(name)+1);
		new[strlen(name)] = 0;
		memcpy(new,name,strlen(name));
		get_running_config()->hostname = new;
		printf("Hostname changed to \"%s\".\n",name);
		return 0;
	}else{
		return -1;
	}
}

int interface_com(char *line, sbuffer *buffer, profile *prof){
	char *interface_name = strsep(&line," ");
	
	if(interface_name == NULL)return -1;

	int index = if_nametoindex(interface_name);
	if(index == 0)return 1;

	prof->node_id = index;
	prof->active_node = INTERFACE;

	//Check if the interface has been initialized
	iff_info *iff = get_interface_info(prof->node_id);
	if(iff != NULL) return 0;

	//Initialize it
	iff_info *new_iff = malloc(sizeof(iff_info));

	new_iff->index = index;
	char *iff_name = malloc(strlen(interface_name)+1);
	iff_name[strlen(interface_name)] = 0;
	memcpy(iff_name,interface_name,strlen(interface_name));
	new_iff->name = iff_name;
	new_iff->delay = 100000;
	new_iff->bandwidth = 100000;
	new_iff->eigrp_encryption = create_hash_table(10);

	hashtable_additem(running_config.interface_list,new_iff,index);
	printf("Interface %s registered for initialization.\n",interface_name);

	return 0;
}

int interface_bandwidth_com(char *line, sbuffer *buffer, profile *prof){
	char *token = strsep(&line," ");

	if(token == NULL)return -1;

	long bw;
	bool res = is_number(&bw, token);

	if(!res)return 1; // Return error at number
	if(bw < 1 && bw >10000000) return 1;
	
	iff_info *iff = get_interface_info(prof->node_id);
	iff->bandwidth = bw;

	return 0;
}

int interface_delay_com(char *line, sbuffer *buffer, profile *prof){
	char *token = strsep(&line," ");

	if(token == NULL)return -1;

	long delay;
	bool res = is_number(&delay, token);

	if(!res)return 1; // Return error at number
	if(delay < 1 && delay >16777215) return 1;
	
	iff_info *iff = get_interface_info(prof->node_id);
	iff->delay = delay;

	return 0;
}

int interface_auth_mode_com(char *line, sbuffer *buffer, profile *prof){
	char *as_num = strsep(&line," ");
	char *algorithm = strsep(&line," ");

	if(as_num == NULL || algorithm == NULL) return -1;

	//Digest Algorithm must be md5
	if(!equals(algorithm,"md5")) return 1;

	long as;
	bool res = is_number(&as, as_num);
	if(!res)return 1;
	//AS number must be within valid range
	if(as < 1 || as > 65535) return 1;

	iff_info *iff = get_interface_info(prof->node_id);
	encrypt_info *encrypt = hashtable_getitem(iff->eigrp_encryption,as);
	if(encrypt == NULL){
		encrypt = malloc(sizeof(encrypt_info));
		encrypt->keychain_name = "";
		hashtable_additem(iff->eigrp_encryption,encrypt,as);
	}
	encrypt->eigrp_id = as;
	encrypt->encryption = "md5";
	return 0;
}

int interface_auth_keychain_com(char *line, sbuffer *buffer, profile *prof){
	char *as_num = strsep(&line," ");
	char *keychain_name = strsep(&line," ");

	if(as_num == NULL || keychain_name == NULL) return -1;

	long as;
	bool res = is_number(&as, as_num);
	if(!res)return 1;
	//AS number must be within valid range
	if(as < 1 || as > 65535) return 1;

	iff_info *iff = get_interface_info(prof->node_id);
	encrypt_info *encrypt = hashtable_getitem(iff->eigrp_encryption,as);
	if(encrypt == NULL){
		encrypt = malloc(sizeof(encrypt_info));
		encrypt->encryption = "";
		hashtable_additem(iff->eigrp_encryption,encrypt,as);
	}
	encrypt->eigrp_id = as;
	encrypt->keychain_name = keychain_name;
	return 0;
}

int exit_com(char *line, sbuffer *buffer, profile *prof){

	prof->node_id = 0;
	prof->active_node = NONE;
	return 0;
}

int router_eigrp_com(char *line, sbuffer *buffer, profile *prof){

	char *token = strsep(&line," ");

	if(token == NULL)return -1;

	long id;
	bool res = is_number(&id, token);

	if(!res)return 1; // Return error at number
	if(id < 1 && id >65535) return 1;

	prof->node_id = (int)id;
	prof->active_node = ROUTER;

	//Check if the proccess exists
	proccess *proc = get_proccess_info(prof->node_id, AF_INET);
	if(proc != NULL)return 0;

	//Create it since it doesn't exists
	proccess *new_proc = malloc(sizeof(proccess));
	new_proc->id = (int)id;
	new_proc->k1 = 1;
	new_proc->k2 = 0;
	new_proc->k3 = 1;
	new_proc->k4 = 0;
	new_proc->k5 = 0;
	new_proc->k6 = 0;

	new_proc->redistribute_static = false;
	new_proc->variance = 1;
	new_proc->lb_enabled = false;
	new_proc->lb_min = false;

	vector_init(&new_proc->passive_ifs);
	vector_init(&new_proc->advertised_networks);

	if(new_proc->id > 0) get_global_vars()->proccesses_ip4++;
	if(new_proc->id > get_global_vars()->maxid_ip4) get_global_vars()->maxid_ip4 = new_proc->id;

	hashtable_additem(running_config.proccess_list_ip4,new_proc,new_proc->id);
	printf("EIGRP Autonomous System %lu registered for ip4.\n",new_proc->id);

	return 0;
}

int ip_route_com(char *line, sbuffer *buffer, profile *prof){
	char *network = strsep(&line," ");
	char *mask = strsep(&line," ");
	char *forward = strsep(&line," ");

	if(network == NULL || mask == NULL || forward == NULL)
		return -1;

	struct sockaddr_in address;
	address.sin_family = AF_INET;
	int result = inet_pton(AF_INET, network, &address.sin_addr);
	if(result != 1){
		printf("Invalid network address %s.\n", network);
		return -1;
	}
							
	int network_prefix = wildcard_to_prefix(mask);
					
	net_info *adv_net = malloc(sizeof(net_info));
	adv_net->external = true;
	memcpy(&adv_net->network,&address,sizeof(struct sockaddr_in));
	adv_net->prefix = network_prefix;
	adv_net->forward = malloc(strlen(forward));
	memcpy(adv_net->forward,forward,strlen(forward));

	char *token = strsep(&line," ");
	if(compare(token, "tag")){
		char *tag = strsep(&line," ");
		char *p = NULL;
		long val = strtol(tag,&p,10);
		if(*p){
			adv_net->tag = 0;
		}else{
			adv_net->tag = val;
		}
						
	}

	vector_add(&get_global_vars()->static_routes_ip4,adv_net);

	return 0;
}

int eigrprouter_redistribute_static_com(char *line, sbuffer *buffer, profile *prof){
	proccess *proc = get_proccess_info(prof->node_id, AF_INET);
	proc->redistribute_static = true;
	return 0;
}

int eigrprouter_network_com(char *line, sbuffer *buffer, profile *prof){
	char *network_number = strsep(&line," ");
	char *mask = strsep(&line," ");

	if(network_number == NULL || mask == NULL) return -1;	

	net_info *adv_net = malloc(sizeof(net_info));
	adv_net->external = false;

	adv_net->family = AF_INET;
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	int result = inet_pton(AF_INET, network_number, &address.sin_addr);
	memcpy(&adv_net->network,&address,sizeof(struct sockaddr_in));
	if(result != 1){
		printf("Invalid network address %s.\n", network_number);
		free(adv_net);
		return 1;
	}
	//Mask
	adv_net->prefix = wildcard_to_prefix(mask);
	if(adv_net->prefix == -1){
		printf("Invalid subnet mask or wildcard %s.\n",mask);
		free(adv_net);
		return 1;
	}

	proccess *proc = get_proccess_info(prof->node_id, AF_INET);
	vector_add(&proc->advertised_networks,adv_net);
	return 0;
}

int eigrprouter_passiveinterface_com(char *line, sbuffer *buffer, profile *prof){
	char *interface_name = strsep(&line," ");
	if(interface_name == NULL) return -1;

	proccess *proc = get_proccess_info(prof->node_id, AF_INET);
	char *name = malloc(strlen(interface_name)+1);
	name[strlen(interface_name)] = 0;
	memcpy(name,interface_name,strlen(interface_name));
	vector_add(&proc->passive_ifs,name);
	return 0;
}

int eigrprouter_trafficbalanced_com(char *line, sbuffer *buffer, profile *prof){
	proccess *proc = get_proccess_info(prof->node_id, AF_INET);
	proc->lb_enabled = true;
	proc->lb_min = false;
	return 0;
}

int eigrprouter_trafficmin_com(char *line, sbuffer *buffer, profile *prof){
	proccess *proc = get_proccess_info(prof->node_id, AF_INET);
	proc->lb_enabled = true;
	proc->lb_min = true;
	return 0;
}

int eigrprouter_variance_com(char *line, sbuffer *buffer, profile *prof){
	char *token = strsep(&line," ");
	if(token == NULL) return -1;

	long variance;
	bool res = is_number(&variance, token);

	if(!res)return 1; // Return error at number
	if(variance < 1 || variance > 128) return 1;

	proccess *proc = get_proccess_info(prof->node_id, AF_INET);
	proc->variance = variance;
	return 0;
}

int eigrprouter_metricweights_com(char *line, sbuffer *buffer, profile *prof){

	char *tos_token = strsep(&line," ");
	char *k1_token = strsep(&line," ");
	char *k2_token = strsep(&line," ");
	char *k3_token = strsep(&line," ");
	char *k4_token = strsep(&line," ");
	char *k5_token = strsep(&line," ");

	if(tos_token == NULL || k1_token == NULL || k2_token == NULL || 
	k3_token == NULL || k4_token == NULL || k5_token == NULL) return -1;

	bool res;
	long tos,k1,k2,k3,k4,k5;
	res = is_number(&tos, tos_token);
	if(!res)return 1;
	res = is_number(&k1, k1_token);
	if(!res)return 1;
	res = is_number(&k2, k2_token);
	if(!res)return 1;
	res = is_number(&k3, k3_token);
	if(!res)return 1;
	res = is_number(&k4, k4_token);
	if(!res)return 1;
	res = is_number(&k5, k5_token);
	if(!res)return 1;

	if(k1 < 0 || k1 > 256) return 1;
	if(k2 < 0 || k2 > 256) return 1;
	if(k3 < 0 || k3 > 256) return 1;
	if(k4 < 0 || k4 > 256) return 1;
	if(k5 < 0 || k5 > 256) return 1;

	proccess *proc = get_proccess_info(prof->node_id, AF_INET);
	proc->k1 = (int)k1;
	proc->k2 = (int)k2;
	proc->k3 = (int)k3;
	proc->k4 = (int)k4;
	proc->k5 = (int)k5;

	return 0;
}

int key_chain_com(char *line, sbuffer *buffer, profile *prof){
	char *keyname = strsep(&line," ");
	if(keyname == NULL) return -1;

	keychain_info *chain = hashtable_getitem(running_config.keychain_list,hash(keyname));
	if(chain == NULL){
		keychain_info *new_chain = malloc(sizeof(keychain_info));
		new_chain->keys = create_hash_table(100);
		new_chain->name = keyname;
		hashtable_additem(running_config.keychain_list,new_chain,hash(keyname));
		printf("New key chain \"%s\" created.\n",keyname);
		chain = new_chain;
	}
	prof->active_node = KEYCHAIN;
	prof->active_chain = chain;

	return 0;
}

int key_com(char *line, sbuffer *buffer, profile *prof){
	char *key_num = strsep(&line," ");
	
	bool res;
	long id;
	res = is_number(&id, key_num);
	if(!res)return 1;
	if( id < 0 || id > 2147483647) return 1;

	key_info *key = hashtable_getitem(prof->active_chain->keys,id);
	if(key == NULL){
		key_info *new_key = malloc(sizeof(key_info));
		new_key->indentifier = id;
		hashtable_additem(prof->active_chain->keys,new_key,id);
	}

	prof->active_node = KEY;
	prof->node_id = id;

	return 0;
}

int key_keystring_com(char *line, sbuffer *buffer, profile *prof){
	char *keyline = strsep(&line," ");
	if(keyline == NULL) return -1;

	key_info *active_key = hashtable_getitem(prof->active_chain->keys,prof->node_id);
	active_key->password = keyline;
	active_key->encryption = 0;
	return 0;
}

int key_exit_com(char *line, sbuffer *buffer, profile *prof){
	prof->active_node = KEYCHAIN;
	return 0;
}

int end_com(char *line, sbuffer *buffer, profile *prof){
	return END_CODE;
}

int enable_secret_com(char *line, sbuffer *buffer, profile *prof){
	char *first_param = strsep(&line," ");
	char *second_param = strsep(&line," ");
	if(first_param == NULL) return -1;
	
	bool res;
	long encrypt;
	res = is_number(&encrypt, first_param);
	if(!res){
		char *password = malloc(strlen(first_param));
		memcpy(password,first_param,strlen(first_param));
		char *salt = get_random_salt(4);
		char *result = crypt(password,salt);
		get_running_config()->password = result;
		return 0;
	}else{
		if(second_param == NULL) return -1; //No password line specified
		char *password = malloc(strlen(second_param));
		memcpy(password,second_param,strlen(second_param));
		//Free password only in case of error, if there is no error it will be freed at termination of the procces
		if(encrypt == 0){
			//encrpt it
			char *salt = get_random_salt(4);
			char *result = crypt(password,salt);
			get_running_config()->password = result;
			return 0;
		}else if(encrypt == 5){
			get_running_config()->password = password;
			return 0;
		}else{
			free(password);
			return 1;
		}
	}
}
