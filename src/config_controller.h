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

#include "utils.h"
#include "eigrp_structs.h"

#define SINGLE_LINE 0
#define MULTI_LINE 1

#define END_CODE -100

#ifndef CONFIGCONTROLLER_H_
#define CONFIGCONTROLLER_H_
typedef enum command_node_{
	NONE,
	ROUTER,
	KEYCHAIN,
	KEY,
	INTERFACE,
	IPV6
}command_node;

typedef struct _profile{
	command_node active_node;
	keychain_info *active_chain;
	int node_id;
} profile;

struct sub_command{
	int code;
	char name[20];
	int parent;
	bool end;
	int (*execute)(char *token, sbuffer *buffer, profile *prof); // Return values: 0 - No problem, Positive - Error location, -1 - Ambigious command
};

struct config{
	char *hostname;
	char *password;
	char *salt;
	hash_table_t *proccess_list_ip4;
	hash_table_t *proccess_list_ip6;
	hash_table_t *interface_list;
	hash_table_t *keychain_list;
};

proccess *get_proccess_info(int id, int family);
iff_info *get_interface_info(int index);
void free_lists();
int config_controller_init();

int hostname_com(char *line, sbuffer *buffer, profile *prof);
int interface_com(char *line, sbuffer *buffer, profile *prof);
int exit_com(char *line, sbuffer *buffer, profile *prof);
int router_eigrp_com(char *line, sbuffer *buffer, profile *prof);
int ip_route_com(char *line, sbuffer *buffer, profile *prof);
int interface_bandwidth_com(char *line, sbuffer *buffer, profile *prof);
int interface_delay_com(char *line, sbuffer *buffer, profile *prof);
int interface_auth_mode_com(char *line, sbuffer *buffer, profile *prof);
int interface_auth_keychain_com(char *line, sbuffer *buffer, profile *prof);
int eigrprouter_redistribute_static_com(char *line, sbuffer *buffer, profile *prof);
int eigrprouter_network_com(char *line, sbuffer *buffer, profile *prof);
int eigrprouter_passiveinterface_com(char *line, sbuffer *buffer, profile *prof);
int eigrprouter_trafficbalanced_com(char *line, sbuffer *buffer, profile *prof);
int eigrprouter_trafficmin_com(char *line, sbuffer *buffer, profile *prof);
int eigrprouter_variance_com(char *line, sbuffer *buffer, profile *prof);
int eigrprouter_metricweights_com(char *line, sbuffer *buffer, profile *prof);
int key_chain_com(char *line, sbuffer *buffer, profile *prof);
int key_com(char *line, sbuffer *buffer, profile *prof);
int key_keystring_com(char *line, sbuffer *buffer, profile *prof);
int key_exit_com(char *line, sbuffer *buffer, profile *prof);
int end_com(char *line, sbuffer *buffer, profile *prof);
int enable_secret_com(char *line, sbuffer *buffer, profile *prof);

struct config *get_running_config();
int parse_config_file(char *path);
int handle_line(char *line, profile *prof, sbuffer *buffer);
int config_telnet(char *line, profile *prof, sbuffer *buffer);
bool options_help(sbuffer *buffer, char *token, int lastcommand_id, struct sub_command *active, unsigned long size);
int find_error_location(char *token, int lastcommand_id,struct sub_command *active, unsigned long size);

#endif

