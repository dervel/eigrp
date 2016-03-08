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
#include <pthread.h>
#include <sys/types.h>
#include <asm/byteorder.h>
#include <netinet/ip.h>

#include "vector.h"
#include "hashtable.h"
#include "linkedlist.h"
#include "libtelnet.h"
#include "config.h"

#define PASSIVE_STATE 1 //forwards packets
#define ACTIVE_STATE 2	//router is computing a successor

#define PENDING_STATE 	1
#define UP_STATE 	2

#ifndef EIGRPSTRUCT_H_
#define EIGRPSTRUCT_H_

struct neighbour_;

struct topology_table{
	
};

typedef struct key_{
	long indentifier;
	int encryption;
	char *password;
	char *md5_hash;
}key;

typedef struct key_chain_{
	char *name;
	hash_table_t *keys;
}key_chain;

typedef struct global_vars{
	hash_table_t *key_chains;
	vector static_routes_ip4;
	vector static_routes_ip6;
	int router_id;
	int proccesses_ip4;
	int maxid_ip4;
	int proccesses_ip6;
	int maxid_ip6;
}globals;

typedef struct telnet_client_{
	telnet_t *client;
	int sock;
}telnet_client;

//Is used at command parsing for information holding
typedef struct keychain_info_{
	char *name;
	hash_table_t *keys;
}keychain_info;

typedef struct key_info_{
	long indentifier;
	int encryption;
	char *password;
}key_info;

typedef struct interface_encryption_info{
	int eigrp_id;
	char *keychain_name;
	char *encryption;
}encrypt_info;

typedef struct interface_info{
	char *name;
	int index;
	long bandwidth;
	long delay;
	hash_table_t *eigrp_encryption;
}iff_info;

typedef struct proccess_{
	long id;
	vector passive_ifs;
	vector advertised_networks;
	bool redistribute_static;
	int k1, k2, k3, k4, k5, k6;
	unsigned long router_id;
	int variance;
	bool lb_enabled;
	bool lb_min;
}proccess;

typedef struct network_info_{
	short family;
	struct sockaddr_storage network;
	int prefix;
	bool external;
	char *forward;
	long tag;
}net_info;

typedef struct process_keys_{
	long eigrp_id;
	key_chain *keychain;
}process_keys;

typedef struct interface_{

	struct sockaddr_in ifa_addr_ip4;
	struct sockaddr_in ifa_netmask_ip4;

	struct sockaddr_in6 ifa_addr_ip6;
	struct sockaddr_in6 ifa_netmask_ip6;

	hash_table_t *proccess_encryption;

	bool ip4_init;
	bool ip6_init;

	int index;

	int socket4;
	int socket6;
	char *name;
	pthread_t packet_listener4;
	pthread_t packet_listener6;

	//At interface_metric_changed the value_index refers to the variables below
	//mtu = 0, bandwidth = 1, delay = 2, load = 3, reliability = 4
	unsigned int mtu;
	unsigned int bandwidth;
	long long delay;
	unsigned int load;
	unsigned int reliability;

	bool running;
	bool is_up;

	//This is ONLY used for directly connected routes to pull information
	//It's prbly a bad idea but for now it will work
	struct neighbour_ *self; 
}interface;

typedef struct neighbour_{

	struct sockaddr_storage address;
	//__u32 address; //used as an identifier for the neighbour
	interface *interface; //the interface this neighbour was found
	struct eigrp_proccess *proc; //the proccess number this neighbour is
	struct sockaddr_in sin; //socket info
	vector routes; //routes learned from the neightbour
	int os_version;
	int eigrp_version;	
	linkedlist packet_queue;
	int pending_ack; //The last seq_num we received from the neighbour
	int last_ack_sent; //The last acknolegement we have sended
	long long last_packet_sent; //Last time we sended a packet
	long long holdtime; //Holdtime before considering neighour offline/inactive - in milliseconds
	long long last_response; //Time last packet received
	long long discovery_time; //Time the neighbour found 
	long long srtt; //smooth round time t
	bool is_active;
	bool send_next_packet; //Used to skip the waiting time for the next packet - turns to true when a new packet is received
	
	linkedlist update_tlv_queue;
	linkedlist reply_tlv_queue;
	linkedlist query_tlv_queue;

	int update_flag,reply_flag,query_flag; //next flag to be used for queued tlv packet

	int state; //Pending or Up state for initialization
	int init_seq; //Used for the above state change

	bool eot; //End of table - Used for start up
	bool cr; //Conditional Receive - IF this flag is set drop the packet that seq is equal to cr_num
	int cr_num;
} neighbour;

typedef struct route_{

	struct sockaddr_storage dest;
	unsigned int prefix;

	long long delay; //Accumulative - Is still scaled
	long bandwidth; //Minimum - Is still scaled
	int mtu; //Minimum
	int hop; //Accumulative
	int reliability; //Minimum
	int load; //Maximun

	unsigned int reported_distance;
	unsigned int feasible_distance;

	neighbour *sender;

	int route_tag;

	bool is_proccess_generated; //If it's an advertized entry - from the process
	int index; //The interface index this route refers to
	int rijk;

	bool sia_query_received;

	bool to_be_removed; //Marked to be freed after a packet is sent

	bool is_external;
	int orig_router_id;
	int orig_as_number;
	int admin_tag;
	int external_metric;
	int external_prot;
	int external_flags;

}route;

struct topology_route{
	struct sockaddr_storage dest;
	int prefix;

	struct eigrp_proccess *proc;
	route *successor;
	int old_successor_metric;

	unsigned int feasible_distance_external;
	unsigned int feasible_distance_internal;
	unsigned int feasible_distance; //Is the one currently used - assigned when a new successor is found

	int ioj;

	int route_state;
	bool was_changed;
	bool has_no_successors;

	vector routes;
	pthread_t active_route_control;
};

struct topology_support{
	//Do not use/call this - Look at egrip_base for the faction to get a topology_route
	//This structures identifies the networks - search destination by network
	//The below hashtable holds the mask prefix - searches by prefix in the above network
	hash_table_t *topology_route;
};

typedef struct proccess_stats_{
	int packets_sent[12];
	int packets_received[12];
	int acks_sent;
	int acks_received;
}proccess_stats;

struct eigrp_proccess{

	bool running;
	int family;
	pthread_t hello_sender;

	//neighbour table
	hash_table_t *neighbours;
	//topology table
	hash_table_t *topology_support;

	unsigned int proccess_id;
	unsigned long router_id;

	bool redistribute_static; //If the proccess should redistribute static routes

	vector ifs; //Active interfaces on the proccess
	vector connected_routes; //routes the proccess is advertizing only

	pthread_t packet_sender;
	linkedlist multicast_queue; //queue used for multicast packets
	linkedlist query_tlv_queue; //queue for multicast tlv
	linkedlist update_tlv_queue;//queue for multicast tlv

	proccess_stats stats;

	//Load Balancing
	bool lb_enabled; //Load balancing enabled
	bool lb_min; //traffic-share min across_interfaces
	int variance;

	int seq_num; //Next Seq to send - init at 1 cause 0 means no ack - Packets i am sending

	int k1,k2,k3,k4,k5,k6;
	int holdtime;
	int hello_interval;
};

struct eigrphdr{
	__u8 version;
	__u8 opcode;
	__u16 checksum;
	__u32 flags;
	__u32 seqnum;
	__u32 acknum;
	__u16 router_id;
	__u16 autonomous_sys_number;
};

struct tlv_parameter_type{
	__u16 type;
	__u16 length;
	__u8 k1;
	__u8 k2;
	__u8 k3;
	__u8 k4;
	__u8 k5;
	__u8 k6;
	__u16 holdtime;
};

struct tlv_version_type{
	__u16 type;
	__u16 length;
	__u16 os_version; //os version
	__u16 eigrp_version; //eigrp version - tlv version
};

//tlv_sequence_type is a higly varriable lenght tlv so we will just read it from the buffer

typedef struct tlv_ip4_internal_{
	__u16 type;
	__u16 length;
	__u32 nexthop;
	__u32 scaled_delay;
	__u32 scaled_bw;
	__u8  mtu_1;
	__u8  mtu_2;
	__u8  mtu_3;
	__u8  hop_count;
	__u8  reliability;
	__u8  load;
	__u8  route_tag;
	__u8  flags;
	__u8  prefix;
	__u8  pnt_var_addr1;
	__u8  pnt_var_addr2;
	__u8  pnt_var_addr3;
	__u8  pnt_var_addr4;
} tlv_ip4_internal;

typedef struct tlv_ip4_external_{
	__u16 type;
	__u16 length;
	__u32 nexthop;
	__u32 origin_router;
	__u32 origin_as;
	__u32 admin_tag;
	__u32 external_metric;
	__u16 reserved;
	__u8  external_protocol;
	__u8  external_flags;
	__u32 scaled_delay;
	__u32 scaled_bw;
	__u8  mtu_1;
	__u8  mtu_2;
	__u8  mtu_3;
	__u8  hop_count;
	__u8  reliability;
	__u8  load;
	__u8  route_tag;
	__u8  flags;
	__u8  prefix;
	__u8  pnt_var_addr1;
	__u8  pnt_var_addr2;
	__u8  pnt_var_addr3;
	__u8  pnt_var_addr4;
}tlv_ip4_external;

struct tlv_next_multicast{
	__u16 type;
	__u16 length;
	__u32 seq_num;
};

typedef struct outgoing_packetv4_param_{
	char buffer[PACKET_LEN];
	int buffer_len;
	int flags;
	int seq_num;
	int opcode;
	struct sockaddr_in sin; //When sending multicast it doesn't matter what this field contains
} packetv4_param;
#endif
