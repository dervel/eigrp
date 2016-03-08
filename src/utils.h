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
#include <linux/kernel.h>
#include <asm/byteorder.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MIN(x,y) ((x<y) ? x : y)

#ifndef UTILS_H_
#define UTILS_H_

typedef struct simple_buffer{
	char buffer[1024];
	char s[512]; //support buffer, you can fill it with whatever you want
	int len;
}sbuffer;

bool compare(char *s1, char *s2);
bool oneway_compare(char *s1, char *s2);
bool equals(char *s1, char *s2);
long long current_timestamp();
int sleep_millis(long long milliseconds);
void time_format(void *time,long long timestamp);
__u16 checksum(char *buffer,int len);
int subnet_to_prefix(unsigned int subnet_mask);
int wildcard_to_prefix(char *ch);
unsigned int ip4_toint(char *ip);
//char *ip4_tochar(unsigned int ip);
void init_sbuffer(sbuffer *b);
void bwrite(sbuffer *buffer, char *append, int size);
bool flags_are_set(int flag_field, int flag);
int compare_ip6_addr(struct in6_addr *addr1, struct in6_addr *addr2);
bool ip_equals(struct sockaddr_storage *addr1, struct sockaddr_storage *addr2);
void ip_tochar(void *str, struct sockaddr_storage *address);
void str_now(void *str);
void filenamefromtime(void *str);
void text_arrowpointer(sbuffer *buffer,int len);
bool is_number(long *res, char *str);
char *get_random_salt(int len);

#endif
