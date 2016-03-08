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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/types.h>
#include <asm/byteorder.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

bool compare(char *s1, char *s2){

	if(s1 == NULL || s2 == NULL)return false;
	
	int result = strncmp(s1,s2,MIN(strlen(s1),strlen(s2)));
	if(result == 0)
		return true;
	else
		return false;
}

bool oneway_compare(char *s1, char *s2){

	if(s1 == NULL || s2 == NULL)return false;

	if(strlen(s1) > strlen(s2))return false;	

	int result = strncmp(s1,s2,strlen(s1));
	if(result == 0)
		return true;
	else
		return false;
}

bool equals(char *s1, char *s2){
	if(s1 == NULL || s2 == NULL) return false;
	if(strlen(s1) != strlen(s2)) return false;
	return compare(s1, s2);
}

long long current_timestamp(){
	struct timeval te;
	gettimeofday(&te,NULL);
	long long mill = te.tv_sec*1000LL + te.tv_usec/1000;
	return mill;
}

void time_format(void *time,long long timestamp){
	int secs = timestamp % (60*1000LL);
	secs /= 1000;
	int mins = timestamp % (60*60*1000LL);
	mins /= 60*1000;
	int hours = timestamp / (60*60*1000LL);
	sprintf(time,"%d:%d:%d",hours,mins,secs);
}

int sleep_millis(long long milliseconds){
	struct timeval te;
	te.tv_sec = milliseconds / 1000;
	te.tv_usec = (milliseconds % 1000) * 1000000LL;
	return nanosleep((struct timespec*)&te, NULL);
}

__u16 checksum(char *buffer,int len){
	__u32 sum = 0;
	__u16 word16 = 0;
	int i;
	for(i=0;i<len;i+=2){
		word16 = ((buffer[i]<<8)&0xFF00)+(i+1>=len ? 0 : (buffer[i+1]&0xFF));
		sum = sum +(__u32)word16;
	}

	while(sum>>16){
		sum = (sum & 0xFFFF)+(sum >> 16);
	}

	sum= ~sum;

	return ((__u16)sum);
}

int subnet_to_prefix(unsigned int subnet_mask){
	int prefix = 0;

	while(subnet_mask % 2 == 1){
		subnet_mask = subnet_mask >> 1;
		prefix++;
	}
	//Check if the wildcard is discontiguous
	
	if(subnet_mask != 0)return -1;
	
	return prefix;
}

/*
If this function is given a subnet mask instead of a wildcard it will automatically turn it to a wildcard
*/
int wildcard_to_prefix(char *ch){
	in_addr_t wildcard = inet_network(ch);
	if(wildcard == -1) return -1;
	int prefix = 32;
	//If it's a subnet mask turn it to a wildcard
	if(wildcard % 2 == 0)
		wildcard = ~wildcard;

	while(wildcard % 2 == 1){
		wildcard = wildcard >> 1;
		prefix--;
	}
	//Check if the wildcard is discontiguous
	if(wildcard != 0)return -1;
	
	return prefix;
}

unsigned int ip4_toint(char *ip){
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
	if(result == 0) return 0;
	return sa.sin_addr.s_addr;
}

char *ip4_tochar(unsigned int ip){
	struct sockaddr_in sa;
	char *str = malloc(16);
	sa.sin_addr.s_addr = ip;
	inet_ntop(AF_INET, &(sa.sin_addr),str, INET_ADDRSTRLEN);
	return str;
}

void init_sbuffer(sbuffer *b){
	memset(b->buffer,0,sizeof(b->buffer));
	memset(b->s,0,sizeof(b->s));
	b->len = 0;
}

void bwrite(sbuffer *buffer, char *append, int size){
	//if(sizeof(buffer->buffer) + buffer->len) len = sizeof(buffer->buffer) - buffer->len;
	memcpy(&buffer->buffer[buffer->len], append, size);
	buffer->len += size;
}

bool flags_are_set(int flag_field, int flag){
	int val = flag_field & flag;
	if(val == 0){return false;}
	else{return true;}
}

int compare_ip6_addr(struct in6_addr *addr1, struct in6_addr *addr2){
	int i;	
	for(i=15;i>=0;i--){
		if(addr1->s6_addr[i] < addr1->s6_addr[i])
			return -1;
		if(addr1->s6_addr[i] > addr1->s6_addr[i])
			return 1;
	}
	return 0;
}

bool ip_equals(struct sockaddr_storage *addr1, struct sockaddr_storage *addr2){
	if(addr1->ss_family != addr2->ss_family) return false;
	
	if(addr1->ss_family == AF_INET){
		struct sockaddr_in *in1 = (struct sockaddr_in *)addr1;
		struct sockaddr_in *in2 = (struct sockaddr_in *)addr2;
		if(in1->sin_addr.s_addr == in2->sin_addr.s_addr){
			return true;
		}else{
			return false;
		}
	}else{
		struct sockaddr_in6 *in1 = (struct sockaddr_in6 *)&addr1;
		struct sockaddr_in6 *in2 = (struct sockaddr_in6 *)&addr2;
		if(compare_ip6_addr(&in1->sin6_addr,&in2->sin6_addr)== 0){
			return true;
		}else{
			return false;
		}
	}
}

void ip_tochar(void *str, struct sockaddr_storage *address){

	if(address->ss_family == AF_INET){
		memset(str,0,16);
		inet_ntop(AF_INET, &((struct sockaddr_in *)address)->sin_addr, str, INET_ADDRSTRLEN);
	}else{
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)address)->sin6_addr, str, INET6_ADDRSTRLEN);
	}
}

void str_now(void *str){
	time_t t = time(0);
	const struct tm *now = localtime(&t);
	memset(str,0,20);
	strftime(str,20,"%b  %d %H:%M:%S",now);
}

void filenamefromtime(void *str){
	time_t t = time(0);
	const struct tm *now = localtime(&t);
	memset(str,0,20);
	strftime(str,20,"%b%d%H%M%S",now);
}

void text_arrowpointer(sbuffer *buffer,int len){
	int i;
	for(i=0;i<len;i++){
		buffer->s[i] = ' ';
	}
	buffer->s[len] = '^';
	buffer->s[len+1] = '\n';
	bwrite(buffer,buffer->s,len+2);
}

bool is_number(long *res, char *str){
	char *ptr;
	long ret = strtol(str,&ptr,10);
	if (*ptr == '\0') {
		*res = ret;
		return true;
	}else{
		return false;
	}
}

char *get_random_salt(int len){
	char *salt = malloc(3+len);
	memcpy(salt,"$1$",3);

	unsigned long seed[2];
	const char *const seedchars = "./0123456789ABCDEFGHIJKLMNOPQRST"
	"UVWXYZabcdefghijklmnopqrstuvwxyz";

	seed[0] = time(NULL);
	seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);

	int i;
	for(i = 0; i< len ; i++){
		salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];
	}

	return salt;
}
