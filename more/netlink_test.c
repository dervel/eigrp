
#include <stdio.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "netlink.h"
#include "vector.h"
#include "config.h"

int main(){

	//Destination
	struct sockaddr_storage dest;
	struct sockaddr_in *temp = (struct sockaddr_in *)&dest;
	temp->sin_addr.s_addr = inet_addr("10.11.0.0");
	temp->sin_family = AF_INET;
	dest.ss_family = AF_INET;
	//Gateway 1
	struct sockaddr_storage gate1;
	temp = (struct sockaddr_in *)&gate1;
	temp->sin_addr.s_addr = inet_addr("192.168.1.1");
	temp->sin_family = AF_INET;
		temp->sin_port = 5;
	dest.ss_family = AF_INET;
	//Gateway 2
	struct sockaddr_storage gate2;
	temp = (struct sockaddr_in *)&gate2;
	temp->sin_addr.s_addr = inet_addr("192.168.10.1");
	temp->sin_family = AF_INET;
	temp->sin_port = 2;
	dest.ss_family = AF_INET;
	
	vector gateways;
	vector_init(&gateways);
	vector_add(&gateways,&gate1);
	vector_add(&gateways,&gate2);

	multipath_route_add(&dest, &gateways, 24);
	vector_free(&gateways);

	return 0;

}

int interface_up(int i){

}

int interface_down(int i){

}

