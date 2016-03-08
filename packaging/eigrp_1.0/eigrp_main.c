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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "config_controller.h"
#include "eigrp_base.h"
#include "config.h"
#include "netlink.h"
#include "utils.h"

static int telnet_port = 11203;
static int eigrp_routing_table = RT_TABLE_MAIN;
static int eigrp_rtprot = 10;
static int pidFilehandle;

static bool logstuff = false;
static int outputFile;
static char *logpath = NULL;
static char *confpath = NULL;
static char *varpath = NULL;

static bool running = true;

#define DAEMON_NAME "eigrp_daemon"

void signal_handler(int sig){
	switch(sig){
		case SIGHUP:
			syslog(LOG_WARNING, "Received SIGHUP");
			break;
		case SIGINT:
		case SIGTERM:
			syslog(LOG_INFO, "Daemon Exiting");
			shutdown_eigrp();
			exit(EXIT_SUCCESS);
			break;
		default:
			syslog(LOG_WARNING, "Unhandled signal %s", strsignal(sig));
			break;
	}
}

void make_daemon(){
	setlogmask(LOG_UPTO(LOG_INFO));
	openlog(DAEMON_NAME, LOG_CONS | LOG_PERROR, LOG_USER);

	printf("Setting up the daemon\n");
	syslog(LOG_INFO, "Daemon starting up");

	//Already a daemon
	if(getppid() == 1){
		return;
	}

	int pid = fork();

	if(pid < 0){
		//Could not fort
		exit(EXIT_FAILURE);
	}

	if(pid > 0){
		printf("Daemon is ready, you can now close this window.\n");
		exit(EXIT_SUCCESS);
	}

	//child continues from here

	umask(027); //File permissions 750

	//Get a new proccess group
	int sid = setsid();
	if(sid < 0){
		exit(EXIT_FAILURE);
	}

	//Close descriptors
	int i;
	for(i = getdtablesize();i >= 0; i--){
		close(i);
	}

	//Open STDIN
	i = open("/dev/null", O_RDWR);
	
	//STDOUT
	if(logpath == NULL){
		char time[20];
		filenamefromtime(time);
		logpath = malloc(7+20);
		logpath[0] = '\0';
		strcat(logpath,"/etc/eigrp/logs/");
		strcat(logpath,time);
	}
	outputFile = open(logpath, O_RDWR|O_CREAT);
	if(outputFile != -1){
		dup(outputFile);
		dup(outputFile);
	}else{
		dup(i);
		dup(i);
	}
	
	//free(filename);
	//dup(i);

	//STERR

	char *file = "/var/run/eigrp.pid";
	pidFilehandle = open(file, O_RDWR|O_CREAT, 0600);
	if(pidFilehandle == -1){
		syslog(LOG_INFO, "Could not open PID lock file %s, exiting", file);
		exit(EXIT_FAILURE);
	}

	if(lockf(pidFilehandle, F_TLOCK, 0) == -1){
		syslog(LOG_INFO, "Could not lock PID lock file %s : %s, exiting", file,strerror(errno));
		exit(EXIT_FAILURE);
	}

	char str[10];
	sprintf(str, "%d\n",getpid());
	write(pidFilehandle, str, strlen(str));
	
	syslog(LOG_INFO, "Deamon running");
}

void kill_eigrp_proccess(){
	char *file = "/var/run/eigrp.pid";
	pidFilehandle = open(file, O_RDONLY);
	if(pidFilehandle == -1){
		syslog(LOG_INFO, "Could not open PID lock file %s, exiting", file);
		exit(EXIT_FAILURE);
	}

	char buffer[100];
	read(pidFilehandle,buffer,100);
	printf("Buffer:%s\n",buffer);

	int pid = strtol(buffer,0,10);
	
	kill(pid, SIGTERM);
}

void load_variables(){
	if(varpath == NULL)
		varpath = "/etc/eigrp/settings";

	//Open and read the text file
	FILE *f = fopen(varpath, "rb");
	if(f == NULL){
		syslog(LOG_INFO, "Could not find setting file at \"%s\"", varpath);
		return;
	}

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char buffer[fsize];
	fread(buffer, fsize, 1, f);
	fclose(f);

	buffer[fsize] = 0;

	char *buffer_ptr = buffer;
	char *line = NULL;
	char *token = NULL;

	//Parsing file
	do{
		line = strsep(&buffer_ptr,"\n");

		if(strlen(line) == 0)
			continue;
		
		if(compare(line,";"))
			continue;

		token = strsep(&line,"=");
		if(equals(token,"telnet_port")){
			char *p;
			token = strsep(&line,"=");
			long val = strtol(token,&p,10);
			if(*p){
				printf("Not a valid number. Using default\n");
				continue;
			}else{
				telnet_port = val;
			}
		}
		if(equals(token,"eigrp_routing_table")){
			char *p;
			token = strsep(&line,"=");
			long val = strtol(token,&p,10);
			if(*p){
				printf("Not a valid number. Using default\n");
				continue;
			}else{
				eigrp_routing_table = val;
			}
		}
		if(equals(token,"eigrp_rtprot")){
			char *p;
			token = strsep(&line,"=");
			long val = strtol(token,&p,10);
			if(*p){
				printf("Not a valid number. Using default\n");
				continue;
			}else{
				eigrp_rtprot = val;
			}
		}

	}while(buffer_ptr != NULL);
}

int main(int argc, char *argv[]){

	printf("eigrp - A routing daemon for the eigrp protocol\n"
		"Copyright (C) 2015 Paraskeuas Karahatzis\n\n"
		"This program is free software: you can redistribute it and/or modify it under the terms of the\n"
		"GNU General Public License as published by the Free Software Foundation, either version 3 of the\n"
		"License, or (at your option) any later version.\n\n"

		"This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without\n"
		"even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU\n"
		"General Public License for more details.\n\n"

		"You should have received a copy of the GNU General Public License along with this program. If not,\n"
		"see <http://www.gnu.org/licenses/>.\n\n"

		"dervelakos.madlax@gmail.com\n"
	);

	bool run_as_daemon = false;

	uid_t uid = geteuid();
	if(uid != 0){
		printf("Process needs root privilege to open RAW sockets. Exiting.\n");
		return -1;
	}

	if(argc > 1){
		int i;
		for(i=0;i<argc;i++){
			char *command = strsep(&argv[i],"=");
			if(equals(command,"-start_daemon"))
				run_as_daemon = true;
			if(equals(command,"-stop")){
				kill_eigrp_proccess();
				return 0;
			}
			if(equals(command,"--clear-routes")){
				remove_routes_by_protocol(eigrp_rtprot,AF_INET);
				return 0;
			}
			if(equals(command,"-log")){
				logstuff = true;
				char *token = strsep(&argv[i],"=");
				if(token != NULL){
					logpath = token;
				}
			}
			if(equals(command,"-conf")){
				char *token = strsep(&argv[i],"=");
				if(token != NULL){
					confpath = token;
				}
			}
			if(equals(command,"-var")){
				char *token = strsep(&argv[i],"=");
				if(token != NULL){
					varpath = token;
				}
			}
		}
	}

	//Block the following signals
	sigset_t newSigSet;
	sigemptyset(&newSigSet);
	sigaddset(&newSigSet, SIGCHLD);
	sigaddset(&newSigSet, SIGSTOP);
	sigaddset(&newSigSet, SIGTTOU);
	sigaddset(&newSigSet, SIGTTIN);
	sigprocmask(SIG_BLOCK, &newSigSet, NULL);

	struct sigaction newSigAction;
	newSigAction.sa_handler = signal_handler;
	sigemptyset(&newSigAction.sa_mask);
	newSigAction.sa_flags = 0;

	sigaction(SIGHUP, &newSigAction, NULL);	//hang up
	sigaction(SIGTERM, &newSigAction, NULL); //terminate
	sigaction(SIGINT, &newSigAction, NULL); //interupt
	
	printf("Loading basic variables.\n");
	load_variables();
	if(run_as_daemon)
		make_daemon();
	printf("Starting Eigrp.\n");

	//Clean old routes
	printf("Cleaning old routes.\n");
	remove_routes_by_protocol(eigrp_rtprot,AF_INET);
	//remove_routes_by_protocol(RTPROT_EIGRP,AF_INET6);

	config_controller_init();
	pre_init();
	
	printf("Loading configuration.\n");
	if(confpath == NULL)
		confpath = "/etc/eigrp/conf";
	parse_config_file(confpath);
	post_init();

	start_interface_state_listener();

	while(running){
		sleep(3);
	}
	
	//shutdown_eigrp();
	close(pidFilehandle);
	close(outputFile);
	
	printf("Cleaning routes.\n");
	remove_routes_by_protocol(eigrp_rtprot,AF_INET);
	//remove_routes_by_protocol(RTPROT_EIGRP,AF_INET6);
	return 0;
}

void stop(){
	running =false;
}

int get_telnet_port(){
	return telnet_port;
}
int get_eigrp_routing_table_number(){
	return eigrp_routing_table;
}
int get_eigrp_routing_protocol_number(){
	return eigrp_rtprot;
}
