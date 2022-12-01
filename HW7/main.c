#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <time.h>
#include <net/if.h>

#include "fill_packet.h"
#include "pcap.h"


#define IP_SIZE 16
#define req_size 50

void print_usage(){
	printf("Usage:\n");
	printf("sudo ./ipscanner -i [Network Interface Name] -t [timeout(ms)]\n");
}

int ValidIP(const char* str){
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, str, &(sa.sin_addr));
	if(result == 1){
		return 1;
	}
	return 0;
}

int IsNumber(const char* str){
	for(int i = 0; i < strlen(str); i++){
		if(!isdigit(str[i])){
			return 0;	
		}
	}
	return 1;
}

pid_t pid;
u16 ICMP_count = 1;

int main(int argc, char* argv[]){
	int sockfd;
	int on = 1;
	int sockfd_send;
	
	pid = getpid(); //process ID
	struct sockaddr_in destination; //socket address
	struct in_addr my_ip, my_mask; //my IP address and mask
	struct ifreq req; //request
	myicmp *packet = (myicmp*)malloc(PACKET_SIZE); //packet
	
	//network interface got by ifconfig
	strcpy(req.ifr_name, argv[2]);

	//set timeout
	int timeout = atoi(argv[4]);

	//set interface name
	
	/* 
	 * in pcap.c, initialize the pcap
	 */
	//pcap_init( target_ip , timeout);

	//check the root identity
	if(geteuid() != 0){
		printf("%s\n","ERROR: You must be root to use this tool!");
		exit(1);
	}

	//check socket
	if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
			perror("open send socket error");
			exit(1);
	}
	
	/* get ip address of my interface */
    if(ioctl(sockfd_send, SIOCGIFADDR, &req) == -1){
        perror("SIOCGIFADDR error");
        my_ip.s_addr = 0;
    }
    else{
        memcpy(&destination,&req.ifr_addr,sizeof(destination));
        my_ip = destination.sin_addr;
    }

	 /*get network mask of my interface */
	if(ioctl(sockfd_send,SIOCGIFNETMASK, &req)== -1){
		perror("SIOCGIFNETMASK ERROR");
		exit(1);
		my_mask.s_addr = 0;
	}
	else{
		memcpy(&destination,&req.ifr_addr,sizeof(destination));
        my_mask = destination.sin_addr;
	}






















	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}
	
	
	
	/*
	 *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
		 or use the standard socket like the one in the ARP homework
 	 *   to get the "ICMP echo response" packets 
	 *	 You should reset the timer every time before you send a packet.
	 */
	 if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&destination, sizeof(destination)) < 0)
	{
			perror("sendto");
			exit(1);
	}

	free(packet);

	return 0;
}

