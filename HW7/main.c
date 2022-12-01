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
	int sockfd_receive;
	
	pid = getpid(); //process ID
	struct sockaddr_in destination;
	myicmp *packet = (myicmp*)malloc(PACKET_SIZE);


	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	
	/* 
	 * in pcap.c, initialize the pcap
	 */
	pcap_init( target_ip , timeout);

	
	
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

