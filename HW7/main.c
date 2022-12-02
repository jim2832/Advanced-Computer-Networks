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
#define ADDR_LEN 30

void print_usage(){
	printf("Usage:\n");
	printf("sudo ./ipscanner -i [Network Interface Name] -t [timeout(ms)]\n");
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
	myicmp *packet;
	
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

	char mask[INET6_ADDRSTRLEN];
	char IP[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &my_ip, IP, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &my_mask, mask, INET_ADDRSTRLEN);

	//split the mask
	//255.255.255.0
	/*
	splited_mask[0] = 255
	splited_mask[1] = 255
	splited_mask[2] = 255
	splited_mask[3] = 0
	*/
	char temp_mask[ADDR_LEN];
	unsigned char splited_mask[ADDR_LEN];
	memcpy(temp_mask, mask, ADDR_LEN);
	char *mask_token;
	int mask_num;
	mask_token = strtok(temp_mask, ".");
	int i = 0;
	while(mask_token != NULL){
		mask_num = atoi(mask_token);
		splited_mask[i] = mask_num;
		i++;
		mask_token = strtok(temp_mask, ".");
	}

	//split the IP
	//140.117.169.50
	/*
	splited_ip[0] = 140
	splited_ip[1] = 117
	splited_ip[2] = 169
	splited_ip[3] = 50
	*/
	char temp_ip[ADDR_LEN];
	unsigned char splited_ip[ADDR_LEN];
	memcpy(temp_ip, IP, ADDR_LEN);
	char *ip_token;
	int ip_num;
	ip_token = strtok(temp_ip, ".");
	int j = 0;
	while(ip_token != NULL){
		ip_num = atoi(ip_token);
		splited_ip[j] = ip_num;
		j++;
		ip_token = strtok(temp_ip, ".");
	}

	int available_IP, segment, start, end;
	if(splited_mask[2] == 255){
		available_IP = 256 - splited_mask[3]; //host個數
		segment = 256 / available_IP; //子網域數量
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
	 if(sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&destination, sizeof(destination)) < 0)
	{
			perror("sendto");
			exit(1);
	}

	free(packet);

	return 0;
}

