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
#define ADDRLEN 30


pid_t pid;
u16 icmp_req = 1;
struct timeval start, stop, Time;

void print_usage(){
	printf("Usage:\n");
	printf("sudo ./ipscanner -i [Network Interface Name] -t [timeout(ms)]\n");
}

int main(int argc, char* argv[]){
	printf("\n");
	int sockfd;
	int on = 1;
	int sockfd_send;
	
	pid = getpid();
	struct sockaddr_in destination;
	
	struct in_addr myip, mymask;
	struct ifreq req; 
	char device_name[100];
	
	myicmp packet;
	int timeout = DEFAULT_TIMEOUT;

	strcpy(device_name, argv[2]);
	strcpy(req.ifr_name, device_name);
	timeout = atoi(argv[4]);

	//determine the root status
	if(geteuid() != 0){
		printf("%s\n","ERROR: You must be root to use this tool!");
		exit(1);
	}

	//set socket
	if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("open send socket error");
		exit(1);
	}
	
	//get ip address of my interface
    if(ioctl(sockfd_send, SIOCGIFADDR, &req) < 0){
        perror("ioctl SIOCGIFADDR error");
        myip.s_addr = 0;
    }
    else{
        memcpy(&destination, &req.ifr_addr, sizeof(destination));
        myip = destination.sin_addr;
    }

	//get network mask of my interface
	if(ioctl(sockfd_send, SIOCGIFNETMASK, &req) == -1){
		perror("SIOCGIFADDR ERROR");
		exit(1);
		mymask.s_addr = 0;
	}
	else{
		memcpy(&destination,&req.ifr_addr,sizeof(destination));
        mymask = destination.sin_addr;
	}
	
	char IP[INET_ADDRSTRLEN];
	char mask[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &myip, IP, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &mymask, mask, INET_ADDRSTRLEN);

	// printf("myip = %s \n", IP);
	// printf("mymask = %s \n", mask);
	
	//split the mask
	char temp_mask[ADDRLEN];
	unsigned char splited_mask[ADDRLEN]; //store subnet mask each value (int)
	memcpy(temp_mask, mask, ADDRLEN);
	char *Mask_token;
	int MASK_Num;
	Mask_token = strtok(temp_mask, ".");
	int i = 0;
	while(Mask_token != NULL){
		MASK_Num = atoi(Mask_token);
		splited_mask[i] = MASK_Num;
		i++;
		Mask_token = strtok(NULL,".");
	}
	
	//split the ip address
	char temp_ip[ADDRLEN];
	unsigned char splited_ip[ADDRLEN]; //store subnet mask each value (int)
	memcpy(temp_ip, IP, ADDRLEN);
	char *IP_token;
	int IP_Num;
	IP_token = strtok(temp_ip, ".");
	int j = 0;
	while(IP_token != NULL){
		IP_Num = atoi(IP_token);
		splited_ip[j] = IP_Num;
		j++;
		IP_token = strtok(NULL,".");
	}
	
	//find the start and end IP address of the subnet
	int available_ip, segment, start_ip, end_ip;
	if(splited_mask[2] == 255){
		available_ip = 256 - splited_mask[3];
		segment = 256 / available_ip;

		// printf("available_ip :%d\n",available_ip);
		// printf("segment :%d\n",segment);
		
		start_ip = splited_ip[3] & splited_mask[3];
		end_ip = start_ip + available_ip - 1 - 1; //all ones is reserved for broadcast
		start_ip++; //all zero is reserved
	}

	// printf("%d\n",start_ip);
	// printf("%d\n",end_ip);

	if(argc == 5){
		if(!strcmp(argv[0],"./ipscanner") && !strcmp(argv[1],"-i") && !strcmp(argv[3],"-t")){
			for(int i=start_ip; i<=end_ip; i++){
				char full_IP[30];
				sprintf(full_IP, "%d.%d.%d.%d", splited_ip[0], splited_ip[1], splited_ip[2], i);

				//set socket
				if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0){
					perror("socket");
					exit(1);
				}
				//set socket option
				if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
					perror("setsockopt");
					exit(1);
				}

				//set ICMP data section and destination IP address
				char data[20] = "M113040064";
				destination.sin_family = AF_INET;
				destination.sin_addr.s_addr = inet_addr(full_IP);
				
				//print out the ping result
				printf("------------------------------------------------------------\n");
				printf("ping host %s\n", full_IP);
				printf("data size = %ld, ping_seq = %d, id = 0x%x, timeout = %d ms\n", sizeof(packet.icmp_all.icmp_data), icmp_req, pid, timeout);
				printf("------------------------------------------------------------\n");

				//fill ip and icmp header
				fill_icmphdr(&packet.icmp_all, data);
				fill_iphdr(&packet.ip_hdr, full_IP, IP, sizeof(packet));

				unsigned long timeUsec;
				unsigned long timeSec;

				//set timer
				gettimeofday(&start, NULL);
				if(sendto(sockfd, &packet, sizeof(packet), 0, &destination, sizeof(destination)) < 0){
					perror("sendto");
					exit(1);
				}

				if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_ICMP)) < 0){
					perror("socket");
					exit(1);
				}

				Time.tv_sec = timeout / 1000;
				bzero(&destination, sizeof(destination));

				while(1){
					//Unreachable
					setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&Time, sizeof(struct timeval));
					if(recvfrom(sockfd, &packet, sizeof(packet), 0, NULL, NULL) < 0){
						printf("Destination Unreachable\n\n\n");
						break;
					}

					gettimeofday(&stop, NULL);
					timeSec = stop.tv_sec - start.tv_sec;
					timeUsec = stop.tv_usec - start.tv_usec;

					//receive from host
					if(ntohs(packet.icmp_all.icmp_type) == ICMP_ECHOREPLY){
						printf("ICMP reply from: %s , time : %ld.%04ld ms\n\n\n",full_IP,timeSec,timeUsec);
						break;
					}	
				}
				icmp_req++;
			}
		}
		else{
			printf("Plaese input valid command!");
			print_usage();
			exit(1);
		}
	}
	else{
		printf("Plaese input valid command!");
		print_usage();
		exit(1);
	}
	return 0;
}