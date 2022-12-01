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


pid_t pid;
u16 icmp_req = 1;
struct timeval stop,start,middle;

int ValidIP(const char* str);
int IsNumber(const char* str);

void print_usage()
{
	printf("Please enter the following command.\n");
	printf("sudo ./ipscanner –i [Network Interface Name] -t [timeout(ms)]\n");
}

int main(int argc, char* argv[])
{
	int sockfd;
	int on = 1;
	int sockfd_send;
	int sockfd_recv;
	
	pid = getpid();
	struct sockaddr_in dst;
	//struct ifreq icmp_req;
	
	struct in_addr myip,mymask;
	struct ifreq req_local; 
	in_addr_t target_ip_default;
	char device_name[100];
	
	myicmp packet,packet_recv;
	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	char *dstIP, *gatewayIP;
	/* 
	 * in pcap.c, initialize the pcap
	 */
	strcpy(device_name,argv[2]);
	timeout = atoi(argv[4]);
	strcpy(req_local.ifr_name,device_name);

	if(geteuid() != 0){
			printf("%s\n","ERROR: You must be root to use this tool!");
			exit(1);
	}
	if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
			perror("open send socket error");
			exit(1);
	}
	/* get ip address of my interface */
    if(ioctl(sockfd_send, SIOCGIFADDR, &req_local) < 0) {
        perror("ioctl SIOCGIFADDR error");
        myip.s_addr = 0;
    }
    else {
        memcpy(&dst,&req_local.ifr_addr,sizeof(dst));
        myip = dst.sin_addr;
    }

	 /*get network mask of my interface */
	if( ioctl(sockfd_send,SIOCGIFNETMASK, &req_local)== -1){
		perror("SIOCGIFADDR ERROR");
		exit(1);
		mymask.s_addr = 0;
	}
	else{
		memcpy(&dst,&req_local.ifr_addr,sizeof(dst));
        mymask = dst.sin_addr;
	}
	//printf("myip = %u \n",myip );
	//printf("mymask = %u \n",mymask);
	//printf("device = %s \n",device_name);
	//printf("timeout = %d \n",timeout);
	char str_IP[INET_ADDRSTRLEN];
	char str_Mask[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &myip, str_IP, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &mymask, str_Mask, INET_ADDRSTRLEN);
	//printf("myip = %s \n",str_IP );
	//printf("mymask = %s \n",str_Mask);
	
	char maskStr[30];
	unsigned char	Target_Mask[30]; //store subnet mask each value (int)
	memcpy(maskStr, str_Mask, 30);
	char *Mask_token;
	int MASK_Num;
	Mask_token = strtok(maskStr, ".");
	int i=0;
	while( Mask_token != NULL) 
	{
		MASK_Num = atoi(Mask_token);
		Target_Mask[i] = MASK_Num;
		i++;
		Mask_token = strtok(NULL,".");
	}

	char ipStr[30];
	unsigned char 	Target_IP[30]; //store subnet mask each value (int)
	memcpy(ipStr, str_IP, 30);
	char *IP_token;
	int IP_Num;
	IP_token = strtok(ipStr, ".");
	int j=0;
	while( IP_token != NULL) 
	{
		IP_Num = atoi(IP_token);
		Target_IP[j] = IP_Num;
		j++;
		IP_token = strtok(NULL,".");
	}
	
	int ableIP,netSeg,startMask,endMask;
	if(Target_Mask[2] == 255){
		
		ableIP = 256 - Target_Mask[3];
		netSeg = 256 / ableIP;

		//printf("ableIP :%d\n",ableIP);
		//printf("netSeg :%d\n",netSeg);
		if(netSeg == 1){
			startMask =0+1;
			endMask = 255-1;
		}
		else if(netSeg == 2){
			if( Target_IP[3]<128){
				startMask =0+1;
				endMask = 128-1;
			}
			else{
				startMask =128;
				endMask = 255-1;
			}
		}
		else if(netSeg == 4){
			if(Target_IP[3]<64){
				startMask =0+1;
				endMask = 63-1;
			}
			else if(Target_IP[3]>63 && Target_IP[3]<128){
				startMask =64+1;
				endMask = 127-1;
			}
			else if(Target_IP[3]>127 && Target_IP[3]<192){
				startMask =128+1;
				endMask = 191-1;
			}
			else if(Target_IP[3]>191 && Target_IP[3]<256){
				startMask =191+1;
				endMask = 255-1;
			}
		}
		else if(netSeg == 8){
			if(Target_IP[3]<32){
				startMask =0+1;
				endMask = 31-1;
			}
			else if(Target_IP[3]>31 && Target_IP[3]<64){
				startMask =32+1;
				endMask = 63-1;
			}
			else if(Target_IP[3]>63 && Target_IP[3]<96){
				startMask =64+1;
				endMask = 95-1;
			}
			else if(Target_IP[3]>95 && Target_IP[3]<128){
				startMask =96+1;
				endMask = 127-1;
			}
			else if(Target_IP[3]>127 && Target_IP[3]<160){
				startMask =128+1;
				endMask = 159-1;
			}
			else if(Target_IP[3]>159 && Target_IP[3]<192){
				startMask =160+1;
				endMask = 191-1;
			}
			else if(Target_IP[3]>191 && Target_IP[3]<224){
				startMask =192+1;
				endMask = 223-1;
			}
			else if(Target_IP[3]>223 && Target_IP[3]<256){
				startMask =224+1;
				endMask = 255-1;
			}
		}
	}
	//printf("%d\n",startMask);
	//printf("%d\n",endMask );

	if(argc == 5){
		if(!strcmp(argv[0],"./ipscanner") && !strcmp(argv[1],"-i") && !strcmp(argv[3],"-t"))
		{	
			

			for(int i=startMask;i<=endMask;i++){
				char testIP[30];
				sprintf(testIP,"%d.%d.%d.%d",Target_IP[0],Target_IP[1],Target_IP[2],i);
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

				char data[20] = "M073040023";
				dst.sin_family = AF_INET;
				//memcpy(testIP,"10.0.2.2",sizeof(testIP));
				dst.sin_addr.s_addr = inet_addr(testIP);
				
				printf("Ping %s (data size = %ld, id = 0x%x, seq = %d, timeout = %d ms)\n", testIP, sizeof(packet.icmp_all.icmp_data),pid,icmp_req,timeout);

				//fill ip and icmp header
				fill_icmphdr(&packet.icmp_all,data);
				fill_iphdr(&packet.ip_hdr, testIP,str_IP,sizeof(packet));
				unsigned long timeUsec;
				unsigned long timeSec;
				//set timer
				gettimeofday(&start, NULL);
				if(sendto(sockfd, &packet, sizeof(packet), 0, &dst, sizeof(dst)) < 0)
				{
					perror("sendto");
					exit(1);
				}

				if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_ICMP)) < 0)
				{
					perror("socket");
					exit(1);
				}
				middle.tv_sec = timeout/1000;
				bzero(&dst,sizeof(dst));
				//int status=1;
				while(1){
					if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&middle,sizeof(struct timeval)) == -1){
						
			    	}
			    		if(recvfrom(sockfd, &packet, sizeof(packet), 0,  NULL, NULL) < 0){
				            printf("Destination Unreachable\n\n");
				            break;
						}
						gettimeofday(&stop, NULL);
						timeSec = stop.tv_sec-start.tv_sec;
						timeUsec =(stop.tv_usec-start.tv_usec);
						if(ntohs(packet.icmp_all.icmp_type) == ICMP_ECHOREPLY )
			        	{
			            	printf("Reply from : %s , time : %ld.%04ld ms\n\n",testIP,timeSec,timeUsec);
			            	break;
			        	}	
				}
				icmp_req++;
				
			}
		}
		else{
				print_usage();
				exit(1);
		}
	}
	else{
		print_usage();
		exit(1);
	}

	return 0;
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