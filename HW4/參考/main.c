#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
//#include <sys/sysctl.h>


/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp2s0f5"
#define PACKET_SIZE 2000
#define ETH_PALEN 4
#define ETH_HALEN 6
#define ETHERTYPE_ARP 0x0806
#define ARP_HRD_ETHER 0x0001
#define ETHERTYPE_IP 0x0800
#define ARP_OP_REQUEST 0x0001
#define ARP_OP_REPLY 0x0002
/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

int main(int argc, char **argv)
{

	int 				sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll  sa;
	struct ifreq        req,req_mac,req_ip;
	struct ether_addr   Src_haddr,Dst_haddr,Arp_Src_haddr,Arp_Dst_haddr;
	socklen_t 	addr_len = sizeof(sa);
	struct 		arp_packet arp_packet_send,arp_packet_recv;
	u_int8_t 	arp_packetS[PACKET_SIZE];
	u_int8_t 	arp_packetR[PACKET_SIZE];
	u_int8_t	Not_Know_Mac_Addr[ETH_HALEN]={0x00,0x00,0x00,0x00,0x00,0x00};

	int 			recv_length,send_length;
	char 			tell_ip[32],has_ip[32],Mac_Addr[32],recv_SHA[32],recv_SPA[32],recv_TPA[32];
	unsigned char 	Source_MAC[ETH_ALEN],Source_IP[ETH_ALEN];
	unsigned char 	Target_IP[30];
	unsigned char 	Source_MAC_Addr[ETH_ALEN];
	in_addr_t       Arp_Src_IP,Arp_Dst_IP;

	if(geteuid() != 0){
			printf("%s\n","ERROR: You must be root to use this tool!");
			exit(1);
	}
	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}
	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 */
	if(argc == 4 || argc == 3 || argc == 2)
	{
		if(!strcmp(argv[0],"./arp"))
		{
			if(!strcmp(argv[1],"-help") || !strcmp(argv[1],"-h") )
			{
					print_usage();
					exit(1);
			}
			else if(!strcmp(argv[1],"-l"))
			{
				printf("%s\n","[ ARP sniffer and spoof program ]");
				printf("%s\n","#### ARP sniffer mode ####");
				while(1){

					if((recv_length = recvfrom(sockfd_recv,(void*) &arp_packet_recv,sizeof(struct arp_packet), 0, NULL, NULL)) < 0){
						perror("recvfrom error");
						exit(1);
					} //change arp_packet_send
					memcpy(arp_packetR, (void*) &arp_packet_recv,sizeof(struct arp_packet));//copy struct arp_packet into arp_packet array
					if((arp_packetR[12] == 8 && arp_packetR[13] == 6)){

						strcpy(tell_ip,get_sender_protocol_addr( &(arp_packet_recv.arp)));
						strcpy(has_ip,get_target_protocol_addr( &(arp_packet_recv.arp)));

						if(!strcmp(argv[2],"-a")){
							printf("Get ARP packet - who has %s ? \t Tell %s \n",has_ip,tell_ip);
							//free(tell_ip);free(has_ip);
						}else if(strlen(argv[2])>=7&&strlen(argv[2])<=15){

							if(!strcmp(argv[2],has_ip)){
								printf("Get ARP packet - who has %s ? \t Tell %s \n",has_ip,tell_ip);
							}
						}
						else{
							printf("\n Error command!! \n");
							exit(1);
						}

					}
				}
			}
			else if(!strcmp(argv[1],"-q"))
			{
				printf("%s\n","[ ARP sniffer and spoof program ]");
				printf("%s\n","#### ARP query mode ####");
					if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
					{
						perror("open send socket error");
						exit(1);
					}

					memset(&req,0,sizeof(req));
					strcpy(req.ifr_name,DEVICE_NAME);

					memset(&req_ip,0,sizeof(req_ip));
					strcpy(req_ip.ifr_name,DEVICE_NAME);

					memset(&req_mac,0,sizeof(req_mac));
					strncpy(req_mac.ifr_name,DEVICE_NAME, ETH_ALEN);

					if( ioctl(sockfd_send,SIOCGIFINDEX, &req)== -1){
						perror("SIOCGIFINDEX ERROR");
						exit(1);
					}
					//printf("INDEX=>%d\n",req.ifr_ifindex);

					if( ioctl(sockfd_send,SIOCGIFADDR, &req_ip)== -1){
						perror("SIOCGIFADDR ERROR");
						exit(1);
					}
					memcpy(Source_IP, req_ip.ifr_addr.sa_data+2, ETH_HALEN);
					/*for(int i =0;i<6;i++){
						printf("IP= No.%d =>%d\n",i,Source_IP[i]);
					}*/

					//printf("\n");
					if( ioctl(sockfd_send,SIOCGIFHWADDR, (void*) &req_mac)== -1){
						perror("SIOCGIFHWADDR ERROR");
						exit(1);
					}
					memcpy(Source_MAC, req_mac.ifr_hwaddr.sa_data, ETH_HALEN);
					memcpy(arp_packet_send.eth_hdr.ether_shost, req_mac.ifr_hwaddr.sa_data, ETH_HALEN);
				/*
	 			 * Use ioctl function binds the send socket and the Network Interface Card.
`				 * ioctl( ... )
				 */
					arp_packet_send.eth_hdr.ether_dhost[0] = 0xff;
					arp_packet_send.eth_hdr.ether_dhost[1] = 0xff;
					arp_packet_send.eth_hdr.ether_dhost[2] = 0xff;
					arp_packet_send.eth_hdr.ether_dhost[3] = 0xff;
					arp_packet_send.eth_hdr.ether_dhost[4] = 0xff;
					arp_packet_send.eth_hdr.ether_dhost[5] = 0xff;

					memcpy(Source_MAC_Addr,arp_packet_send.eth_hdr.ether_dhost,ETH_HALEN);
					memcpy(arp_packet_send.eth_hdr.ether_shost,req_mac.ifr_hwaddr.sa_data,ETH_HALEN);
					arp_packet_send.eth_hdr.ether_type = htons(ETHERTYPE_ARP);// arp_packet_send.eth_hdr.ether_type = 0x0608;
					
					set_hard_type(&arp_packet_send.arp, htons(ARP_HRD_ETHER));
	    			set_prot_type(&arp_packet_send.arp, htons(ETHERTYPE_IP));
	    			set_hard_size(&arp_packet_send.arp, ETH_HALEN);
	    			set_prot_size(&arp_packet_send.arp, ETH_PALEN);
	    			set_op_code(&arp_packet_send.arp, htons(ARP_OP_REQUEST));
	    			
					memcpy(arp_packet_send.arp.arp_sha,Source_MAC , ETH_HALEN);			
	    			memcpy(arp_packet_send.arp.arp_spa,Source_IP , ETH_HALEN);
	    			/*myip.s_addr = inet_addr(Source_IP);
	    			set_sender_protocol_addr(&arp_packet_send.arp,inet_ntoa(myip));
	    			printf("%hhn\n",arp_packet_send.arp.arp_spa);*/
					//printf("\n");
					memcpy(arp_packet_send.arp.arp_tha,Not_Know_Mac_Addr ,ETH_HALEN);
					/*for(int i =0;i<6;i++){
	    				printf("THA= No.%d =>%02x\n",i,arp_packet_send.arp.arp_tha[i]);
	    			}*/
	    			//set_target_hardware_addr(&arp_packet_send.arp, "00:00:00:00:00:00");
	    			//printf("%s\n",arp_packet_send.arp.arp_sha);
	    			//printf("\n");
					char Dst_Addr[30];
	    			memcpy(Dst_Addr, argv[2], 30);
	   				char *Addr_token;
	   				int IP_Num;
	   				Addr_token = strtok(Dst_Addr, ".");
	   				int i=0;
	   				while( Addr_token != NULL) 
				   	{
				    	IP_Num = atoi(Addr_token);
						Target_IP[i] = IP_Num;
						i++;
						Addr_token = strtok(NULL,".");
				    }
				    memcpy(arp_packet_send.arp.arp_tpa,Target_IP, ETH_HALEN);
			   	/*for(int i = 0;i < 4;i++){
    				printf("TPA= No.%d =>%d\n",i,arp_packet_s.arp.arp_tpa[i]);
    			}*/
    			/*set_target_protocol_addr(&arp_packet_s.arp, argv[2]);
    			printf("%s\n",arp_packet_s.arp.arp_tpa);
    			printf("\n");
    			bzero(&sa, sizeof(sa));*/
	
				// Fill the parameters of the sa.

					bzero(&sa, sizeof(sa));

					sa.sll_family = AF_PACKET;
					sa.sll_ifindex = if_nametoindex(req.ifr_name);
					sa.sll_protocol = htons(ETH_P_ARP);
					sa.sll_halen = ETHER_ADDR_LEN;
					sa.sll_hatype = htons(ARP_HRD_ETHER);
					sa.sll_pkttype = PACKET_BROADCAST;
			
					sa.sll_addr[0] = 0xff;
					sa.sll_addr[1] = 0xff;
					sa.sll_addr[2] = 0xff;
					sa.sll_addr[3] = 0xff;
					sa.sll_addr[4] = 0xff;
					sa.sll_addr[5] = 0xff;

				/*
				 * use sendto function with sa variable to send your packet out
				 * sendto( ... )
				 */
				
					sendto(sockfd_send, (void*)&arp_packet_send, sizeof(arp_packet_send), 0, (struct sockaddr*)&sa, sizeof(sa));

					while(1){
						
						if(recvfrom(sockfd_recv, &arp_packet_recv, sizeof(arp_packet_recv), 0, (struct sockaddr*)&sa, &addr_len) < 0){
			                printf("ERROR: recv\n");
						}
						if(ntohs(arp_packet_recv.eth_hdr.ether_type) == ETHERTYPE_ARP && arp_packet_recv.arp.arp_op == htons(ARP_OP_REPLY)&& memcmp(arp_packet_recv.arp.arp_spa, arp_packet_send.arp.arp_tpa,ETH_PALEN) == 0)
			            {
			               	printf("MAC address of %u.%u.%u.%u is %02x:%02x:%02x:%02x:%02x:%02x\n",
			                arp_packet_recv.arp.arp_spa[0], 
			                arp_packet_recv.arp.arp_spa[1], 
			                arp_packet_recv.arp.arp_spa[2], 
			                arp_packet_recv.arp.arp_spa[3],

			                arp_packet_recv.arp.arp_sha[0], 
			                arp_packet_recv.arp.arp_sha[1], 
			                arp_packet_recv.arp.arp_sha[2], 
			                arp_packet_recv.arp.arp_sha[3], 
			                arp_packet_recv.arp.arp_sha[4], 
			                arp_packet_recv.arp.arp_sha[5]);
			                exit(1);
			            }
					}
	       	}
	       	else if(!strcmp(argv[1],"00:11:22:33:44:55"))
			{	

				printf("[ ARP sniffer and spoof program ]\n");
				printf("### ARP spoof mode ###\n");
				if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
				{
					perror("open recv socket error");
					exit(1);
				}
				if(strlen(argv[2])>= 7 && strlen(argv[2]) <= 15)
				{		

					while(1)
			        {
						if(recv_length = recvfrom( sockfd_recv, (void *)&arp_packet_recv, sizeof(struct arp_packet), 0, NULL, NULL)<0)
						{	
							perror("recvfrom");
							exit(1);
						}

						memcpy(arp_packetR,(void *)&arp_packet_recv, sizeof(struct arp_packet)); 
						if((arp_packetR[12]==8 && arp_packetR[13]==6))// filter arp_packet 
						{
							memcpy(recv_SHA,get_sender_hardware_addr(&arp_packet_recv.arp),32);
							strcpy(recv_SPA,get_sender_protocol_addr(&arp_packet_recv.arp));
							strcpy(recv_TPA,get_target_protocol_addr(&arp_packet_recv.arp));

							if (!strcmp(argv[2], recv_TPA))
							{
								if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
								{
									perror("open send socket error");
									exit(1);
								}
								ether_aton_r(recv_SHA, &Dst_haddr);
								memcpy(&arp_packet_send.eth_hdr.ether_dhost, &Dst_haddr,ETH_HALEN);//ethernet dst MAC
								ether_aton_r(argv[1], &Src_haddr);
								memcpy(&arp_packet_send.eth_hdr.ether_shost, &Src_haddr,ETH_HALEN);//ethernet src MAC
								arp_packet_send.eth_hdr.ether_type = htons(ETHERTYPE_ARP);

								set_hard_type(&arp_packet_send.arp, htons(ARP_HRD_ETHER));
								set_prot_type(&arp_packet_send.arp, htons(ETHERTYPE_IP));
								set_hard_size(&arp_packet_send.arp, ETH_HALEN);
								set_prot_size(&arp_packet_send.arp, ETH_PALEN);
								set_op_code(&arp_packet_send.arp, htons(ARP_OP_REPLY));//change to op_reply

								ether_aton_r(argv[1], &Arp_Src_haddr);
								memcpy(&arp_packet_send.arp.arp_sha, &Arp_Src_haddr,ETH_HALEN);//sender hardware addr (fake)

								Arp_Src_IP = inet_addr(recv_TPA);
								memcpy(&arp_packet_send.arp.arp_spa, &Arp_Src_IP,ETH_PALEN);

								ether_aton_r(recv_SHA, &Arp_Dst_haddr);
								memcpy(&arp_packet_send.arp.arp_tha, &Arp_Dst_haddr,ETH_HALEN);

								Arp_Dst_IP = inet_addr(recv_SPA);
								memcpy(&arp_packet_send.arp.arp_tpa,&Arp_Dst_IP ,ETH_PALEN);


								memset(&req,0,sizeof(req));
								strcpy(req.ifr_name,DEVICE_NAME);
				
								if((ioctl(sockfd_send,SIOCGIFINDEX,&req)) < 0 )
								{
									perror("SIOCGIFINDEX\n");
									exit(1);
								}

								bzero(&sa,sizeof(sa));
								sa.sll_family = AF_PACKET;
								sa.sll_ifindex = req.ifr_ifindex;
								sa.sll_halen = ETH_HALEN;
								sa.sll_protocol = htons(ETH_P_ARP);
								memcpy(sa.sll_addr,recv_SHA,ETH_HALEN);

								if((sendto(sockfd_send,&arp_packet_send,sizeof(arp_packet_send),0,(struct sockaddr *)&sa,sizeof(sa))) < 0)
								{
									perror("sendto");
								}

								else
								{
									printf("Get ARP packet - who has %s ? \t Tell %s \n",recv_TPA,recv_SPA);
									printf("send ARP reply : %u.%u.%u.%u is %02x:%02x:%02x:%02x:%02x:%02x\n",
			                       arp_packet_send.arp.arp_spa[0], 
			                       arp_packet_send.arp.arp_spa[1], 
			                       arp_packet_send.arp.arp_spa[2], 
			                       arp_packet_send.arp.arp_spa[3],
			                       arp_packet_send.arp.arp_sha[0], 
			                       arp_packet_send.arp.arp_sha[1], 
			                       arp_packet_send.arp.arp_sha[2], 
			                       arp_packet_send.arp.arp_sha[3], 
			                       arp_packet_send.arp.arp_sha[4], 
			                       arp_packet_send.arp.arp_sha[5]);
									printf("send sucessful.\n");
								}

								break;
							}
						}
					}
				}		
						
			}		
	       	else
			{
				printf("%s\n","ERROR: You must be use ./arp.");
				exit(1);
			}
		}
		return 0;
	}
}
void print_usage()
{
	printf("%s\n","[ ARP sniffer and spoof program ]");
	printf("%s\n","Format :");
	printf("%s\n","1) ./arp -l -a");
	printf("%s\n","2) ./arp -l <filter_ip_address>");
	printf("%s\n","3) ./arp -q <query_ip_address>");
	printf("%s\n","4) ./arp <fake_mac_address> <target_ip_address>");
}