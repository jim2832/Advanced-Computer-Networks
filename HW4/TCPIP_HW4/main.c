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
//#include <sys/sysctl.h>

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp0s31f6" //my device name
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

int main(int argc, char **argv){
	int sockfd_receive = 0, sockfd_send = 0;
	struct sockaddr_ll sa; //socket
	socklen_t address_len = sizeof(sa);
	struct ifreq req,req_mac,req_ip;
	struct ether_addr Src_haddr,Dst_haddr,Arp_Src_haddr,Arp_Dst_haddr;
	struct arp_packet arp_packet_send,arp_packet_receive;
	u_int8_t arp_packetS[PACKET_SIZE];
	u_int8_t arp_packetR[PACKET_SIZE];
	u_int8_t Not_Know_Mac_Addr[ETH_HALEN]={0x00,0x00,0x00,0x00,0x00,0x00};
	struct in_addr myip;

	int 			receive_length,send_length;
	char 			tell_ip[32],has_ip[32],Mac_Addr[32],receive_SHA[32],receive_SPA[32],receive_TPA[32];
	unsigned char 	Source_MAC[ETH_ALEN],Source_IP[ETH_ALEN];
	unsigned char 	Target_IP[30];
	unsigned char 	Source_MAC_Addr[ETH_ALEN];
	in_addr_t       Arp_Src_IP,Arp_Dst_IP;

	//determine the login identity
	if(geteuid() != 0){
		printf("%s\n","ERROR: You must be root to use this tool!");
		exit(1);
	}
	
	// Open a receive socket in data-link layer.
	if((sockfd_receive = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("open receive socket error");
		exit(1);
	}

	if(argc == 2 || argc == 3 || argc == 4){
		if(!strcmp(argv[0], "./arp")){
			//print usage
			if(!strcmp(argv[1], "-help") || !strcmp(argv[1], "-h") ){
				print_usage();
				exit(1);
			}

			//show all of the ARP packets
			else if(!strcmp(argv[1], "-l")){
				printf("[ ARP sniffer and spoof program ]");
				printf("#### ARP sniffer mode ####");
				while(1){
					//error message
					if((receive_length = recvfrom(sockfd_receive,(void*) &arp_packet_receive,sizeof(struct arp_packet), 0, NULL, NULL)) < 0){
						perror("recvfrom error");
						exit(1);
					}
					memcpy(arp_packetR, (void*) &arp_packet_receive, sizeof(struct arp_packet)); //copy the arp struct into array
					//ARP frame type : 0x0806
					if((arp_packetR[12] == 8 && arp_packetR[13] == 6)){
						strcpy(tell_ip,get_sender_protocol_addr(&(arp_packet_receive.arp)));
						strcpy(has_ip,get_target_protocol_addr(&(arp_packet_receive.arp)));
						
						//list all ARP packet
						if(!strcmp(argv[2], "-a")){
							printf("Get ARP packet - who has %s ? \t Tell %s \n",has_ip,tell_ip);
						}

						//list specific ARP packets
						else if(strlen(argv[2]) >= 7 && strlen(argv[2]) <= 15){ //determine whether the IP is valid
							if(!strcmp(argv[2], has_ip)){ //compare arg with target IP
								printf("Get ARP packet - who has %s ? \t Tell %s \n",has_ip,tell_ip);
							}
						}

						//error
						else{
							printf("\n Error command!! \n");
							exit(1);
						}
					}
					else{
						printf("\n Error command!! \n");
						exit(1);
					}
				}
			}

			//ARP request to get the MAC address
			else if(!strcmp(argv[1], "-q")){
				printf("%s\n","[ ARP sniffer and spoof program ]");
				printf("%s\n","#### ARP query mode ####");

				//exception
				if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
				{
					perror("open send socket error");
					exit(1);
				}
			}

			else{
				printf("%s\n","ERROR: You must be use ./arp.");
				exit(1);
			}
		}
	}
	



	
	// Open a send socket in data-link layer.
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}
	
	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
`	 * ioctl( ... )
	 */
	
	

	
	// Fill the parameters of the sa.



	
	/*
	 * use sendto function with sa variable to send your packet out
	 * sendto( ... )
	 */
	
	
	


	return 0;
}

void print_usage(){
	printf("%s\n","[ ARP sniffer and spoof program ]");
	printf("%s\n","Format :");
	printf("%s\n","1) ./arp -l -a");
	printf("%s\n","2) ./arp -l <filter_ip_address>");
	printf("%s\n","3) ./arp -q <query_ip_address>");
	printf("%s\n","4) ./arp <fake_mac_address> <target_ip_address>");
}