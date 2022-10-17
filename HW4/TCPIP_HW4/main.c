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
	int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq req;
	// struct in_addr myip;
	
	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}

	if(argc == 4 || argc == 3 || argc == 2){
		if(!strcmp(argv[0], "./arp")){
			if(!strcmp(argv[1], "-help") || !strcmp(argv[1], "-h") ){
				print_usage();
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