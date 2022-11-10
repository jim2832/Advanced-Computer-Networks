#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char **argv){
    int sockfd_recv = 0, sockfd_send = 0;

    //determine the login identity
	if(geteuid() != 0){
		printf("%s\n","ERROR: You must be root to use this tool!");
		exit(1);
	}
	
	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("open recv socket error");
		exit(1);
	}
    if(argc == 4){
        if(!strcmp(argv[0]), "/prog"){

        }
    }
}