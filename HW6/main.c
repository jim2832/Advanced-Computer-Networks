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
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

unsigned short checksum(unsigned short *buffer, int buffersz){
    unsigned long sum = 0xffff;

    while(buffersz > 1){
        sum += *buffer;
        buffer++;
        buffersz -= 2;
    }

    if(buffersz == 1)
        sum += *(unsigned char*)buffer;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int main(int argc, char **argv){
    struct sockaddr_in IP_send_header; //發送的IP header
    struct iphdr *IP_recv_header; //接收的IP header
    struct icmphdr ICMP_send_header; //發送的ICMP header
    struct icmphdr *ICMP_recv_header; //接收的ICMP header

    int network_number;
    int soc_send, soc_recv;
    char buffer[1024];
    int TTL = 1;
    int max_hopping = atoi(argv[1]);
    char target_addr[32];
    memcpy(target_addr, argv[2], 32);

    //determine the login identity
	if(geteuid() != 0){
		printf("%s\n","ERROR: You must be root to use this tool!");
		exit(1);
	}

    // 將使用者輸入的 IP 轉成 network order
    network_number = inet_pton(PF_INET, argv[2], &IP_send_header.sin_addr);
    if(network_number < 0){
        perror("inet_pton");
        exit(-1);
    }

    //send socket
    soc_send = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(soc_send < 0){
        perror("socket");
        exit(-1);
    }

    //receive socket
    soc_recv = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(soc_recv < 0){
        perror("socket");
        exit(-1);
    }

    // 清空結構內容
    memset(&ICMP_send_header, 0, sizeof(ICMP_send_header));
    
    //設定每個封包的TTL
    setsockopt(soc_send, IPPROTO_IP, IP_TTL, (char *)&TTL, sizeof(TTL));

    // 初始化 ICMP Header
    ICMP_send_header.type = ICMP_ECHO;
    ICMP_send_header.code = 0;
    ICMP_send_header.checksum = 0;
    ICMP_send_header.un.echo.id = 0;
    ICMP_send_header.un.echo.sequence = 0;
    ICMP_send_header.checksum = checksum((unsigned short*)&ICMP_send_header, sizeof(ICMP_send_header)); //計算checksum

    // 將定義好的 ICMP Header 送到目標主機
    network_number = sendto(soc_send, (char*)&ICMP_send_header, sizeof(ICMP_send_header), 0, (struct sockaddr*)&IP_send_header, sizeof(IP_send_header));
    if(network_number < 1){
        perror("sendto");
        exit(-1);
    }
    else{
        printf("an ICMP packet has been sent to %s\n", argv[2]);
    }

    //expanding ring search
    for(TTL=1; TTL<max_hopping; TTL++){
        // 清空 bufferfer
        memset(buffer, 0, sizeof(buffer));

        printf("Waiting for ICMP echo reply...\n");

        // 接收來自目標主機的 Echo Reply
        network_number = recv(soc_recv, buffer, sizeof(buffer), 0);
        if(network_number < 1){
            perror("recv");
            exit(-1);
        }

        // 取出 IP Header
        IP_recv_header = (struct iphdr*)buffer;
        // 取出 ICMP Header
        ICMP_recv_header = (struct icmphdr*)(buffer+(IP_recv_header->ihl)*4);

        // 判斷 ICMP 種類
        switch(ICMP_recv_header->type){
            //ICMP echo reply
            case 0:
                printf("The host %s is alive!\n", argv[2]);
                printf("The ICMP type is %d\n", ICMP_recv_header->type);
                printf("The ICMP code is %d\n", ICMP_recv_header->code);
                break;
            //time exceed
            case 11:
                printf("time exceeded!\n");
                printf("The ICMP type is %d\n", ICMP_recv_header->type);
                printf("The ICMP code is %d\n", ICMP_recv_header->code);
                break;
            default:
                printf("Another situations!\n");
                printf("The ICMP type is %d\n", ICMP_recv_header->type);
                printf("The ICMP code is %d\n", ICMP_recv_header->code);
                break;
        }
        printf("\n");
    }
    return EXIT_SUCCESS;
}
