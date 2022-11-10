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

unsigned short checksum(unsigned short *buf, int bufsz){
    unsigned long sum = 0xffff;

    while(bufsz > 1){
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if(bufsz == 1)
        sum += *(unsigned char*)buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int main(int argc, char **argv){
    int soc;
    struct icmphdr hdr;
    struct sockaddr_in addr;
    int network_number;
    char buf[1024];
    struct icmphdr *icmphdrptr;
    struct iphdr *iphdrptr;
    int TTL = 0;
    int max_hopping = atoi(argv[1]);
    char target_addr[32];
    memcpy(target_addr, argv[2], 32);

    addr.sin_family = PF_INET; // IPv4

    // 將使用者輸入的 IP 轉成 network order
    network_number = inet_pton(PF_INET, argv[2], &addr.sin_addr);
    if(network_number < 0){
        perror("inet_pton");
        exit(-1);
    }

    //創建一個socket收取ICMP封包
    soc = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(soc < 0){
        perror("socket");
        exit(-1);
    }

    // 清空結構內容
    memset(&hdr, 0, sizeof(hdr));

    // 初始化 ICMP Header
    hdr.type = ICMP_ECHO;
    hdr.code = 0;
    hdr.checksum = 0;
    hdr.un.echo.id = 0;
    hdr.un.echo.sequence = 0;
    hdr.checksum = checksum((unsigned short*)&hdr, sizeof(hdr)); //計算checksum

    for(TTL=1; TTL<max_hopping; TTL++){
        printf("Now the TTL is %d\n", TTL);
        setsockopt(fd, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(ttl)); //set ttl  on all sockets
        // 將定義好的 ICMP Header 送到目標主機
        network_number = sendto(soc, (char*)&hdr, sizeof(hdr), 0, (struct sockaddr*)&addr, sizeof(addr));
        if(network_number < 1){
            perror("sendto");
            exit(-1);
        }
        printf("an ICMP packet has been sent to %s\n", argv[2]);

        // 清空 buf
        memset(buf, 0, sizeof(buf));

        printf("Waiting for ICMP echo reply...\n");

        // 接收來自目標主機的 Echo Reply
        network_number = recv(soc, buf, sizeof(buf), 0);
        if(network_number < 1){
            perror("recv");
            exit(-1);
        }

        // 取出 IP Header
        iphdrptr = (struct iphdr*)buf;

        // 取出 ICMP Header
        icmphdrptr = (struct icmphdr*)(buf+(iphdrptr->ihl)*4);

        // 判斷 ICMP 種類
        switch(icmphdrptr->type){
            case 3:
                printf("address %s: Destination Unreachable\n", argv[2]);
                printf("The ICMP type is %d\n", icmphdrptr->type);
                printf("The ICMP code is %d\n", icmphdrptr->code);
                break;
            case 8:
                printf("The host %s is alive!\n", argv[2]);
                printf("The ICMP type is %d\n", icmphdrptr->type);
                printf("The ICMP code is %d\n", icmphdrptr->code);
                break;
            case 0:
                printf("The host %s is alive!\n", argv[2]);
                printf("The ICMP type is %d\n", icmphdrptr->type);
                printf("The ICMP code is %d\n", icmphdrptr->code);
                break;
            default:
                printf("Another situations!\n");
                printf("The ICMP type is %d\n", icmphdrptr->type);
                printf("The ICMP code is %d\n", icmphdrptr->code);
                break;
        }
        printf("\n");
        }
        close(soc); // 關閉 socket
        return EXIT_SUCCESS;
    }
