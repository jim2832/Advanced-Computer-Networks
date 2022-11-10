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

uint16_t calculate_checksum(unsigned char* buffer, int bytes){
    uint32_t checksum = 0;
    unsigned char* end = buffer + bytes;

    // odd bytes add last byte and reset end
    if (bytes % 2 == 1) {
        end = buffer + bytes - 1;
        checksum += (*end) << 8;
    }

    // add words of two bytes, one by one
    while (buffer < end) {
        checksum += buffer[0] << 8;
        checksum += buffer[1];
        buffer += 2;
    }

    // add carry if any
    uint32_t carray = checksum >> 16;
    while (carray) {
        checksum = (checksum & 0xffff) + carray;
        carray = checksum >> 16;
    }

    // negate it
    checksum = ~checksum;

    return checksum & 0xffff;
}

int main(int argc, char *argv[]){
    int sd;
    struct icmphdr hdr;
    struct sockaddr_in addr;
    int network_order;
    char buf[1024];
    struct icmphdr *icmphdrptr;
    struct iphdr *iphdrptr;

    if(argc != 2){
        printf("usage: %s IPADDR\n", argv[0]);
        exit(-1);
    }

    addr.sin_family = PF_INET; // IPv4

    // 將使用者輸入的 IP 轉成 network order
    network_order = inet_pton(PF_INET, argv[1], &addr.sin_addr);
    if(network_order < 0){
        perror("inet_pton");
        exit(-1);
    }

    // 開一個 IPv4 的 RAW Socket , 並且準備收取 ICMP 封包
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sd < 0){
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

    // 計算出 checksum
    hdr.checksum = checksum((unsigned short*)&hdr, sizeof(hdr));

    // 將定義好的 ICMP Header 送到目標主機
    network_order = sendto(sd, (char*)&hdr, sizeof(hdr), 0, (struct sockaddr*)&addr, sizeof(addr));
    if(network_order < 1){
        perror("sendto");
        exit(-1);
    }
    printf("We have sended an ICMP packet to %s\n", argv[1]);

    // 清空 buf
    memset(buf, 0, sizeof(buf));

    printf("Waiting for ICMP echo...\n");

    // 接收來自目標主機的 Echo Reply
    network_order = recv(sd, buf, sizeof(buf), 0);
    if(network_order < 1){
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
            printf("The host %s is a unreachable purpose!\n", argv[1]);
            printf("The ICMP type is %d\n", icmphdrptr->type);
            printf("The ICMP code is %d\n", icmphdrptr->code);
            break;
        case 8:
            printf("The host %s is alive!\n", argv[1]);
            printf("The ICMP type is %d\n", icmphdrptr->type);
            printf("The ICMP code is %d\n", icmphdrptr->code);
            break;
        case 0:
            printf("The host %s is alive!\n", argv[1]);
            printf("The ICMP type is %d\n", icmphdrptr->type);
            printf("The ICMP code is %d\n", icmphdrptr->code);
            break;
        default:
            printf("Another situations!\n");
            printf("The ICMP type is %d\n", icmphdrptr->type);
            printf("The ICMP code is %d\n", icmphdrptr->code);
            break;
    }

    close(sd); // 關閉 socket
    return EXIT_SUCCESS;
}