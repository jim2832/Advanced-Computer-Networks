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
    int num;
    char buf[1024];
    struct icmphdr *icmphdrptr;
    struct iphdr *iphdrptr;

    if(argc != 2){
        printf("usage: %s IPADDR\n", argv[0]);
        exit(-1);
    }

    addr.sin_family = PF_INET; // IPv4

    // 將使用者輸入的 IP 轉成 network order
    num = inet_pton(PF_INET, argv[1], &addr.sin_addr);
    if(num < 0){
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
    num = sendto(sd, (char*)&hdr, sizeof(hdr), 0, (struct sockaddr*)&addr, sizeof(addr));
    if(num < 1){
        perror("sendto");
        exit(-1);
    }
    printf(KYEL"We have sended an ICMP packet to %s\n", argv[1]);

    // 清空 buf
    memset(buf, 0, sizeof(buf));

    printf(KGRN"Waiting for ICMP echo...\n");

    // 接收來自目標主機的 Echo Reply
    num = recv(sd, buf, sizeof(buf), 0);
    if(num < 1){
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
            printf(KBLU"The host %s is a unreachable purpose!\n", argv[1]);
            printf(KBLU"The ICMP type is %d\n", icmphdrptr->type);
            printf(KBLU"The ICMP code is %d\n", icmphdrptr->code);
            break;
        case 8:
            printf(KRED"The host %s is alive!\n", argv[1]);
            printf(KRED"The ICMP type is %d\n", icmphdrptr->type);
            printf(KRED"The ICMP code is %d\n", icmphdrptr->code);
            break;
        case 0:
            printf(KRED"The host %s is alive!\n", argv[1]);
            printf(KRED"The ICMP type is %d\n", icmphdrptr->type);
            printf(KRED"The ICMP code is %d\n", icmphdrptr->code);
            break;
        default:
            printf(KMAG"Another situations!\n");
            printf(KMAG"The ICMP type is %d\n", icmphdrptr->type);
            printf(KMAG"The ICMP code is %d\n", icmphdrptr->code);
            break;
    }

    close(sd); // 關閉 socket
    return EXIT_SUCCESS;
}