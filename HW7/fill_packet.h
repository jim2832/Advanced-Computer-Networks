#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef char u8;
typedef unsigned short u16;
/*
#define PACKET_SIZE    84
#define IP_OPTION_SIZE 0
#define ICMP_PACKET_SIZE   PACKET_SIZE - (int)sizeof(struct ip) - IP_OPTION_SIZE
#define ICMP_DATA_SIZE     ICMP_PACKET_SIZE - (int)sizeof(struct icmphdr)
*/
#define DEFAULT_SEND_COUNT 4
#define DEFAULT_TIMEOUT 1500

extern pid_t pid;
extern u16 icmp_req;

typedef struct{
	struct ip ip_hdr;
	struct icmp icmp_all;
	//struct icmphdr icmp_hdr;
	//struct icmp icmp_all;
	//u8 data[ICMP_DATA_SIZE];
}myicmp ;

void fill_iphdr(struct ip *ip_hdr, const char* dst_ip,char *sourceIP ,int totalLen);

void fill_icmphdr(struct icmp *icmp_all,char *strData);

unsigned short fill_cksum(struct icmp *icmp_packet);
 
#endif