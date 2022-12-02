#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>

#define	IP_DF 0x4000		/* dont fragment flag */
#define	IP_MF 0x2000		/* more fragments flag */

extern pid_t pid;
extern u16 icmp_req;

void fill_iphdr (struct ip *ip_hdr , const char* dst_ip ,char *sourceIP ,int len){
	ip_hdr -> ip_v = 4; //IPv4
	ip_hdr -> ip_hl = 5; //IP header length
	ip_hdr -> ip_tos = 0; //IP type of service
	ip_hdr -> ip_len = len; //total IP length
	ip_hdr -> ip_id = 0; //IP identification
	ip_hdr -> ip_off = htons(IP_DF); //fragment offset field
	ip_hdr -> ip_ttl = 1; //TTL		
	ip_hdr -> ip_p = IPPROTO_ICMP; //protocol
	//ip_hdr -> ip_sum; //checksum -> OS will do it
	inet_aton(dst_ip, &(ip_hdr->ip_dst));
	inet_aton(sourceIP, &(ip_hdr->ip_src));
}

void fill_icmphdr (struct icmp *icmp_all,char *strData){	
	
	icmp_all -> icmp_type = ICMP_ECHO;
	icmp_all -> icmp_code = 0;
	icmp_all -> icmp_cksum = 0;	
	icmp_all -> icmp_id = htons(pid);
	icmp_all -> icmp_seq = htons(icmp_req);
	sprintf(icmp_all -> icmp_data	,"%s",strData);
	icmp_all -> icmp_cksum =fill_cksum(icmp_all);/* checksum --->let OS automatically do it*/
}

unsigned short fill_cksum(struct icmp *icmp_packet){
	unsigned long sum = 0;  /* assume 32 bit long, 16 bit short */
    unsigned short *buffer = (unsigned short*) icmp_packet;
    int len = sizeof(struct icmp);
	while(len > 1){
    	sum += *buffer;
    	buffer++;
        len -= 2;
    }

    if(len == 1){       /* take care of left over byte */
      	sum += *(unsigned char *)buffer;
    }
    
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}