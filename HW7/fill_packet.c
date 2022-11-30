#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>


void fill_iphdr(struct ip *ip_hdr ,const char* source_ip, const char* destination_ip, int len){
    ip_hdr -> ip_v = 4; //IPv4
    ip_hdr -> ip_hl = 5; //IP header length
    ip_hdr -> ip_tos = 0; //IP type of service
    ip_hdr -> ip_len = len; //total IP length
    ip_hdr -> ip_id = 0; //IP identification
    ip_hdr -> ip_off = htons(IP_DF); //fragment offset field
	ip_hdr -> ip_ttl = 1; //TTL		
	ip_hdr -> ip_p = IPPROTO_ICMP; //protocol
	//ip_hdr -> ip_sum; //checksum -> OS will do it
	inet_aton(source_ip, &(ip_hdr->ip_src));
	inet_aton(destination_ip, &(ip_hdr->ip_dst));
}

void fill_icmphdr(struct icmphdr *icmp_hdr){
	icmp_hdr->type = ICMP_ECHO;
	icmp_hdr->icmp_id = htons(pid);
	icmp_hdr->icmp_cksum = 0;
	icmp_hdr->icmp_id = htons(pid);
	icmp_hdr->icmp_seq = htons(icmp_req);
	icmp_hdr->icmp_cksum =fill_cksum(icmp_hdr);/* checksum --->let OS automatically do it*/
}

u16 fill_cksum(struct icmphdr* icmp_hdr){
	unsigned long sum = 0; //32 bits -> long, 16 bits -> short
    unsigned short *buffer = (unsigned short*) icmp_hdr;
    int len = sizeof(struct icmp);
	while(len > 1){
    	sum += *buffer;
    	buffer++;
        len -= 2;
    }

    if(len == 1){
      	sum += *(unsigned char *)buffer;
    }
    
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}