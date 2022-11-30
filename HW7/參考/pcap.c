#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>




extern struct timeval stop;

static char* dev;
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p;

static struct pcap_pkthdr hdr;

static char fixed_filter[FILTER_STRING_SIZE] = "";
/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */

void pcap_init( const char* dst_ip ,int timeout )
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];  //error buffer point
	strcat(filter_string,dst_ip);
	//memcpy(&dev,Device_Name,sizeof(dev));
	const u_char *ptr;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	
	struct in_addr addr;
	struct bpf_program fcode;

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{
	   printf("%s\n",errbuf);
	   exit(1);
	}
	printf("DEV: %s\n",dev);


	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}

	addr.s_addr = netp;
	net = inet_ntoa(addr);	//返回十進制的字符串在靜態內存中的指針,將網路地址轉換成“.”點隔的字符串格式
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	printf("NET: %s\n",net);


	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if(mask == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	printf("MASK: %s\n",mask);
	
	p = pcap_open_live(dev, 65535, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}

	ptr = pcap_next(p, &hdr);
	if(ptr == NULL)
    {
        printf("Didn't grab packet\n");
        exit(1);
    }
   // filter_string = "icmp[icmptype] == icmp-echo and icmp[icmptype] == icmp-echoreply";
	/*
	//destination IP should be router IP
	strcat(strcat(filter_string, "src host "), dst_ip);
	//icmp type should be ping reply packet
	strcat(filter_string, " and icmp[icmptype] == icmp-echoreply");
	//id in icmp packet should be the same as the icmp request
	//proto[expr : size], icmp id is spreading across the 5th and 6th byte
	strcat(filter_string, " and icmp[4:2] == ");
	char tmp[50]; 
	sprintf(tmp, "0x%x", htons(pid));
	strcat(filter_string, tmp);
	strcpy(fixed_filter, filter_string);
	//the sequence number in icmp packet is the same as icmp request
	strcat(filter_string, " and icmp[6:2] == ");
	sprintf(tmp, "0x%x", icmp_req);
	strcat(filter_string, tmp);
	

	 *    you should complete your filter string before pcap_compile
	
	
	printf("Grabbed packet of length %d\n",hdr.len);
    printf("Recieved at ..... %d\n",ctime((const time_t*)&hdr.ts.tv_sec));
    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);
	*/


	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}


int pcap_get_reply( const char* dst_ip )
{
	const u_char *ptr;
	struct bpf_program fcode;
	bpf_u_int32 maskp;

	strcpy(filter_string,"icmp[icmptype] == icmp-echo and icmp[icmptype] == icmp-echoreply");
	/*
	//reset the filter because sequence number is increase after each packet
	memset(filter_string, 0, strlen(filter_string));
	strcpy(filter_string, fixed_filter);
	char tmp[50];
	strcat(filter_string, " and icmp[6:2] == ");
    sprintf(tmp, "0x%x", icmp_req);
    strcat(filter_string, tmp);
	//strcat(filter_string, "1");
	inet_aton(mask, (struct in_addr *)&maskp);
	//printf("filter string : %s\n", filter_string);
	//printf("id : %u, seq : %u\n", pid, icmp_req);
	*/

	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	//apply the filter
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
	ptr = pcap_next(p, &hdr);
	/*
	 * google "pcap_next" to get more information
	 * and check the packet that ptr pointed to.
	 * ref:https://www.tcpdump.org/pcap.html
	*/
	//stop = clock();
	if(ptr != NULL){
		stop = hdr.ts;		
		return 1;
	}
	//printf("time = *\n");
	return 0;


}