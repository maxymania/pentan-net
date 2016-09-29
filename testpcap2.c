// this file is changed.
// This file has been modified by Simon Schmidt
/**********************************************************************
* file:   testpcap2.c
* date:   2001-Mar-14 12:14:19 AM 
* Author: Martin Casado
* Last Modified:2001-Mar-14 12:14:11 AM
*
* Description: Q&D proggy to demonstrate the use of pcap_loop
*
**********************************************************************/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include <ppe/ethernet.h>
#include <ppe/ipv4.h>
#include <ppe/ip.h>
#include <ppe/ip_ph.h>
#include <ppe/phlite.h>
#include <ppe/tcp.h>
#include <ppe/udp.h>

/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	ppeBuffer BUFFER;
	Eth_FrameInfo eth_info;
	//IPV4_PacketInfo ip4_info;
	IPPH_Struct ip_info;
	IPPH_Info   ip_phsum;
	TCP_SegmentInfo tcp_info;
	UDP_PacketInfo udp_info;
	int result,i;
    static int count = 1;
    fprintf(stdout,"%d, ",count);
    //if(count == 4)
        //fprintf(stdout,"Come on baby sayyy you love me!!! ");
    //if(count == 7)
        //fprintf(stdout,"Tiiimmmeesss!! ");
	BUFFER.begin = BUFFER.position = (void*)(packet);
	BUFFER.end = BUFFER.limit = (BUFFER.begin + (pkthdr->len));
	result = ppe_parsePacket_eth(&BUFFER,&eth_info,0);
	//for(i = 0;i<pkthdr->len && i<20; ++i)
	//	fprintf(stdout,"%02x",(int)(packet[i]));
	
	if(result)goto my_error;

	switch(eth_info.type){
	case Eth_IPv4:
		fprintf(stdout,"IPv4 ");
		ip_info.ipphType = IPPH_IPv4;
		result = ppe_parsePacket_ipv4(&BUFFER,&ip_info.ipv4);
		ppe_ipphChecksum(&ip_info,&ip_phsum);
		if(result)goto my_error;
		switch(ip_info.ipv4.protocol) {
			case IPProto_TCP:
				tcp_info.phCheckSum = ip_phsum;
				result = ppe_parsePacket_tcp(&BUFFER,&tcp_info);
				if(result)goto my_error;
				fprintf(stdout," TCP [%d->%d]"
								,(int)tcp_info.ports[0]
								,(int)tcp_info.ports[1]);
				break;
			case IPProto_UDP:
				udp_info.phCheckSum = ip_phsum;
				result = ppe_parsePacket_udp(&BUFFER,&udp_info);
				if(result)goto my_error;
				fprintf(stdout," UDP [%d->%d]"
								,(int)udp_info.ports[0]
								,(int)udp_info.ports[1]);
				break;
			default:
				fprintf(stdout," Unknown (P:%02x)",(int)ip_info.ipv4.protocol);
		}
	}
	
	fprintf(stdout,"\n");
    fflush(stdout);
    count++;
	return;
	my_error:
	fprintf(stdout,"ERROR(%d) \n",result); fflush(stdout); count++; return;
}

int main(int argc,char **argv)
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */

    if(argc != 2){ fprintf(stdout,"Usage: %s numpackets\n",argv[0]);return 0;}

    /* grab a device to peak into... */
    //dev = pcap_lookupdev(errbuf);
    //if(dev == NULL)
    //	{ printf("%s\n",errbuf); exit(1); }
    /* open device for reading */
    //descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
	descr = pcap_open_offline("../pcap_example.pcap",errbuf);



    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

    /* allright here we call pcap_loop(..) and pass in our callback function */
    /* int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)*/
    /* If you are wondering what the user argument is all about, so am I!!   */
    pcap_loop(descr,atoi(argv[1]),my_callback,NULL);

    fprintf(stdout,"\nDone processing packets... wheew!\n");
    return 0;
}
