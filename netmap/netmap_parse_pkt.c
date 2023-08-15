
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_mbuf.h>

#include "common.h"
#include "utils.h"
#include "dpdk_main.h"
#include "netmap.h"
#include "netmap_ip.h"
#include "netmap_parse_pkt.h"


#define IP_MORE_FRAG	(0x0020)		/* network order */

#define IP_IS_FRAG(ip)	(ip->frag_off & (0xff1f | IP_MORE_FRAG))

int net_map_debug = 1;

//解析以太头
int packet_parse_eth(struct rte_mbuf * mbuf){

	char sip1[32], sip2[32];
	struct ethhdr_bm  * mac;

	struct iphdr_bm   *ip;
	int proto;
	//int isboardcast ; 

	mbuf_app_ext * papp; 
	
	if( rte_pktmbuf_data_len(mbuf) < ETH_HLEN )
		return PACKET_DROP;

	
	mac =(struct ethhdr_bm *) (MBUF_DATA(mbuf));
	
	papp = MBUF_APP_EXT(mbuf);
	papp->raw_eth = (unsigned char *)mac;

	proto = ntohs(mac->h_proto);
	if(proto  == ETH_P_IP)
	{
		if(rte_pktmbuf_data_len(mbuf) < ETH_HLEN + ETH_MIN_IPHDR_LEN)	
			return PACKET_DROP;
		papp->layer_offset = ETH_HLEN; //不支持vlan
		ip = (struct iphdr_bm	 *)(MBUF_DATA(mbuf) + ETH_HLEN);
		papp->raw_ip = (unsigned char *)ip;
		if(net_map_debug){
			printf("%s %d, recv ip pkt 0x%x:%s->%s\n", __FILE__,__LINE__,mbuf, GETIPSTRING(ip->saddr, sip1), GETIPSTRING(ip->daddr, sip2));
		}
		return PACKET_CONN;
	}
	else if(proto == ETH_P_ARP){
		struct arphdr * parp = (struct arphdr*)(MBUF_DATA(mbuf) + ETH_HLEN);
		if(net_map_debug){
			snprintf(sip1, sizeof(sip1), "%d.%d.%d.%d",parp->ar_sip[0],parp->ar_sip[1],parp->ar_sip[2],parp->ar_sip[3]);
			snprintf(sip2, sizeof(sip2), "%d.%d.%d.%d",parp->ar_tip[0],parp->ar_tip[1],parp->ar_tip[2],parp->ar_tip[3]);
			printf("%s %d recv arp pkt:0x%x,sip:%s->%s\n", __FILE__,__LINE__,mbuf, sip1, sip2);
		}
		return PACKET_INJECT;
	}

	return PACKET_DROP;

}


int packet_parse_ip(struct rte_mbuf * mbuf, int dir){

	struct iphdr_bm   *ip;
	mbuf_app_ext * papp; 
	

	
	papp = MBUF_APP_EXT(mbuf);
	
	if( rte_pktmbuf_data_len(mbuf) -papp->layer_offset < ETH_MIN_IPHDR_LEN )
		return PACKET_DROP;
	
	ip = (struct iphdr_bm *)papp->raw_ip;

	papp->ipfrag = IP_IS_FRAG(ip);
	
	
	if(ip->protocol == TCP_PROT){
	
		unsigned short iplen = ip->ihl;
		iplen = (ip->ihl << 2);
		struct tcptype * tcph  =  (struct tcptype *) ((char*)ip + iplen);

		if(papp->ipfrag) PACKET_INJECT;
		
	
		unsigned short dport = tcph->dport;
		unsigned short sport = tcph->sport;	
		
		papp->dport = dport;
		papp->sport = sport;
		papp->daddr = ip->daddr;
		papp->saddr = ip->saddr;
		if(dir == dir_inside && dport != htons(443)) {
			return PACKET_INJECT;
		}
		return PACKET_CONN;
	}
	else if(ip->protocol == ICMP_PROT){
		
		return PACKET_INJECT; 
		
	} else if(ip->protocol == UDP_PROT){
			return PACKET_INJECT; 

	}
	
	return PACKET_INJECT; ;
}

int netmap_parse_packet(struct rte_mbuf * mbuf, int dir){
	int ret;
	ret  = packet_parse_eth(mbuf);
	
	if(ret != PACKET_CONN) return ret;

	ret = packet_parse_ip(mbuf,dir);
	return ret;
}