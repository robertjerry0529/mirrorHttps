#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h> 
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>



#include <pcap.h>
#include <pthread.h>
#include "common.h"
#include "bsd-queue.h"
#include "netmap_ip.h"
#include "iputils.h"
#include "conn.h"
#include "pktout.h"


/*将报文镜像出去

1. 输入配置参数：
	上行报文镜像接口名称； 目的mac
	下行报文镜像接口名称:        目的mac

外部接口:
	1. 初始化
	2. 配置解析
	3. 报文发送
	4. 连接结束
内部模块：
	1. 连接表组织
	
*/

struct mirror_cfg_t {
	char ifname[12];
	char smac[6];
	char dmac[6];
};

#define EXTERN_API

static struct mirror_cfg_t g_mi_cfg[2];

pcap_t *pcap_handle[2];

unsigned int g_ip_id[2];

EXTERN_API
int mirror_cfg_set(char * i_ifname, char * i_mac, char * o_ifname , char * o_mac){
	int index;
	char *mac ;
	memset(&g_mi_cfg, 0x00, sizeof(g_mi_cfg));


	mac = g_mi_cfg[0].dmac;

	strncpy(g_mi_cfg[0].ifname, i_ifname, sizeof(g_mi_cfg[0].ifname)-1);
	sscanf(i_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]); 
	
	strncpy(g_mi_cfg[1].ifname, o_ifname, sizeof(g_mi_cfg[1].ifname)-1);

	mac = g_mi_cfg[1].dmac;
	sscanf(o_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]); 
	return 1;
	
}



int get_iface_mac(char *dev, char * mac){

	int reqfd, n;

	struct ifreq macreq;

	reqfd = socket(AF_INET, SOCK_DGRAM, 0);

	strcpy(macreq.ifr_name, dev);

	/* 获取本地接口MAC地址*/

	if(ioctl(reqfd, SIOCGIFHWADDR, &macreq) != 0)

		return 1;

	memcpy(mac, macreq.ifr_hwaddr.sa_data, 6);

	close(reqfd);
	return 0;

}

EXTERN_API
int mirror_start(){
	int ret;
	char error_content[PCAP_ERRBUF_SIZE];
	pcap_t * tph;
	
	if(g_mi_cfg[0].ifname[0] == 0 || g_mi_cfg[1].ifname == 0) {
		printf("Error: configuration miss for mirror interface\n");
		return -1;
	}

	ret = get_iface_mac(g_mi_cfg[0].ifname, g_mi_cfg[0].smac);
	if(ret != 0){
		printf("Error: Get iface %s mac address failed\n", g_mi_cfg[0].ifname);
		return -1;
	}
	
	ret = get_iface_mac(g_mi_cfg[1].ifname, g_mi_cfg[1].smac);
	if(ret != 0){
		printf("Error: Get iface %s mac address failed\n", g_mi_cfg[0].ifname);
		return -1;
	}

	conn_init();
	g_ip_id[0] = 123787;
	g_ip_id[1] = 456999;
	
	tph = pcap_open_live(g_mi_cfg[0].ifname, BUFSIZ, 1, 0, error_content);
	if (!tph){
		printf("Error: pcap failed to open iface %s, error: %s\n", g_mi_cfg[0].ifname,error_content);
		return -1;
	}
	pcap_handle[0] = tph;
	if(strcmp(g_mi_cfg[1].ifname,g_mi_cfg[0].ifname ) == 0){
		pcap_handle[1] = tph;
	}
	else {
		tph = pcap_open_live(g_mi_cfg[1].ifname, BUFSIZ, 1, 0, error_content);
		if (!tph){
			printf("Error: pcap failed to open iface %s, error: %s\n", g_mi_cfg[0].ifname,error_content);
			return -1;
		}
		pcap_handle[1] = tph;
	}

	return 1;

}

/*
	desc:	
		sendpkt 
	param:
		data: packet app data
		len : datalen
		dir: 0:inside, 1:outside
		sip: source ip
		sport: source port
		dip: destination ip
		dport: destination port
		
*/
EXTERN_API
int mirror_pkt_send(void * vdata, int len, int dir,
	char* sip, unsigned short sport, char * dip, unsigned short dport){

	int tlen;
	in_addr_t saddr;
	in_addr_t daddr;
	in_port_t s_port;
	in_port_t d_port;
	char pdata[2048];
	struct ethhdr_bm  * mac;

	struct iphdr_bm   *ip;
	struct tcptype * ptcp;
	
	char * pos;
	char *data = (char*)vdata;
	saddr = inet_addr(sip);
	daddr = inet_addr(dip);
	s_port = htons(sport);
	d_port = htons(dport);

	tcp_conn_t * conn;
	
	if(dir == 0){   
		conn = conn_tcp_lookup(saddr,daddr,s_port,d_port);
		if(!conn){
			//create 
			conn = conn_tcp_create(daddr,saddr,s_port, d_port);
		}
	}
	else {
		conn = conn_tcp_lookup(daddr,saddr,d_port,s_port);
		if(!conn){
			//create 
			conn = conn_tcp_create(daddr,saddr,d_port, s_port);
		}


	}

	if (conn == NULL){
		printf("Error: create tcp connection failed\n");
		return -1;
	}

	for(tlen = 0; tlen<len; tlen++){
		int dlen = len-tlen;
		int addlen = 0;
	
		if(dlen> 1400) dlen = 1400;

		ptcp = (struct tcptype*) (data+100);
		pos = (char*)ptcp;
		ptcp->ack = htonl(conn->seq[((dir+1)&1)]);
		ptcp->seq = htonl(conn->seq[dir]);
		conn->seq[dir] += dlen;
		ptcp->sport = s_port;
		ptcp->dport = d_port;
		
		ptcp->len = (5<<4);  //only high 4bit 
		ptcp->flags = TH_ACK;
		ptcp->window = htons(65535);
		ptcp->checksum = 0;
		ptcp->urgentpointer = 0;
		memcpy(pos+20,data+tlen,  dlen);
		ptcp->checksum = tcp_dosums(ptcp, saddr, daddr, 20+dlen);
		
		addlen += 20;
		
		//re calc tcp checksum

		ip = (struct iphdr_bm *) (pos - 20);
		pos =(char*)ip;
		ip->version = 4;
		ip->ihl = 5;
		ip->tos  = 0;
		ip->daddr = daddr;
		ip->frag_off = 0;
		ip->id = g_ip_id[dir];
		 g_ip_id[dir]++;
		ip->protocol = 6;
		ip->saddr = saddr;
		ip->tot_len = htons(20 +20+ dlen);	 /*tcp head len + data len*/
		ip->ttl = 64;
		ip->check = 0;
		ip->check = ip_chksum((unsigned short *)pos, 20);

		addlen += 20;
		

				
		mac = (struct ethhdr_bm*)(pos - ETH_HLEN);
		pos -= ETH_HLEN;
		
		memcpy(mac->h_dest,g_mi_cfg[dir].dmac,6);
		memcpy(mac->h_source,g_mi_cfg[dir].smac,6);
		mac->h_proto = htons(ETH_P_IP);
		addlen += ETH_HLEN;
		tlen  += addlen + dlen;
		
		pcap_sendpacket(pcap_handle[dir], (unsigned char *)mac, addlen + dlen);
	}

	return len;
}


EXTERN_API
int mirror_connection_end(int dir,
	char* sip, unsigned short sport, char * dip, unsigned short dport){

	in_addr_t saddr;
	in_addr_t daddr;
	in_port_t s_port;
	in_port_t d_port;

	saddr = inet_addr(sip);
	daddr = inet_addr(dip);
	s_port = htons(sport);
	d_port = htons(dport);

	tcp_conn_t * conn;
	//clean old node
	conn_free_delay();
	
	if(dir == 0){
		conn = conn_tcp_lookup(saddr,daddr,s_port,d_port);
	}
	else {
		conn = conn_tcp_lookup(daddr,saddr,d_port,s_port);
	}
	if (conn == NULL){
		printf("Error: not find connection %s:%d->%s-%d\n",sip, sport, dip, dport);
		return 0;
	}
	
	conn->mirror_close_state[dir] = 1;
	
	if(conn->mirror_close_state[0] == 1 && conn->mirror_close_state[1] == 1){
		conn_free_force(conn);
	}
	return 1;

}

