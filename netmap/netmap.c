/*
 
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_bus_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>



#include "common.h"
#include "utils.h"
#include "dpdk_main.h"
#include "netmap_ip.h"
#include "timewheel.h"

#include "conn.h"
#include "local_ip.h"
#include "netmap_packet_io.h"
#include "netmap.h"
#include "https_parse.h"


int g_deploy_mode = 0;
extern TimeWheel * tcpwhile;
int conn_debug = 1;

static unsigned short
ip_checksum_adjust_inline (unsigned short checksum, unsigned short old_ushort,
  unsigned short new_ushort)
{
  unsigned int    tlong;

  tlong = checksum - (~old_ushort & 0xffff);
  tlong = ((tlong & 0xffff) + (tlong >> 16)) & 0xffff;
  tlong = tlong - new_ushort;
  return ((tlong & 0xffff) + (tlong >> 16));
}

static unsigned short
ip_checksum_adjust_long_inline (unsigned short checksum, unsigned int  old_addr,
  unsigned int new_addr)
{
  checksum = ip_checksum_adjust_inline (checksum, old_addr >> 16,
  new_addr >> 16);
  return (ip_checksum_adjust_inline (checksum, old_addr & 0xffff,
	  new_addr & 0xffff));
}

void* netmap_forward_process(void * arg){
	int bufCount;
	int index;

	int ret;
	struct rte_mbuf * pkt_burst[MAX_ENBURST];
	arg = arg;
	kni_iface_ready_get();
	//thread_set_cpu(__FUNCTION__, g_process_info[netmap_forward_thread].core_mask);

	while(1){
		bufCount = netmap_pkt_retrieve_intput(pkt_burst,MAX_ENBURST);
		if(bufCount == 0){
			conn_node_aging();
			continue;
		}
	
		for(index = 0; index<bufCount; index++){
			if(conn_debug) printf("%s %d, retrieve input packet:0x%x\n", __FUNCTION__,__LINE__, pkt_burst[index]);
			ret = netmap_parse_packet(pkt_burst[index]);
			if(ret == PACKET_DROP) {
				if(conn_debug)  printf("%s %d, 0x%x package droped\n", __FUNCTION__,__LINE__,pkt_burst[index]);
				if(g_deploy_mode == mode_inline){
					 netmap_pkt_output(pkt_burst[index]);
				}
				else {
					//mbuf_freed_check(pkt_burst[index], __LINE__) ;
					rte_pktmbuf_free(pkt_burst[index]);
				}
				
				continue;
			}
			else if(ret == PACKET_INJECT){
				//SEND PACKET TO KNI
				if(conn_debug)  printf("%s %d, send to kni packet:0x%x\n", __FUNCTION__,__LINE__, pkt_burst[index]);
				kni_put_pkt_to_send_list(pkt_burst[index]);
				continue;
			}
			else if(ret == PACKET_CACHE){
				if(conn_debug)  printf("%s %d, 0x%x package cached\n", __FUNCTION__,__LINE__,pkt_burst[index]);
				continue;
			}
			
			ret = netmap_packet_conn(pkt_burst[index], dir_inside);	
			if(ret == PACKET_DROP) {

				if(conn_debug)  printf("%s %d, 0x%x package droped\n", __FUNCTION__,__LINE__,pkt_burst[index]);
				if(g_deploy_mode == mode_inline){
					 netmap_pkt_output(pkt_burst[index]);
				}
				else {
					//mbuf_freed_check(pkt_burst[index], __LINE__) ;
					rte_pktmbuf_free(pkt_burst[index]);
				}
				continue;
			} else {
				kni_put_pkt_to_send_list(pkt_burst[index]);
				continue;
			}
		}

	
		conn_node_aging();
	}

	
	return NULL;
}


int netmap_packet_conn(struct rte_mbuf * mbuf, int dir){
	int ret;
	
	mbuf_app_ext * papp; 
	tcp_conn_t * tcp_conn;
	struct tcptype * ptcp;
	papp = MBUF_APP_EXT(mbuf);
	struct iphdr_bm * iph;
	int datalen ;
	int tcphlen;
	int created = 0;
	char sip[32], dip[32];
	in_addr_t faddr, laddr;
	in_port_t fport, lport;

	
	if(dir == dir_inside){
		if(ntohs(papp->dport) != 443) {
			return PACKET_INJECT;
		}
		
		faddr = papp->saddr;
		laddr = papp->daddr;
		fport = papp->sport;
		lport = papp->dport;
	} else {
		if(ntohs(papp->sport) != 443) {
			return PACKET_INJECT;
		}
		faddr = papp->daddr;
		laddr = papp->saddr;
		fport = papp->dport;
		lport = papp->sport;

	}
	iph =(struct iphdr_bm*) papp->raw_ip;
	if (iph == NULL) {
		return PACKET_INJECT;
	}

	GETIPSTRING(papp->saddr, sip);
	GETIPSTRING(papp->daddr, dip);
	if(dir == dir_inside){
		tcp_conn = conn_tcp_lookup(faddr, laddr,fport, lport);
	}
	else {
		tcp_conn = conn_tcp_flookup(faddr, laddr,fport, lport);
	}
	if(tcp_conn == NULL){
		if(dir == dir_outside) {
			if(conn_debug)  printf("%s %d, 0x%x find connection falied for outside packet %s:%d->%s:%d droped :0x%x\n", __FILE__,__LINE__,mbuf, sip, ntohs(papp->sport), dip,ntohs(papp->dport));
			return PACKET_INJECT;
		}
		tcp_conn = conn_tcp_create(faddr, laddr,fport, lport);
		if(!tcp_conn) {
			if(conn_debug)  printf("%s %d, 0x%x package create connection failed\n", __FUNCTION__,__LINE__,mbuf);
			return PACKET_INJECT;
		} else {
			created  =1;
			if(conn_debug)  printf("%s %d, 0x%x package %s:%d->%s:%d create connection success\n", __FILE__,__LINE__,mbuf, sip,  ntohs(papp->sport),dip, ntohs(papp->dport));
		}
	}
	else {
		DeleteTimerNode(tcpwhile,&tcp_conn->tn,0);
		if(conn_debug) printf("%s %d, 0x%x package %s:%d->%s:%d find connection :0x%x\n", __FILE__,__LINE__,mbuf, sip, ntohs(papp->sport), dip,ntohs(papp->dport),tcp_conn);
	}

	
	ptcp = (struct tcptype*)((char*)iph + (iph->ihl<< 2) );
	
	
	time(&tcp_conn->last_active); 
	//rewrite daddr to local
	if(ptcp->flags & TH_RST){
		InsertTimerNode(tcpwhile,&tcp_conn->tn, 5);
	} else {
		InsertTimerNode(tcpwhile,&tcp_conn->tn, 150);
	}


	if(tcp_conn->bypass  == 1){
		return PACKET_INJECT;
	}

	if(created == 1){
		ret = whiteItem_check_addr(laddr);
		if(ret == 1){
			tcp_conn->bypass = 1;
			return PACKET_INJECT;
		}
	}
	


	if(dir == dir_inside){
		
		/*需要将目的地址更改成本机地址，

		 源地址，每个连接分配一个虚拟地址池
	    */
		
		 ptcp->checksum = ip_checksum_adjust_long_inline(ptcp->checksum,
	    				    iph->daddr, g_local_ip_addr);

		ptcp->checksum = ip_checksum_adjust_long_inline(ptcp->checksum,
	    				    iph->saddr, tcp_conn->nat_faddr);
		
		iph->check = ip_checksum_adjust_long_inline(iph->check, 
		    				iph->daddr, g_local_ip_addr);
		
		iph->check = ip_checksum_adjust_long_inline(iph->check, 
		    				iph->saddr, tcp_conn->nat_faddr);

		tcp_conn->raw_saddr = iph->saddr;
		tcp_conn->raw_daddr = iph->daddr;
		tcp_conn->raw_dport = ptcp->dport;
		tcp_conn->raw_sport = ptcp->sport;
		
		
		iph->saddr = tcp_conn->nat_faddr;
		iph->daddr = g_local_ip_addr;
		
		tcp_conn->nat_laddr = g_local_ip_addr;
		assert(tcp_conn->nat_faddr);
		//tcp_conn->nat_laddr = 
		
		if(tcp_conn->in_fhash == 0){
			
			conn_fhash_insert(tcp_conn);
		}
		
		
		//kni_put_pkt_to_send_list(mbuf);   //to kni
		
	} else {
		ptcp->checksum = ip_checksum_adjust_long_inline(ptcp->checksum,
							   iph->saddr, tcp_conn->raw_daddr);

	   ptcp->checksum = ip_checksum_adjust_long_inline(ptcp->checksum,
	   							iph->daddr, tcp_conn->raw_saddr);
	   
	   iph->check = ip_checksum_adjust_long_inline(iph->check, 
						   iph->saddr, tcp_conn->raw_daddr);

	   iph->check = ip_checksum_adjust_long_inline(iph->check, 
						   iph->daddr, tcp_conn->raw_saddr);

	   
	   
	   iph->saddr = tcp_conn->raw_daddr;
	   iph->daddr = tcp_conn->raw_saddr;
	 
	   //netmap_pkt_output(mbuf);   //
	}
	
	tcphlen =  (((ptcp->len&0xf0)>>4) <<2);
	datalen = ntohs(iph->tot_len) - tcphlen - (iph->ihl<< 2);

	if(dir == dir_inside) {
		if(tcp_conn->ssl_state != ssl_parse_end && datalen > 0){
			unsigned char * data = (char*)ptcp+tcphlen;
			int tpay =  rte_pktmbuf_data_len(mbuf) -(data - papp->raw_eth);
			if(tpay <= 0) {
				goto skip_ssl;
			}
			if(conn_debug)  printf("%s %d, packet len: %d,iphlen:%d,tcphlen:%d,paylen:%d\n",__FILE__,__LINE__,
				rte_pktmbuf_data_len(mbuf), iph->ihl<<2, tcphlen,tpay);
			
			ret = https_host_parse(data,tpay, tcp_conn->host, sizeof(tcp_conn->host));
			if(ret == HTTPS_CLIENT_HELLO_PARSE_OK){
				//post host 
				if(conn_debug)  printf("%s %d, 0x%x package https parse ok, got host:%s\n", __FUNCTION__,__LINE__,mbuf,tcp_conn->host);
				tcp_conn->ssl_state = ssl_parse_end;
				ret = whiteItem_check(tcp_conn->host);
				if(ret == 1) {
					tcp_conn->bypass = 1;
					whiteItem_add_addr_inet(tcp_conn->raw_daddr);
					
				}else {
					ssl_ctx_post_host_cert(tcp_conn->host, tcp_conn->nat_laddr, tcp_conn->raw_dport, tcp_conn->nat_faddr, tcp_conn->raw_sport, tcp_conn->raw_saddr, tcp_conn->raw_daddr);
				}
			} else if(ret == HTTPS_CLIENT_HELLO_PART){
				if(conn_debug)  printf("%s %d, 0x%x package hello part data\n", __FUNCTION__,__LINE__,mbuf);
				//copy partdata
				
			} else if (ret == HTTPS_CLIENT_HELLO_INVALID){
				if(conn_debug)  printf("%s %d, 0x%x package hello invalid\n", __FUNCTION__,__LINE__,mbuf);
				//drop
			} else if(ret == HTTPS_CLIENT_HELLO_OVERRUN){
				if(conn_debug)  printf("%s %d, 0x%x package hello overrun\n", __FUNCTION__,__LINE__,mbuf);
				//over run
				return PACKET_INJECT;
			} else if(ret == HTTPS_CLIENT_HOST_TOO_LONG){
				if(conn_debug)  printf("%s %d, 0x%x package host too long\n", __FUNCTION__,__LINE__,mbuf);
					return PACKET_INJECT;

			} else if(ret == HTTPS_CLIENT_HELLO_NOHOST){
				if(conn_debug)  printf("%s %d, 0x%x package hello no host\n", __FUNCTION__,__LINE__,mbuf);
				return PACKET_INJECT;
			}
		}
	}
	//

	//rewrite saddr to id
	skip_ssl:
	

	return PACKET_CONN;
}


int netmap_start(){



	int ret;
	int index;
	pthread_t pid1,pid2;
	pthread_attr_t attr1,attr2;
	int coreid;



	pthread_attr_init(&attr1);
	pthread_attr_setscope(&attr1, PTHREAD_SCOPE_PROCESS);
	pthread_attr_setdetachstate(&attr1, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&pid1, &attr1, netmap_forward_process, NULL);
	if(ret < 0){
		return -1;
	}
	pthread_attr_destroy(&attr1);

}

