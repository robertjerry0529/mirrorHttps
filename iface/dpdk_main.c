/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
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
#include "dpdk_main.h"
#include "utils.h"
#include "plat_log.h"
#include "iface.h"
#include "local_ip.h"

#define DPDK_CONFIG_FILE   "config.txt"

 void
print_usage(const char *prgname);

/*
 * Structure of port parameters
 */
struct kni_port_params {

	uint16_t port_id;/* Port ID */
	uint16_t group_id;  //group id
	unsigned lcore_rx; /* lcore ID for RX */
	unsigned lcore_tx; /* lcore ID for TX */
	uint32_t nb_lcore_k; /* Number of lcores for KNI multi kernel threads */
	uint32_t nb_kni; /* Number of KNI devices to be created */
	unsigned lcore_k[KNI_MAX_KTHREAD]; /* lcore ID list for kthreads */
	struct rte_kni *kni[KNI_MAX_KTHREAD]; /* KNI context pointers */
	char kni_name[KNI_MAX_KTHREAD][RTE_KNI_NAMESIZE];
	
	char mac[6];
} __rte_cache_aligned;

static struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];


/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

/* Mempool for mbufs */
static struct rte_mempool * pktmbuf_pool = NULL;

/* Mask of enabled ports */
static uint32_t ports_mask = 0;
/* Ports set in promiscuous mode off by default. */
static int promiscuous_on = 1;
/* Monitor link status continually. off by default. */
static int monitor_links;
static int signle_deloyed;
static int kni_iface_ready = 0;
static int pkgbuf_count;
static int main_thread_ready = 0;
int io_thread_core_start = 0;
int io_thread_core_count = 0;
int app_thread_core_start = 0;
int app_thread_core_count = 0;

in_addr_t local_service_ip;  //本地服务IP地址
in_addr_t local_service_mask;  //本地服务IP地址


iface_role   g_iface_role[eth_role_max];
iface_cfg_t  g_iface_cfg[RTE_MAX_ETHPORTS];

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
	/* number of pkts received from NIC, and sent to KNI */
		uint64_t rx_eth_packets;
		uint64_t rx_kni_packets;
		
		/* number of pkts received from NIC, but failed to send to KNI */
		uint64_t rx_eth_dropped;
		uint64_t rx_kni_dropped;
	
		/* number of pkts received from KNI, and sent to NIC */
		uint64_t tx_eth_packets;
		uint64_t tx_kni_packets;
	
		/* number of pkts received from KNI, but failed to send to NIC */
		uint64_t tx_eth_dropped;
		uint64_t tx_kni_dropped;

};

/* kni device statistics array */
static struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];

static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu);
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up);
static int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]);

static rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t kni_pause = RTE_ATOMIC32_INIT(0);


__thread int db_threadId; /* data plane thread id from 0, 按照收发线程和业务线程分组，分别从0开始*/





/* Print out statistics on packets handled */
static void
print_stats(void)
{
	uint16_t i;

	printf("total packet pool size:%u\n", pkgbuf_count);
	
	printf("\n**KNI example application statistics**\n"
	       "======  ======  ==============  ============  ============  ============  ============\n"
	       " Iface  Port    Lcore(RX/TX)    rx_packets    rx_dropped    tx_packets    tx_dropped\n"
	       "------  ------  --------------  ------------  ------------  ------------  ------------\n");
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!kni_port_params_array[i])
			continue;

		
		printf("ETH: %7d %10u/%2u %13"PRIu64" %13"PRIu64" %13"PRIu64" "
							"%13"PRIu64"\n", i,
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->lcore_tx,
						kni_stats[i].rx_eth_packets,
						kni_stats[i].rx_eth_dropped,
						kni_stats[i].tx_eth_packets,
						kni_stats[i].tx_eth_dropped);

		printf("KNI: %7d %10u/%2u %13"PRIu64" %13"PRIu64" %13"PRIu64" "
							"%13"PRIu64"\n", i,
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->lcore_tx,
						kni_stats[i].rx_kni_packets,
						kni_stats[i].rx_kni_dropped,
						kni_stats[i].tx_kni_packets,
						kni_stats[i].tx_kni_dropped);
	}
	printf("======  ==============  ============  ============  ============  ============\n");
}

void dpdk_iface_stats(){
	print_stats();

}



/* Print the link stats and info */
static void
print_link_info(int port, char *out, size_t out_size)
{
	struct rte_eth_stats stats;
	struct rte_ether_addr mac_addr;
	struct rte_eth_link eth_link;
	uint16_t mtu;
	int ret;

	memset(&stats, 0, sizeof(stats));
	rte_eth_stats_get(port, &stats);

	ret = rte_eth_macaddr_get(port, &mac_addr);
	if (ret != 0) {
		snprintf(out, out_size, "\n%u: MAC address get failed: %s",
			 port, rte_strerror(-ret));
		return;
	}

	ret = rte_eth_link_get(port, &eth_link);
	if (ret < 0) {
		snprintf(out, out_size, "\n%u: link get failed: %s",
			 port, rte_strerror(-ret));
		return;
	}

	rte_eth_dev_get_mtu(port, &mtu);

	snprintf(out, out_size,
		"\n"
		"%u: flags=<%s> mtu %u\n"
		"\tether %02X:%02X:%02X:%02X:%02X:%02X\n"
		"\tspeed %u Mbps\n"
		"\tRX packets %" PRIu64"  bytes %" PRIu64"\n"
		"\tRX errors %" PRIu64"  missed %" PRIu64"  no-mbuf %" PRIu64"\n"
		"\tTX packets %" PRIu64"  bytes %" PRIu64"\n"
		"\tTX errors %" PRIu64"\n",
		port,
		eth_link.link_status == 0 ? "DOWN" : "UP",
		mtu,
		mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
		mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
		mac_addr.addr_bytes[4], mac_addr.addr_bytes[5],
		eth_link.link_speed,
		stats.ipackets,
		stats.ibytes,
		stats.ierrors,
		stats.imissed,
		stats.rx_nombuf,
		stats.opackets,
		stats.obytes,
		stats.oerrors);
}

void dpdk_port_stats(int port, char *outbuf, int len){
	int i;
	struct rte_eth_stats lst;

	
	struct rte_eth_link eth_link;
	uint16_t mtu;
	int ret;
	
	outbuf[0] = 0;
	
	memset(&lst, 0, sizeof(lst));
	for (i = 0; i < RTE_MAX_ETHPORTS; i++){
			if (kni_port_params_array[i] && kni_port_params_array[i]->port_id == port) {
				rte_eth_stats_get(port,&lst);
				break;
			}	
	}

	if(i == RTE_MAX_ETHPORTS){
		return ;
	}
	
	print_link_info(port,outbuf, len);

	

}

/* Custom handling of signals to handle stats and kni processing */
static void
signal_handler(int signum)
{
	/* When we receive a USR1 signal, print stats */
	if (signum == SIGUSR1) {
		print_stats();
	}

	/* When we receive a USR2 signal, reset stats */
	if (signum == SIGUSR2) {
		memset(&kni_stats, 0, sizeof(kni_stats));
		printf("\n** Statistics have been reset **\n");
		return;
	}

	/* When we receive a RTMIN or SIGINT signal, stop kni processing */
	if (signum == SIGRTMIN || signum == SIGINT){
		printf("\nSIGRTMIN/SIGINT received. KNI processing stopping.\n");
		rte_atomic32_inc(&kni_stop);
		return;
        }
}

static void
kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
static int
kni_ingress(struct kni_port_params *p)
{
	uint8_t i;
	uint16_t port_id;
	unsigned nb_rx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_mbuf *pkts_output[PKT_BURST_SZ];
	uint16_t groupid = 0;
	unsigned nb_tx;
	int ntotal = 0;
	//struct kni_port_params *tgrp;
	if (p == NULL)
		return 0;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from eth */
		nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, APP, "Error receiving from eth\n");
			return 0;
		}
		if(nb_rx > 0){

			kni_stats[port_id].rx_eth_packets += nb_rx ;
			num = netmap_pkt_input(pkts_burst, nb_rx, port_id);
			//num = 0;
			if (unlikely(num < nb_rx)) {
				/* Free mbufs not tx to kni interface */
				kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
				kni_stats[port_id].rx_eth_dropped += nb_rx - num;
			}
		}
		ntotal += nb_rx;
		
		rte_kni_handle_request(p->kni[i]);
		//获取需要发送到kni的报文
		nb_tx = kni_get_pkt_from_send_list(pkts_output,PKT_BURST_SZ);
		if(nb_tx > 0){
			/* Burst tx to kni */
			num = rte_kni_tx_burst(p->kni[i], pkts_output, nb_tx);
			if (num)
				kni_stats[port_id].tx_kni_packets += num;
			
			if (unlikely(num < nb_tx)) {
				/* Free mbufs not tx to NIC */
				kni_burst_free_mbufs(&pkts_output[num], nb_tx - num);
				kni_stats[port_id].tx_kni_dropped += nb_tx-num;
			}
		}

		ntotal += nb_tx;
		
		
	}

	return ntotal;
}

/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
static int
kni_egress(struct kni_port_params *p)
{
	uint8_t i;
	uint16_t port_id;
	unsigned nb_tx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_mbuf *pkts_output[PKT_BURST_SZ];
	int groupid;
	unsigned nb_ni;
	int ntotal = 0;
	if (p == NULL)
		return 0;

	groupid = p->group_id;
	
	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from kni */
		num = rte_kni_rx_burst(p->kni[i], pkts_burst, PKT_BURST_SZ);
		if (unlikely(num > PKT_BURST_SZ)) {
			RTE_LOG(ERR, APP, "Error receiving from KNI\n");
			return 0;
		}
		ntotal += num;	
		if(num > 0){
			kni_stats[port_id].rx_kni_packets += num;
			
			nb_ni = kni_pkt_put_to_recv_list(pkts_burst, num, port_id);
			
			if (unlikely(nb_ni < num)) {
				/* Free mbufs not tx to kni interface */
				kni_burst_free_mbufs(&pkts_burst[nb_ni], num - nb_ni);
				kni_stats[port_id].rx_kni_dropped += num - nb_ni;
			}
		}

		
		//获取需要发送到eth的报文
		nb_tx =netmap_pkt_retrieve_output(pkts_output,PKT_BURST_SZ);
		if(nb_tx > 0){
			num = rte_eth_tx_burst(g_iface_cfg[eth_inject_inside].id, 0, pkts_output, (uint16_t)nb_tx);
			if (num)
				kni_stats[port_id].tx_eth_packets += num;
			
			if (unlikely(num < nb_tx)) {
				/* Free mbufs not tx to NIC */
				kni_burst_free_mbufs(&pkts_output[num], nb_tx - num);
				kni_stats[port_id].tx_eth_dropped +=  nb_tx - num;
			}
		}
		ntotal += nb_tx;
		
		
	}

	return ntotal;
}



void kni_prepare_kernel_alloc_buf(struct kni_port_params *p){
	int index = 0;
	int i;
	int nb;
	nb = p->nb_kni;
	for(index = 0; index<16; index++){
		for(i = 0; i< nb; i++){
			rte_kni_rx_burst(p->kni[i], NULL, 0);
		}
	}
}
static int
main_loop(__rte_unused void *arg)
{
	uint16_t i;
	int index;
	int32_t f_stop;
	int32_t f_pause;
	int tflag = 0;
	int npkt = 0;
	int tpkt = 0;
	int rpkt = 0;
	const unsigned lcore_id = rte_lcore_id();
	enum lcore_rxtx {
		LCORE_NONE = 0x00,
		LCORE_RX =0x01,
		LCORE_TX = 0x02,
		
		LCORE_MAX = 0x03
	};
	enum lcore_rxtx flag = LCORE_MAX;
	
	
	if(lcore_id != 0) return ;
	
	printf("%s %d, main loop lcore_id:%d\n", __FILE__,__LINE__,lcore_id);	

	main_thread_ready = 1;
	
	kni_prepare_kernel_alloc_buf(kni_port_params_array[g_iface_cfg[eth_mirror].id]);
	
	
	while(1){
		npkt = 0;
		if (flag & LCORE_RX) {
			
			while (1) {
				rpkt = 0;
	
				rpkt = kni_ingress(kni_port_params_array[g_iface_cfg[eth_mirror].id]);
				if(flag != LCORE_RX){
					npkt += rpkt;
					break;
				}
				if(rpkt == 0) {
					usleep(20);
				}
			}
		} 
		if (flag & LCORE_TX) {
			
			while (1) {
				tpkt = 0;
				
				tpkt += kni_egress(kni_port_params_array[g_iface_cfg[eth_mirror].id]);
				
				
				if(flag != LCORE_TX){
					npkt += tpkt;
					break;
				}
				if(npkt == 0) {
					usleep(20);
				}
			}
		} else {
			RTE_LOG(INFO, APP, "Lcore %u has nothing to do\n", lcore_id);
			break;
		}
		if(npkt == 0) {
			usleep(20);
		}
	}
	return 0;
}

/* Display usage instructions */
 void
print_usage(const char *prgname)
{
	RTE_LOG(INFO, APP, "\nUsage: %s [EAL options] -- -p PORTMASK -P -m "
		   "[--config (port,lcore_rx,lcore_tx,lcore_kthread...)"
		   "[,(port,lcore_rx,lcore_tx,lcore_kthread...)]]\n"
		   "    -p PORTMASK: hex bitmask of ports to use\n"
		   "    -P : enable promiscuous mode\n"
		   "    -m : enable monitoring of port carrier state\n"
		   "    --config (port,lcore_rx,lcore_tx,lcore_kthread...): "
		   "port and lcore configurations\n",
	           prgname);
}

/* Convert string to unsigned number. 0 is returned if error occurs */
static uint32_t
parse_unsigned(const char *portmask)
{
	char *end = NULL;
	unsigned long num;

	num = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return (uint32_t)num;
}

static void
print_config(void)
{
	uint32_t i, j;
	struct kni_port_params **p = kni_port_params_array;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!p[i])
			continue;
		RTE_LOG(DEBUG, APP, "Port ID: %d\n", p[i]->port_id);
		RTE_LOG(DEBUG, APP, "Rx lcore ID: %u, Tx lcore ID: %u\n",
					p[i]->lcore_rx, p[i]->lcore_tx);
		for (j = 0; j < p[i]->nb_lcore_k; j++)
			RTE_LOG(DEBUG, APP, "Kernel thread lcore ID: %u\n",
							p[i]->lcore_k[j]);
	}
}

static int
parse_config(const char *arg)
{
	const char *p, *p0 = arg;
	char s[256], *end;
	unsigned size;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_LCORE_RX,
		FLD_LCORE_TX,
		_NUM_FLD = KNI_MAX_KTHREAD + 3,
	};
	int i, j, nb_token;
	char *str_fld[_NUM_FLD];
	unsigned long int_fld[_NUM_FLD];
	uint16_t port_id, nb_kni_port_params = 0;

	memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));
	while (((p = strchr(p0, '(')) != NULL) &&
		nb_kni_port_params < RTE_MAX_ETHPORTS) {
		p++;
		if ((p0 = strchr(p, ')')) == NULL)
			goto fail;
		size = p0 - p;
		if (size >= sizeof(s)) {
			printf("Invalid config parameters\n");
			goto fail;
		}
		snprintf(s, sizeof(s), "%.*s", size, p);
		nb_token = rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',');
		if (nb_token <= FLD_LCORE_TX) {
			printf("Invalid config parameters\n");
			goto fail;
		}
		for (i = 0; i < nb_token; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i]) {
				printf("Invalid config parameters\n");
				goto fail;
			}
		}

		i = 0;
		port_id = int_fld[i++];
		if (port_id >= RTE_MAX_ETHPORTS) {
			printf("Port ID %d could not exceed the maximum %d\n",
						port_id, RTE_MAX_ETHPORTS);
			goto fail;
		}
		if (kni_port_params_array[port_id]) {
			printf("Port %d has been configured\n", port_id);
			goto fail;
		}
		kni_port_params_array[port_id] =
			rte_zmalloc("KNI_port_params",
				    sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);
		kni_port_params_array[port_id]->port_id = port_id;
		kni_port_params_array[port_id]->lcore_rx =
					(uint8_t)int_fld[i++];
		kni_port_params_array[port_id]->lcore_tx =
					(uint8_t)int_fld[i++];
		if (kni_port_params_array[port_id]->lcore_rx >= RTE_MAX_LCORE ||
		kni_port_params_array[port_id]->lcore_tx >= RTE_MAX_LCORE) {
			printf("lcore_rx %u or lcore_tx %u ID could not "
						"exceed the maximum %u\n",
				kni_port_params_array[port_id]->lcore_rx,
				kni_port_params_array[port_id]->lcore_tx,
						(unsigned)RTE_MAX_LCORE);
			goto fail;
		}
		for (j = 0; i < nb_token && j < KNI_MAX_KTHREAD; i++, j++)
			kni_port_params_array[port_id]->lcore_k[j] =
						(uint8_t)int_fld[i];
		kni_port_params_array[port_id]->nb_lcore_k = j;
	}
	print_config();

	return 0;

fail:
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			rte_free(kni_port_params_array[i]);
			kni_port_params_array[i] = NULL;
		}
	}

	return -1;
}

static int
validate_parameters(uint32_t portmask)
{
	uint32_t i;

	if (!portmask) {
		printf("No port configured in port mask\n");
		return -1;
	}

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (((portmask & (1 << i)) && !kni_port_params_array[i]) ||
			(!(portmask & (1 << i)) && kni_port_params_array[i]))
			rte_exit(EXIT_FAILURE, "portmask is not consistent "
				"to port ids specified in --config\n");

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_rx)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d receiving not enabled\n",
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->port_id);

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_tx)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d transmitting not enabled\n",
					kni_port_params_array[i]->lcore_tx,
					kni_port_params_array[i]->port_id);

	}

	return 0;
}

#define CMDLINE_OPT_CONFIG  "config"

/* Parse the arguments given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, longindex, ret = 0;
	const char *prgname = argv[0];
	static struct option longopts[] = {
		{CMDLINE_OPT_CONFIG, required_argument, NULL, 0},
		{NULL, 0, NULL, 0}
	};

	/* Disable printing messages within getopt() */
	opterr = 0;

	/* Parse command line */
	while ((opt = getopt_long(argc, argv, "p:Pms", longopts,
						&longindex)) != EOF) {
		switch (opt) {
		case 'p':
			ports_mask = parse_unsigned(optarg);
			break;
		case 'P':
			promiscuous_on = 1;
			break;
		case 'm':
			monitor_links = 1;
			break;
		
		case 0:
			if (!strncmp(longopts[longindex].name,
				     CMDLINE_OPT_CONFIG,
				     sizeof(CMDLINE_OPT_CONFIG))) {
				ret = parse_config(optarg);
				if (ret) {
					printf("Invalid config\n");
					print_usage(prgname);
					return -1;
				}
			}
			break;
		default:
			print_usage(prgname);
			rte_exit(EXIT_FAILURE, "Invalid option specified\n");
		}
	}

	/* Check that options were parsed ok */
	if (validate_parameters(ports_mask) < 0) {
		print_usage(prgname);
		rte_exit(EXIT_FAILURE, "Invalid parameters\n");
	}

	return ret;
}

/* Initialize KNI subsystem */
static void
init_kni(void)
{
	unsigned int num_of_kni_ports = 0, i;
	struct kni_port_params **params = kni_port_params_array;

	/* Calculate the maximum number of KNI interfaces that will be used */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			num_of_kni_ports += (params[i]->nb_lcore_k ?
				params[i]->nb_lcore_k : 1);
		}
	}

	/* Invoke rte KNI init to preallocate the ports */
	rte_kni_init(num_of_kni_ports);
}

/* Initialise a single port on an Ethernet device */
static void
init_port(uint16_t port)
{
	int ret;
	uint16_t nb_rxd = NB_RXD;
	uint16_t nb_txd = NB_TXD;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_conf local_port_conf = port_conf;

	/* Initialise device and RX/TX queues */
	RTE_LOG(INFO, APP, "Initialising port %u ...\n", (unsigned)port);
	fflush(stdout);

	ret = rte_eth_dev_info_get(port, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			port, strerror(-ret));

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	ret = rte_eth_dev_configure(port, 1, 1, &local_port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not configure port%u (%d)\n",
		            (unsigned)port, ret);

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned)port, ret);

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(port, 0, nb_rxd,
		rte_eth_dev_socket_id(port), &rxq_conf, pktmbuf_pool);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up RX queue for "
				"port%u (%d)\n", (unsigned)port, ret);

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(port, 0, nb_txd,
		rte_eth_dev_socket_id(port), &txq_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up TX queue for "
				"port%u (%d)\n", (unsigned)port, ret);

	ret = rte_eth_dev_start(port);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not start port%u (%d)\n",
						(unsigned)port, ret);

	if (promiscuous_on) {
		ret = rte_eth_promiscuous_enable(port);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Could not enable promiscuous mode for port%u: %s\n",
				port, rte_strerror(-ret));
	}
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;

	printf("\nChecking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up - speed %uMbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			//rte_delay_ms(CHECK_INTERVAL);
			//usleep(10000);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
		usleep(10000);
	}
}

static void
log_link_state(struct rte_kni *kni, int prev, struct rte_eth_link *link)
{
	if (kni == NULL || link == NULL)
		return;

	if (prev == ETH_LINK_DOWN && link->link_status == ETH_LINK_UP) {
		RTE_LOG(INFO, APP, "%s NIC Link is Up %d Mbps %s %s.\n",
			rte_kni_get_name(kni),
			link->link_speed,
			link->link_autoneg ?  "(AutoNeg)" : "(Fixed)",
			link->link_duplex ?  "Full Duplex" : "Half Duplex");
		tunnel_ip_set();
	} else if (prev == ETH_LINK_UP && link->link_status == ETH_LINK_DOWN) {
		RTE_LOG(INFO, APP, "%s NIC Link is Down.\n",
			rte_kni_get_name(kni));
	}
}

void kni_iface_ready_set(){
	kni_iface_ready = 1;
}

int kni_iface_ready_get(){
	return kni_iface_ready;
}

void kni_iface_config_update(){

	iface_kni_add_ip(1,local_service_ip, local_service_mask);

	kni_iface_ready_set();
}

int tunnel_set_kni_mtu(char * ifname){

	char strcmd[256];
	int mtu;
	int ret;
	
		/*1500 - IP头 - udp 头 - nonce 长度 - msg 头 - 保护16字节*/
	//mtu = 1500 - 20 -   8        - 28          -16     -16;
	mtu = 1400;
	snprintf(strcmd,sizeof(strcmd), "ifconfig %s mtu %u", ifname, mtu);
	ret = system(strcmd);
	return ret;
}

void tunnel_set_kni_up(char * ifname){
	char strcmd[256];
	snprintf(strcmd, sizeof(strcmd), "ifconfig %s up", ifname);
	//printf("%s %d,system cmd:%s\n", __FUNCTION__,__LINE__,strcmd);
	system(strcmd);
	return ;
}

int tunnel_set_kni_ip(char * ifname, in_addr_t ip, in_addr_t mask){
	char strcmd[256];
	char ipstr[32], ipstr2[32];
	int ret;
	if(mask != 0){
		snprintf(strcmd, sizeof(strcmd), "ifconfig %s %s netmask %s", ifname,GETIPSTRING(ip,ipstr),
			GETIPSTRING(mask,ipstr2));
	}
	else {
		snprintf(strcmd, sizeof(strcmd), "ifconfig %s %s", ifname,GETIPSTRING(ip,ipstr));
	}
	ret = system(strcmd);
	return ret;
}

/*
 * Monitor the link status of all ports and update the
 * corresponding KNI interface(s)
 */
static void *
monitor_all_ports_link_status(void *arg)
{
	uint16_t portid;
	struct rte_eth_link link;
	unsigned int i, index;
	struct kni_port_params **p = kni_port_params_array;
	int prev= ETH_LINK_DOWN;
	(void) arg;
	int ret;
	int count = 0;


	while(main_thread_ready == 0){
		usleep(1000000);
		if(count++ > 30) break;
	}

	//设置MTU 
	for (i = 0; i < RTE_MAX_ETHPORTS; i++){
		if (kni_port_params_array[i]) {
			for(index = 0; index < kni_port_params_array[i]->nb_kni; index++){
				tunnel_set_kni_mtu(kni_port_params_array[i]->kni_name[index]);
			}
		}
	}

	
	kni_iface_ready_set();
	iface_kni_up();
	
	kni_iface_config_update();
	
	kni_netmap_pool_route();
	
	usleep(5*1000*1000);

	
	while (monitor_links) {
		

		usleep(500*1000);  //500ms
		count ++;
		if(count >= 120){
			
			count = 0;
		}
		RTE_ETH_FOREACH_DEV(portid) {
			if ((ports_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				RTE_LOG(ERR, APP,
					"Get link failed (port %u): %s\n",
					portid, rte_strerror(-ret));
				continue;
			}
			for (i = 0; i < p[portid]->nb_kni; i++) {
				prev = rte_kni_update_link(p[portid]->kni[i],
						link.link_status);
				log_link_state(p[portid]->kni[i], prev, &link);

				if (prev == ETH_LINK_DOWN && link.link_status == ETH_LINK_UP) {
					//iface_kni_set_ip(local_service_ip, local_service_mask);
					iface_kni_add_ip(1,local_service_ip, local_service_mask);
					kni_netmap_pool_route();
					usleep(3*1000*1000);
					
					kni_iface_ready_set();
				}
			}
		}
	}
	return NULL;
}

/* Callback for request of changing MTU */
static int
kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
	int ret;
	uint16_t nb_rxd = NB_RXD;
	struct rte_eth_conf conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);

	memcpy(&conf, &port_conf, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > RTE_ETHER_MAX_LEN)
		conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	else
		conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;

	/* mtu + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
							KNI_ENET_FCS_SIZE;
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned int)port_id,
				ret);

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0) {
		RTE_LOG(ERR, APP,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

		return ret;
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
		rte_eth_dev_socket_id(port_id), &rxq_conf, pktmbuf_pool);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to setup Rx queue of port %d\n",
				port_id);
		return ret;
	}

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to restart port %d\n", port_id);
		return ret;
	}

	return 0;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	rte_atomic32_inc(&kni_pause);

	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);

	rte_atomic32_dec(&kni_pause);

	if (ret < 0)
		RTE_LOG(ERR, APP, "Failed to start port %d\n", port_id);

	return ret;
}

static void
print_ethaddr(const char *name, struct rte_ether_addr *mac_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
	RTE_LOG(INFO, APP, "\t%s%s\n", name, buf);
}

/* Callback for request of configuring mac address */
static int
kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[])
{
	int ret = 0;
	struct kni_port_params **params = kni_port_params_array;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Configure mac address of %d\n", port_id);
	print_ethaddr("Address:", (struct rte_ether_addr *)mac_addr);

	ret = rte_eth_dev_default_mac_addr_set(port_id,
					(struct rte_ether_addr *)mac_addr);
	if (ret < 0)
		RTE_LOG(ERR, APP, "Failed to config mac_addr for port %d\n",
			port_id);

	if(params[port_id]){
		memcpy(params[port_id]->mac,mac_addr,6);	
	}
	
	return ret;
}

static int
kni_alloc(uint16_t port_id)
{
	uint8_t i;
	struct rte_kni *kni;
	struct rte_kni_conf conf;
	struct kni_port_params **params = kni_port_params_array;
	int ret;

	if (port_id >= RTE_MAX_ETHPORTS || !params[port_id])
		return -1;

	
	params[port_id]->nb_kni = params[port_id]->nb_lcore_k ?
						params[port_id]->nb_lcore_k : 1;

	


	for (i = 0; i < params[port_id]->nb_kni; i++) {
		/* Clear conf at first */
		memset(&conf, 0, sizeof(conf));
		
		snprintf(conf.name, RTE_KNI_NAMESIZE,
						"vEth%u", port_id);
		conf.core_id = params[port_id]->lcore_k[i];
		conf.force_bind = 1;

		
		strcpy(params[port_id]->kni_name[i],conf.name);
		conf.group_id = port_id;
		conf.mbuf_size = MAX_PACKET_SZ;
		/*
		 * The first KNI device associated to a port
		 * is the master, for multiple kernel thread
		 * environment.
		 */
		if (i == 0) {
			struct rte_kni_ops ops;
			struct rte_eth_dev_info dev_info;

			ret = rte_eth_dev_info_get(port_id, &dev_info);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Error during getting device (port %u) info: %s\n",
					port_id, strerror(-ret));

			/* Get the interface default mac address */
			ret = rte_eth_macaddr_get(port_id,
				(struct rte_ether_addr *)&conf.mac_addr);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Failed to get MAC address (port %u): %s\n",
					port_id, rte_strerror(-ret));
			memcpy(params[port_id]->mac,&conf.mac_addr,6);
			
			rte_eth_dev_get_mtu(port_id, &conf.mtu);

			conf.min_mtu = dev_info.min_mtu;
			conf.max_mtu = dev_info.max_mtu;

			memset(&ops, 0, sizeof(ops));
			ops.port_id = port_id;
			ops.change_mtu = kni_change_mtu;
			ops.config_network_if = kni_config_network_interface;
			ops.config_mac_address = kni_config_mac_address;

			kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);
		} else{
			kni = rte_kni_alloc(pktmbuf_pool, &conf, NULL);
		}

		if (!kni)
			rte_exit(EXIT_FAILURE, "Fail to create kni for "
						"port: %d\n", port_id);
		params[port_id]->kni[i] = kni;
	}

	return 0;
}

static int
kni_free_kni(uint16_t port_id)
{
	uint8_t i;
	struct kni_port_params **p = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !p[port_id])
		return -1;

	for (i = 0; i < p[port_id]->nb_kni; i++) {
		if (rte_kni_release(p[port_id]->kni[i]))
			printf("Fail to release kni\n");
		p[port_id]->kni[i] = NULL;
	}
	rte_eth_dev_stop(port_id);

	return 0;
}



static 
int getline_loc(FILE * fp, char *buf, int line)
{
	size_t i;
	char ch;
	size_t len;

	buf[line-1] = 0;
	i = 0;
	while((len = fread(&ch, 1,1,fp)) > 0) {
		buf[i++] = ch;
		if(ch == 0x0a) break;
		if((int)i ==( line-1)) break;
	}
	buf[i] = 0;
	return (int)i;
}
static char * trim(char * buf, int *length)
{
	int i;
	int len;
	i = 0;
	if(*length == 0) return NULL;
	
	len = *length - 1;

	if(len <= 0) return NULL;
	
	
	while(buf[i] == 0x20 || buf[i] == 0x0d || buf[i] == 0x0a || buf[i]=='\t' )
	{	
		buf[i++] = 0;
		if(i == len) return NULL;
	}

	while(buf[len] == 0x20 || buf[len] == 0x0d || buf[len] == 0x0a )
	{	
		buf[len--] = 0;
		if(len == 0) break;
	}
	len -= i;
	*length = len +  1 ;
	
	return buf+i;
	
}

/*eth0:input, engress, eth_coreid, kni_core_id*/
static int
parse_config_2( char *arg)
{
	
	char * str_fld[10];
	int nb_token;
	int port;
	nb_token = split(arg, str_fld, 10);
		
	if(strcmp(str_fld[0], "deploy" )  == 0){
		if(nb_token == 3){
			if(strcmp(str_fld[1], "mode") == 0){
				if(strcmp(str_fld[2], "inline") == 0){
					g_deploy_mode = mode_inline;
					return 1;
				}else if(strcmp(str_fld[2], "bypass") == 0){
					g_deploy_mode = mode_bypass;
					return 1;
				}
				
			}
		}
		return -1;
	}
	else if(strcmp(str_fld[0], "ip" )  == 0){
		if(nb_token != 4 ) {
			printf("config parse failed for %s\n", str_fld[0]);
			return -1;
		}
		local_service_ip = inet_addr(str_fld[2]);
		local_service_mask = inet_addr(str_fld[3]);
	}
	else if(strcmp(str_fld[0], "interface") == 0){
		/*interface mirror inside [mac]
		 interface reinject inside [mac]
		*/
		if(nb_token != 4 ) {
			printf("config parse failed for %s\n", str_fld[0]);
			return -1;
		}
		if(strcmp(str_fld[1], "mirror") == 0 && strcmp(str_fld[2], "inside") == 0 ){
			char * mac = g_iface_role[eth_mirror].mac;
			sscanf(str_fld[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]); 
		    g_iface_role[eth_mirror].valid = 1;

		} else if(strcmp(str_fld[1], "reinject") == 0 && strcmp(str_fld[2], "inside") == 0 ){
			char * mac = g_iface_role[eth_inject_inside].mac;
			sscanf(str_fld[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]); 
			 g_iface_role[eth_inject_inside].valid = 1;
		} else {
			printf("config parse failed for %s\n", str_fld[0]);
			return -1;
		}

	}
	else if(nb_token== 3 && strcmp(str_fld[0], "service") == 0){
		//service ip <ip>
		g_local_ip_addr = inet_addr(str_fld[2]);
	} else if(nb_token ==3 && strcmp(str_fld[0], "netmap") == 0 && strcmp(str_fld[1], "pool") == 0) {
		//netmap pool <mask>
		g_ippool_mask = inet_addr(str_fld[2]);
	}  else if(nb_token==4 && strcmp(str_fld[0], "netmap") == 0 && strcmp(str_fld[1], "reinject") == 0
		&&  strcmp(str_fld[2], "gateway") == 0) {
		//netmap reinject gateway 192.168.75.1
		reject_gateway = inet_addr(str_fld[3]);
	} 
	return 0;
}


int parse_confg_file(const char *file){
	FILE *fp;
	char buf[1024];
	int count,len,temp;
	int bend ;
	int ret;
	char * line;

	int port;
	
	if(!file) return 0;

    fp = fopen(file, "rb");

	if(!fp){
		printf("open file:%s failed\n", file);
		return -1;
	}

	bend = 0;
	
	
	len = 0;
	while(1){
		bend ++;
		temp = getline_loc(fp,buf+len, 1024 - len);
		if(temp>0 && buf[len]=='#') continue; /*skip comment*/ 
		if(temp == 0) {bend = 1; break;}
		count = temp-1;
		line = trim(buf+len, &count);
		if(line == NULL) continue;
		len += count;
		
		ret = parse_config_2( line);	
		if(ret < 0){
			printf("config error in line : %d, text:%s\n",bend, line);
			len = -1;
			break;
		}else {
			len  = 1;
		}
	}

		
	fclose(fp);
	return len;
	
}


/*启动dpdpk 主程序
./build/kni -c 3 -- p 1 -m --config="(0,0,1,1)"

*/
void* dpdk_start2(void *arg ){
	char * argv[32];
	int argc = 0;
	char config[1024];
	int ret;
	int core;
	int rcore ; 

	
	rcore = sysconf(_SC_NPROCESSORS_CONF);  //获取核数
	
	printf("system has %d processor(s). \n", rcore);

	core = rcore;
	if(core > 16){
		core = 16;
	}
	/*--config (port,lcore_rx,lcore_tx,lcore_kthread...): port and lcore configurations\n",
	*/
	
	switch(core){
		case 1:
			strcpy(config, "-c 1 -- -p 1 -m --config=\"(0,0,0,0)\"");
			app_thread_core_start =0;
			app_thread_core_count = 1;
			io_thread_core_start = 0;
			io_thread_core_count = 1;
			break;
		case 2:
			strcpy(config, "-c 1 -- -p 1 -m --config=\"(0,0,0,0)\"");
			app_thread_core_start = 1;
			app_thread_core_count = 1;
			io_thread_core_start = 0;
			io_thread_core_count = 1;
			
			break;
		case 3:
			strcpy(config, "-c 1 -- -p 1 -m --config=\"(0,0,0,0)\"");
			app_thread_core_start = 2;
			app_thread_core_count = 2;
			io_thread_core_start = 0;
			io_thread_core_count = 1;
			break;
		case 4:
			strcpy(config, "-c 1 -- -p 1 -m --config=\"(0,0,0,1)\"");
			app_thread_core_start = 2;
			app_thread_core_count = 2;  //
			io_thread_core_start = 0;
			io_thread_core_count = 1;
			break;
		case 5:
			strcpy(config, "-c 1 -- -p 1 -m --config=\"(0,0,0,1)\"");
			app_thread_core_start = 2;
			app_thread_core_count = 3;  //
			io_thread_core_start = 0;
			io_thread_core_count = 1;
			break;
		case 6:
			strcpy(config, "-c 3 -- -p 1 -m --config=\"(0,0,0,1)\"");
			app_thread_core_start = 3;
			app_thread_core_count = 3; 
			io_thread_core_start = 0;
			io_thread_core_count = 2;
			break;
		case 7:
			strcpy(config, "-c 7 -- -p 1 -m --config=\"(0,0,0,1)\"");
			app_thread_core_start = 4;
			app_thread_core_count = 3; 
			io_thread_core_start = 0;
			io_thread_core_count = 3;
			break;
		default:
			strcpy(config, "-c 7 -- -p 1 -m --config=\"(0,0,0,1)\"");
			app_thread_core_start = 4;
			app_thread_core_count = core - 4; 
			io_thread_core_start = 0;
			io_thread_core_count = 3;
			break;
			
	}

	printf("Core:%d, config=%s\n", core,config);
	argc = split((char *)config,argv, 32);
	dpdk_main(argc, argv);
	return NULL;
}

char * iface_kni_get_ifname(int port){
	if(kni_port_params_array[port]){
		return kni_port_params_array[port]->kni_name[0];
	}
	return NULL;

}

char *  iface_kni_get_mac(int port){
	if(kni_port_params_array[port]){
		return kni_port_params_array[port]->mac;
	}
	return NULL;
}
int iface_kni_set_ip(in_addr_t ip, in_addr_t mask){
	//当前仅支持一个kni接口，仅对该接口设置IP
	int index = 0;
	if (kni_port_params_array[0]) {
		for(index = 0; index <(int) kni_port_params_array[0]->nb_kni; index++){
			
			tunnel_set_kni_ip(kni_port_params_array[0]->kni_name[index], ip, mask);
		}
	}
}

int iface_kni_up(){
	int index;

	if (kni_port_params_array[0]) {
		for(index = 0; index < kni_port_params_array[0]->nb_kni; index++){
		
			tunnel_set_kni_up(kni_port_params_array[0]->kni_name[index]);
		}
	}

}

int tunnel_set_kni_ip_add(char * ifname, in_addr_t ip, int mask_prefix){
	char strcmd[256];
	char ipstr[32];
	int ret;
	
	snprintf(strcmd, sizeof(strcmd), "ip addr add %s/%d dev %s", GETIPSTRING(ip,ipstr),mask_prefix,ifname);
	ret = system(strcmd);
	return ret;
}

int tunnel_set_kni_ip_del(char * ifname, in_addr_t oldip, int mask_prefix){
	char strcmd[256];
	char ipstr[32];
	int ret;
	
	snprintf(strcmd, sizeof(strcmd), "ip addr del %s/%d dev %s", GETIPSTRING(oldip,ipstr),mask_prefix,ifname);
	ret = system(strcmd);
	return ret;
}

int tunnel_ip_set(){
	//reset ip
	int index;
	if (kni_port_params_array[0]) {
		for(index = 0; index < kni_port_params_array[0]->nb_kni; index++){
			tunnel_ip_reset(kni_port_params_array[0]->kni_name[index]);
		}

		if(local_service_ip != 0){
			iface_kni_add_ip(1,local_service_ip, local_service_mask);
		}
		
		
	}

}
int mask_to_prefix(in_addr_t mask){
	char * bits;
	int index;
	int pre = 0;
	
	bits = (char*)&mask;
	for(index = 0; index<4; index++){
		int jj =0;
		for(jj = 0; jj < 8; jj++){
			int bit;
			bit = (bits[index]<<jj)&0x80;
			bit =bit>>7;
			//printf("bit %d,%d:%d ", index,jj,bit);
			if(bit) pre++;
			else return pre;
		}
		//printf("\n");
	}
	//printf("\n");

	return pre;
}


int iface_kni_add_ip(int operate, in_addr_t ip, in_addr_t mask){
	//当前仅支持一个kni接口，仅对该接口设置IP
	int index = 0;
	int pre = 0;

	pre = mask_to_prefix(mask);
	
	if (kni_port_params_array[0]) {
		for(index = 0; index < kni_port_params_array[0]->nb_kni; index++){
			if(operate == 0){
				tunnel_set_kni_ip_del(kni_port_params_array[0]->kni_name[index], ip, pre);
			}
			else {
				tunnel_set_kni_ip_add(kni_port_params_array[0]->kni_name[index], ip, pre);
			}
		}
	}
}


void tunnel_ip_reset(char * ifname){
	char strcmd[256];
	snprintf(strcmd, sizeof(strcmd), "ifconfig %s 0 0 ", ifname);
	system(strcmd);
}

int check_pkg_pool_size(){
	long mem;
	int pool = 4096;
	
	if(pool  < 4096) {
		pool = 4096;
	}
	return pool;
	
}

/* Initialise ports/queues etc. and start main loop on each core */
int
dpdk_main(int argc, char** argv)
{
	int ret;
	uint16_t nb_sys_ports, port;
	unsigned i,index;
	void *retval;
	pthread_t kni_link_tid;
	int pid;
	memset(&g_iface_role, 0x00, sizeof(g_iface_role));
	ret = parse_confg_file(DPDK_CONFIG_FILE);
	if(ret < 0){
		rte_exit(EXIT_FAILURE, "Could not parse config\n");

	}

	for (index = 0; index < eth_role_max; index++){
		if(g_iface_role[index].valid == 0) {
			printf("Error: Loss interface role configuration\n");
			return -1;
		}
	}
	

	/* Initialise EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
	argc -= ret;
	argv += ret;
	/*
	for(i = 0; i<argc; i++){
		printf("argv[%d]=%s\n ",i, argv[i]);
	}
	printf("\n");
	*/
	/* Parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");



	pkgbuf_count = check_pkg_pool_size();

	printf("Packet buffer pool size:%d\n",pkgbuf_count);
	/* Create the mbuf pool */
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", pkgbuf_count/*NB_MBUF*/,
		MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
	if (pktmbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
		return -1;
	}

	/* Get number of ports found in scan */
	nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");

	/* Check if the configured port ID is valid */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		if (kni_port_params_array[i] && !rte_eth_dev_is_valid_port(i))
			rte_exit(EXIT_FAILURE, "Configured invalid "
						"port ID %u\n", i);

	/* Initialize KNI subsystem */
	init_kni();

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(port) {
		init_port(port);

		if (port >= RTE_MAX_ETHPORTS)
			rte_exit(EXIT_FAILURE, "Can not use more than "
				"%d ports for kni\n", RTE_MAX_ETHPORTS);
			char mac_addr[6];
		
			/* Get the interface default mac address */
			ret = rte_eth_macaddr_get(port,
				(struct rte_ether_addr *)mac_addr);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Failed to get MAC address (port %u): %s\n",
					port, rte_strerror(-ret));
			for(index=0; index<eth_role_max; index++){
				if(memcmp(g_iface_role[index].mac, mac_addr,6) == 0 ){
					g_iface_cfg[index].id = port;
					if(g_iface_cfg[index].pkni != NULL && index == eth_mirror) {
						rte_exit(EXIT_FAILURE,
						"Error  duplication for mirror interface(port %u): %s\n",port);
					}else if(index == eth_mirror){
						kni_alloc(port);
					}
				}
			}
	}
	check_all_ports_link_status(ports_mask);

	ret = rte_ctrl_thread_create(&kni_link_tid,
				     "KNI link status check", NULL,
				     monitor_all_ports_link_status, NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"Could not create link status thread!\n");


	
	/* Launch per-lcore function on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
	#if 0
	RTE_LCORE_FOREACH_SLAVE(i) {
		if (rte_eal_wait_lcore(i) < 0)
			return -1;
	}
	#else
	//根本不会运行到这里
	while(1){
		usleep(1000000);
	}
	#endif
	monitor_links = 0;

	
	
	pthread_join(kni_link_tid, &retval);

	/* Release resources */
	RTE_ETH_FOREACH_DEV(port) {
		if (!(ports_mask & (1 << port)))
			continue;
		kni_free_kni(port);
	}
	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		if (kni_port_params_array[i]) {
			rte_free(kni_port_params_array[i]);
			kni_port_params_array[i] = NULL;
		}

	return 0;
}

void *mbuf_data_limit(struct rte_mbuf  *mbuf){
	return ((char*)mbuf->buf_addr +MBUF_DATA_SZ + sizeof(struct rte_mbuf)+ mbuf->priv_size );
}
struct rte_mbuf  * dpdk_get_pkt(){
	struct rte_mbuf  * mbuf = rte_pktmbuf_alloc(pktmbuf_pool );

	return mbuf;
}


int dpdk_start(){
	int ret;
	
	pthread_t pid1;
	pthread_attr_t attr1;

	

	pthread_attr_init(&attr1);
	pthread_attr_setscope(&attr1, PTHREAD_SCOPE_PROCESS);
	pthread_attr_setdetachstate(&attr1, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&pid1, &attr1, dpdk_start2, NULL);
	if(ret < 0){
		return -1;
	}
	pthread_attr_destroy(&attr1);

}

