#ifndef DPDK_MAIN_HEADER
#define DPDK_MAIN_HEADER



/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 2)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ

/* Number of RX ring descriptors */
#define NB_RXD                  1024

/* Number of TX ring descriptors */
#define NB_TXD                  1024

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_US_PER_SECOND       1000000
#define KNI_SECOND_PER_DAY      86400

#define KNI_MAX_KTHREAD 32

#define MAX_ENBURST  32




enum {
	buss_eth_recv_thread,   //注入报文报文接收线程： main_loop
	buss_eth_send_thread,   //inline模式下 ， 报文发送线程：netmap_output_process
	netmap_forward_thread,	//地址转换处理线程
	kni_recv_thread,		//kni 接收线程
	kni_send_thread,		//kni 发送线程
	kni_netmap_thread,      //业务处理线程： kni_forward_process
	reinject_io_thread,		//回注报文接收和   发送线程
	reinject_buss_thread,	//回注报文业务处理处理线程
	other_thread_x,			//其他线程
	thread_max_count,
};

typedef struct _process_type{
	int thread_type;
	int core_mask;    //运行的core 掩码，位1表示在该core上运行
	int eth_id;
}process_deploy;

int thread_set_cpu(const char * name, int cm) ;

int dpdk_main(int argc, char * argv[]);



extern process_deploy  g_process_info[];
extern int g_deploy_mode;


#endif
