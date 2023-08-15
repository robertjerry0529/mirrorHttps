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
	buss_eth_recv_thread,   //ע�뱨�ı��Ľ����̣߳� main_loop
	buss_eth_send_thread,   //inlineģʽ�� �� ���ķ����̣߳�netmap_output_process
	netmap_forward_thread,	//��ַת�������߳�
	kni_recv_thread,		//kni �����߳�
	kni_send_thread,		//kni �����߳�
	kni_netmap_thread,      //ҵ�����̣߳� kni_forward_process
	reinject_io_thread,		//��ע���Ľ��պ�   �����߳�
	reinject_buss_thread,	//��ע����ҵ�������߳�
	other_thread_x,			//�����߳�
	thread_max_count,
};

typedef struct _process_type{
	int thread_type;
	int core_mask;    //���е�core ���룬λ1��ʾ�ڸ�core������
	int eth_id;
}process_deploy;

int thread_set_cpu(const char * name, int cm) ;

int dpdk_main(int argc, char * argv[]);



extern process_deploy  g_process_info[];
extern int g_deploy_mode;


#endif
