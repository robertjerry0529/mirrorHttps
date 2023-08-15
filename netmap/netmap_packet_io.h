#ifndef NETMAP_PACKET_IO_H

#define NETMAP_PACKET_IO_H

typedef struct netmap_mbuf_queue{
	pthread_mutex_t lock;
	unsigned int length;
	unsigned int input_count;
	unsigned int output_count;
	struct rte_mbuf *  mbuf_list;	
	struct rte_mbuf *  mbuf_tail;	
}netmap_mbuf_queue_t;


int netmap_init(void);
int netmap_pkt_input(struct rte_mbuf * mbuf[],int count,int port);

int netmap_pkt_retrieve_intput(struct rte_mbuf * pkt_burst[], int maxcount);
void netmap_pkt_output(struct rte_mbuf * mbuf);
int netmap_pkt_retrieve_output(struct rte_mbuf * pkt_burst[], int maxcount);





#endif
