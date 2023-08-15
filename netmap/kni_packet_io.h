#ifndef KNI_PACKET_IO_H

#define KNI_PACKET_IO_H

typedef struct kni_mbuf_queue{
	pthread_mutex_t lock;
	unsigned int length;
	unsigned int input_count;
	unsigned int output_count;
	struct rte_mbuf *  mbuf_list;	
	struct rte_mbuf *  mbuf_tail;	
}kni_mbuf_queue_t;



int kni_start();
int kni_init(void);


#endif
