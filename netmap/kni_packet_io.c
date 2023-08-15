/*

*/
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h> 
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <semaphore.h>
#include <arpa/inet.h>
#include <netinet/in.h> 

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
#include "iface.h"
#include "netmap.h"
#include "kni_packet_io.h"
#include "netmap_parse_pkt.h"
#include "timewheel.h"

kni_mbuf_queue_t kni_tokni_list;
kni_mbuf_queue_t kni_fromkni_list;

sem_t kni_to_signal_object;
sem_t kni_from_signal_object;


//extern  process_deploy   g_process_info[thread_max_count];
int kni_signal_init(){
	sem_init(&kni_to_signal_object,0, 0);
	sem_init(&kni_from_signal_object,0, 0);
	return 1;
}

int  kni_wait_signal(sem_t* psem,int timeout){

	struct timespec ts;
	int ret;

    ret = clock_gettime(CLOCK_REALTIME,&ts); //这里返回0秒，调用失败
    ts.tv_sec += timeout/1000;
    ts.tv_nsec += (timeout%1000)*1000;
    
    ret= sem_timedwait (psem, &ts);

	return ret;
}

void kni_post_signal_os(sem_t * psem){
	sem_post(psem);
}

int kni_init(void){

	memset(&kni_tokni_list, 0x00, sizeof(kni_tokni_list));
	memset(&kni_fromkni_list, 0x00, sizeof(kni_fromkni_list));
	pthread_mutex_init(&kni_tokni_list.lock,NULL);
	pthread_mutex_init(&kni_fromkni_list.lock,NULL);
	kni_signal_init();

	return 1;
}

#if 0

/*
 desc:
 	send packets to kni interface
*/
void kni_pkt_put_to_recv_list(struct rte_mbuf * mbuf){
	kni_mbuf_queue_t * pface;
	
	pface = &kni_tokni_list;

	pthread_mutex_lock(&pface->lock);
	
	if(pface->mbuf_list){
		
		MBUF_EXT_LINK(pface->mbuf_tail) = mbuf;
		pface->mbuf_tail = mbuf;
	}
	else {
		pface->mbuf_list = mbuf;
		pface->mbuf_tail = mbuf;
	}
	pface->length++;
	
	pface->input_count++;
	assert(pface->output_count + pface->length  == pface->input_count);
	
	pthread_mutex_unlock(&pface->lock);
	
	kni_post_signal_os(&kni_input_signal_object);
	return ;
}
#endif

/*
  desc:
  	 retrieve packet to kni
*/
int kni_get_pkt_from_send_list(struct rte_mbuf * pkt_burst[], int maxcount){
	kni_mbuf_queue_t * penq;
	
	int num = 0;
	
	penq = &kni_tokni_list;
	
	if(penq->length == 0) {
		//kni_wait_signal(&kni_to_signal_object,10000);
		if(penq->length == 0){
			return 0 ;
		}
	}
	
	pthread_mutex_lock(&penq->lock);
	assert(penq->output_count + penq->length  == penq->input_count);
	while(penq->mbuf_list){
		pkt_burst[num] = penq->mbuf_list;
		
		penq->mbuf_list = MBUF_EXT_LINK(penq->mbuf_list);
		if(++num >= maxcount) {
			break;
		}
	}
	if(!penq->mbuf_list){
		penq->mbuf_tail = NULL;
		assert(penq->length == num);
	}
	penq->length -= num;
	penq->output_count += num;
	assert(penq->output_count + penq->length  == penq->input_count);
	pthread_mutex_unlock(&penq->lock);
	return  num;
	
}


/*
  desc:
  	 retrieve packet to kni
*/
int kni_get_pkt_from_recv_list(struct rte_mbuf * pkt_burst[], int maxcount){
	kni_mbuf_queue_t * penq;
	
	int num = 0;
	
	penq = &kni_fromkni_list;
	
	if(penq->length == 0) {
		kni_wait_signal(&kni_from_signal_object,5000);
		if(penq->length == 0){
			return 0 ;
		}
	}
	
	pthread_mutex_lock(&penq->lock);
	while(penq->mbuf_list){
		pkt_burst[num] = penq->mbuf_list;
		printf("Debug: kni pkt get %d:0x%x\n",penq->output_count+num, pkt_burst[num]);
		penq->mbuf_list = MBUF_EXT_LINK(penq->mbuf_list);
		if(++num >= maxcount) {
			break;
		}
	}
	if(!penq->mbuf_list){
		assert(penq->length == num);
		penq->mbuf_tail = NULL;
	}
	penq->length -= num;
	penq->output_count += num;
	assert(penq->output_count + penq->length  == penq->input_count);
	pthread_mutex_unlock(&penq->lock);
	return  num;
	
}

/*
 desc:
 	recv packets from kni interface
*/
int kni_pkt_put_to_recv_list(struct rte_mbuf * mbuf[], int num, int port,int kni_id,int group){
	kni_mbuf_queue_t * pface;

	int index;
	mbuf_app_ext * papp;
	
	pface = &kni_fromkni_list;
	printf("Debug: kni pkt put count\n",num);

	pthread_mutex_lock(&pface->lock);
	for(index = 0; index<num; index++){
		papp = MBUF_APP_EXT(mbuf[index]);
		papp->eth_portid = port;
		papp->kni_portid = kni_id;
		papp->groupId = group;
		MBUF_EXT_LINK(mbuf[index]) = NULL;

		printf("Debug: kni pkt put %d:0x%x\n",pface->input_count+index, mbuf[index]);
		if(pface->mbuf_list){
			
			MBUF_EXT_LINK(pface->mbuf_tail) = mbuf[index];
			pface->mbuf_tail = mbuf[index];
		}
		else {
			pface->mbuf_list = mbuf[index];
			pface->mbuf_tail = mbuf[index];
		}
	}
	pface->length += num;
	
	pface->input_count += num;
	assert(pface->output_count + pface->length  == pface->input_count);
	
	pthread_mutex_unlock(&pface->lock);
	
	kni_post_signal_os(&kni_from_signal_object);
	return num;
}

/*
 desc:
 	recv packets from kni interface
*/
void kni_put_pkt_to_send_list(struct rte_mbuf * mbuf){
	kni_mbuf_queue_t * pface;

	int index;
	mbuf_app_ext * papp;
	
	pface = &kni_tokni_list;

	pthread_mutex_lock(&pface->lock);

	papp = MBUF_APP_EXT(mbuf);
	MBUF_EXT_LINK(mbuf) = NULL;

	
	if(pface->mbuf_list){
		
		MBUF_EXT_LINK(pface->mbuf_tail) = mbuf;
		pface->mbuf_tail = mbuf;
	}
	else {
		pface->mbuf_list = mbuf;
		pface->mbuf_tail = mbuf;;
	}
	
	pface->length += 1;
	
	pface->input_count += 1;
	assert(pface->output_count + pface->length  == pface->input_count);
	
	pthread_mutex_unlock(&pface->lock);
	
	kni_post_signal_os(&kni_to_signal_object);
	return ;
}

#if 0
void* kni_recv_process(void * arg){
	int bufCount;

	wait_dpdk_iface_read();

	if(kni_iface_ready_get() == 0) {
		usleep(1000);
	}
	
	mbuf_app_ext * papp;
	//thread_set_cpu(__FUNCTION__, g_process_info[kni_recv_thread].core_mask);
	
	while(1){
		
		int eth_id = g_process_info[kni_recv_thread].eth_id;
		int kpkts = kni_io(&g_iface_cfg[eth_id ]);
	
		if(kpkts == 0 ) {
			usleep(100);
		}
		
	}
	
	return NULL;
}
#endif

#if 0
void* kni_send_process(void * arg){
	int bufCount;
	
	mbuf_app_ext * papp;

	if(kni_iface_ready_get() == 0) {
		usleep(1000);
	}
	
	struct rte_mbuf * pkt_burst[MAX_ENBURST];
	wait_dpdk_iface_read();

	
	arg = arg;
	//thread_set_cpu(__FUNCTION__, g_process_info[kni_send_thread].core_mask);

	while(1){
		bufCount = kni_get_pkt_from_send_list(pkt_burst,MAX_ENBURST);
		if(bufCount == 0){
			continue;
		}

		papp = MBUF_APP_EXT(pkt_burst[0]);
		
		kni_send_burst(papp->eth_portid,pkt_burst,bufCount);
		

	}

	
	return NULL;
}

#endif


void* kni_forward_process(void * arg){
	int bufCount;
	int index;

	int ret;
	struct rte_mbuf * pkt_burst[MAX_ENBURST];
	arg = arg;
	
	if(kni_iface_ready_get() == 0) {
		usleep(1000);
	}
		

	
	//thread_set_cpu(__FUNCTION__, g_process_info[kni_netmap_thread].core_mask);

	while(1){
		bufCount = kni_get_pkt_from_recv_list(pkt_burst,MAX_ENBURST);
		if(bufCount == 0){
			conn_node_aging();
			continue;
		}

		for(index = 0; index<bufCount; index++){

			ret = netmap_parse_packet(pkt_burst[index], dir_outside);
			if(ret == PACKET_DROP) {
				//mbuf_freed_check(pkt_burst[index], __LINE__) ;
				rte_pktmbuf_free(pkt_burst[index]);
				continue;
			}
			else if(ret == PACKET_CACHE){
				continue;
			}
			else if(ret == PACKET_INJECT){
				netmap_pkt_output(pkt_burst[index]);
				continue;
			}
			
			ret = netmap_packet_conn(pkt_burst[index],dir_outside );	
			if(ret == PACKET_DROP) {
				//mbuf_freed_check(pkt_burst[index], __LINE__) ;
				rte_pktmbuf_free(pkt_burst[index]);
				continue;
			}else if(ret == PACKET_CACHE){
				continue;
			}else {
				netmap_pkt_output(pkt_burst[index]);
				continue;
			}
		}

		conn_node_aging();
	}

	
	return NULL;
}





int kni_start(){
	int ret;
	
	pthread_t pid1;
	pthread_attr_t attr1;


#if 0

	pthread_attr_init(&attr1);
	pthread_attr_setscope(&attr1, PTHREAD_SCOPE_PROCESS);
	pthread_attr_setdetachstate(&attr1, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&pid1, &attr1, kni_recv_process, NULL);
	if(ret < 0){
		return -1;
	}
	pthread_attr_destroy(&attr1);

	pthread_attr_init(&attr1);
	pthread_attr_setscope(&attr1, PTHREAD_SCOPE_PROCESS);
	pthread_attr_setdetachstate(&attr1, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&pid1, &attr1, kni_send_process, NULL);
	if(ret < 0){
		return -1;
	}
	pthread_attr_destroy(&attr1);

#endif
	
	pthread_attr_init(&attr1);
	pthread_attr_setscope(&attr1, PTHREAD_SCOPE_PROCESS);
	pthread_attr_setdetachstate(&attr1, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&pid1, &attr1, kni_forward_process, NULL);
	if(ret < 0){
		return -1;
	}
	pthread_attr_destroy(&attr1);
	return ret;


}

