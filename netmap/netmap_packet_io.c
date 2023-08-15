/*

*/
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h> 
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
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
#include "netmap_ip.h"
#include "timewheel.h"


#include "conn.h"
#include "local_ip.h"
#include "netmap.h"

#include "netmap_packet_io.h"

netmap_mbuf_queue_t netmap_input_list;
netmap_mbuf_queue_t netmap_output_list;

sem_t netmap_input_signal_object;
sem_t netmap_output_signal_object;


int netmap_signal_init(){
	sem_init(&netmap_input_signal_object,0, 0);
	sem_init(&netmap_output_signal_object,0, 0);
	return 1;
}

int  netmap_wait_signal(sem_t * psem, int timeout){

	struct timespec ts;
	int ret;

    ret = clock_gettime(CLOCK_REALTIME,&ts); //这里返回0秒，调用失败
    ts.tv_sec += timeout/1000;
    ts.tv_nsec += (timeout%1000)*1000;
    
    ret= sem_timedwait (psem, &ts);

	return ret;
}

void netmap_post_signal_os(sem_t * psem){
	sem_post(psem);
}

int netmap_init(void){

	memset(&netmap_input_list, 0x00, sizeof(netmap_input_list));
	memset(&netmap_output_list, 0x00, sizeof(netmap_output_list));
	pthread_mutex_init(&netmap_input_list.lock,NULL);
	pthread_mutex_init(&netmap_output_list.lock,NULL);
	netmap_signal_init();

	return 1;
}



/*
  desc:
  	recv pkts from eth

*/
int netmap_pkt_input(struct rte_mbuf * mbuf[],int count,int port){
	netmap_mbuf_queue_t * pface;
	
	int index;
	mbuf_app_ext * papp;
	
	
	pface = &netmap_input_list;

	pthread_mutex_lock(&pface->lock);
	for(index = 0; index< count; index++){
		papp = MBUF_APP_EXT(mbuf[index]);
		papp->eth_portid = port;
		papp->kni_portid = 0;
		papp->groupId = 0;
		MBUF_EXT_LINK(mbuf[index]) = NULL;
		
		if(pface->mbuf_list){
			
			MBUF_EXT_LINK(pface->mbuf_tail) = mbuf[index];
			pface->mbuf_tail = mbuf[index];
		}
		else {
			pface->mbuf_list = mbuf[index];
			pface->mbuf_tail = mbuf[index];
		}
	}
	pface->length += count;
	
	pface->input_count += count;
	assert(pface->output_count + pface->length  == pface->input_count);
	
	pthread_mutex_unlock(&pface->lock);
	
	netmap_post_signal_os(&netmap_input_signal_object);
	return count;
}



int netmap_pkt_retrieve_intput(struct rte_mbuf * pkt_burst[], int maxcount){
	netmap_mbuf_queue_t * penq;
	
	int num = 0;
	
	penq = &netmap_input_list;

	
	if(penq->length == 0) {
		netmap_wait_signal(&netmap_input_signal_object,5000);
		return 0 ;
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




void netmap_pkt_output(struct rte_mbuf * mbuf){
	netmap_mbuf_queue_t * pface;
	

	pface = &netmap_output_list;

	pthread_mutex_lock(&pface->lock);
	MBUF_EXT_LINK(mbuf) = NULL;
	if(pface->mbuf_list){
		
		MBUF_EXT_LINK(pface->mbuf_tail) = mbuf;
		pface->mbuf_tail = mbuf;
	}
	else {
		pface->mbuf_list = mbuf;
		pface->mbuf_tail = mbuf;
	}
	
	pface->length += 1;

	pface->input_count += 1;
	assert(pface->output_count + pface->length  == pface->input_count);
	
	pthread_mutex_unlock(&pface->lock);
	
	netmap_post_signal_os(&netmap_input_signal_object);
	return ;
}


/*
	desc:
		retrieve pkts from send out list
*/
int netmap_pkt_retrieve_output(struct rte_mbuf * pkt_burst[], int maxcount){
	netmap_mbuf_queue_t * penq;
	int len;
	int num = 0;
	
	penq = &netmap_output_list;
	
	if(penq->length == 0) {
		//netmap_wait_signal(&netmap_output_signal_object, 10000);
		return 0 ;
	}
	
	pthread_mutex_lock(&penq->lock);
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

