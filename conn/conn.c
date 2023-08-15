

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "common.h"
#include "bsd-queue.h"
#include "local_ip.h"
#include "timewheel.h"
#include "sslctx_post_domain.h"
#include "conn.h"



int g_conn_hash_tbl_size = 8096*4;
conn_hash_tbl * g_conn_hash_tbl;  //id 用户表

conn_hash_tbl * g_conn_fhash_tbl;  //id 用户表

TimeWheel * tcpwhile;
int g_conn_count = 0; 

#ifdef MIRROR
pthread_mutex_t aging_lock;
conn_hash_head_t aging_list;
#endif


int conn_init(){
	int i;
	g_conn_hash_tbl = malloc(g_conn_hash_tbl_size * sizeof(conn_hash_tbl));
	if(!g_conn_hash_tbl){
		printf("%s: create tcp conn hash table failed\n", __FUNCTION__);
		return -1;
	}

	for(i=0; i< g_conn_hash_tbl_size; i++){
		
		LIST_INIT(&g_conn_hash_tbl[i].hash);
		pthread_mutex_init(&g_conn_hash_tbl[i].lock,NULL);
	}
#ifndef MIRROR 
	g_conn_fhash_tbl = malloc(g_conn_hash_tbl_size * sizeof(conn_hash_tbl));
	if(!g_conn_fhash_tbl){
		printf("%s: create tcp conn hash table failed\n", __FUNCTION__);
		return -1;
	}

	for(i=0; i< g_conn_hash_tbl_size; i++){
		LIST_INIT(&g_conn_fhash_tbl[i].hash);
		pthread_mutex_init(&g_conn_fhash_tbl[i].lock,0);
	}

	tcpwhile = tw_create();
	if(!tcpwhile) return -1;
#else 
	LIST_INIT(&aging_list);
	pthread_mutex_init(&aging_lock,0);

#endif 
	
	return 0;
}

/*param:
	node: 
  return:
  	1: need free node
  	0: normal
*/
int conn_aging(void *node, unsigned int when){
	tcp_conn_t * obj = (tcp_conn_t*)node;

	if(obj->last_active < when + obj->aging_time) {
		//need free
		printf("%s %d, free conn 0x%x\n",__FILE__,__LINE__,node);
		//remove record in redis
#if 0
	no need del record from redis, for its has expire time
	//key  nat_faddr:fport
	//value: domain:nat_faddr:fport:raw_laddr:raw_faddr
		ssl_ctx_remove_from_redis(obj->host, obj->nat_laddr, obj->raw_dport, obj->nat_faddr,
		obj->raw_sport, obj->raw_saddr, obj->raw_daddr);
	#endif
		g_conn_count--;
		conn_hash_remove(node);
		conn_fhash_remove(node);
		return 1;
	}
	return 0;
}



static int hashId(unsigned int saddr,unsigned short sport,  unsigned int daddr,unsigned short dport){
	dport = dport;
	int ret = (saddr^daddr ^ sport) & (g_conn_hash_tbl_size - 1);
	
	return ret;
}
#ifdef MIRROR
void conn_free_force(tcp_conn_t * node){
	//put on timelist
	g_conn_count--;
	conn_hash_remove(node);
	printf("%s %d, node=0x%x to delay list\n",__FUNCTION__,__LINE__,node);
	pthread_mutex_lock(&aging_lock);
	LIST_INSERT_HEAD(&aging_list,node, hash);
	pthread_mutex_unlock(&aging_lock);
	return ;
}

void conn_free_delay(){
	tcp_conn_t * conn;
	pthread_mutex_lock(&aging_lock);
	while((conn = LIST_FIRST(&aging_list)) != NULL){
		LIST_REMOVE(conn, hash);
		printf("%s %d, node=0x%x do free\n",__FUNCTION__,__LINE__,conn);
		free(conn);
	}
	pthread_mutex_unlock(&aging_lock);
}
#else 

void conn_node_aging(){
	TimeWheelTick(tcpwhile);
}

#endif


/*session hash 表*/
int conn_hash_insert(tcp_conn_t * conn){


	int key ;
	conn_hash_tbl * punit;
	tcp_conn_t * curobj;
	conn_hash_head_t *hashlist;
	

	key = hashId(conn->raw_saddr,conn->raw_sport,conn->raw_daddr, conn->raw_dport);
	printf("%s %d, hash key:%d\n",__FUNCTION__,__LINE__, key);
	punit = &g_conn_hash_tbl[key];
	
	pthread_mutex_lock(&punit->lock);
	hashlist = &punit->hash;

	FOREACH_LISTELT(curobj, hashlist, hash)
    {
       assert(conn != curobj);
       if(curobj->raw_saddr == conn->raw_saddr
	   	&&curobj->raw_daddr == conn->raw_daddr 
	   	&& curobj->raw_sport == conn->raw_sport
	   	&& curobj->raw_dport == conn->raw_dport
	   	&& curobj->state == 1){
	   	   printf("warning: exist session node, need remove first\n");
		   assert(0);
           break;
       }
       
    }
	 
	LIST_INSERT_HEAD(hashlist,conn,hash);
	pthread_mutex_unlock(&punit->lock);
	return 1;
}




/*session hash 表*/
int conn_fhash_insert(tcp_conn_t * conn){


	int key ;
	conn_hash_tbl * punit;
	tcp_conn_t * curobj;
	conn_hash_head_t *hashlist;
	

	key = hashId(conn->nat_faddr,conn->raw_sport,conn->nat_laddr, conn->raw_dport);
	printf("%s %d, hash key:%d\n",__FUNCTION__,__LINE__, key);
	punit = &g_conn_fhash_tbl[key];
	
	pthread_mutex_lock(&punit->lock);
	hashlist = &punit->hash;

	FOREACH_LISTELT(curobj, hashlist, fhash)
    {
       assert(conn != curobj);
       if(curobj->nat_laddr == conn->nat_laddr
	   	&&curobj->raw_sport == conn->raw_sport 
	   	&& curobj->nat_faddr == conn->nat_faddr
	   	&& curobj->raw_dport == conn->raw_dport
	   	&& curobj->state == 1){
	   	   printf("warning: exist session node, need remove first\n");
           break;
       }
       
    }
	 
	LIST_INSERT_HEAD(hashlist,conn,fhash);
	pthread_mutex_unlock(&punit->lock);
	conn->in_fhash = 1;
	return 1;
}


void conn_hash_remove(tcp_conn_t * conn ) 
{

   int key ;
    conn_hash_tbl * punit;
   if(conn->in_hash == 0) return ;
   
   key = hashId(conn->raw_saddr,conn->raw_dport,conn->raw_saddr, conn->raw_dport);
	printf("%s %d, hash key:%d\n",__FUNCTION__,__LINE__, key);
	punit = &g_conn_hash_tbl[key];

    pthread_mutex_lock(&punit->lock);
    LIST_REMOVE(conn,hash);
    pthread_mutex_unlock(&punit->lock);
	conn->in_hash  = 0;
    return ;
}

void conn_fhash_remove(tcp_conn_t * conn ) 
{

   int key ;
    conn_hash_tbl * punit;

	if(conn->in_fhash ==0) return ;
	
    key = hashId(conn->nat_laddr,conn->raw_sport,conn->nat_faddr, conn->raw_dport);
	printf("%s %d, hash key:%d\n",__FUNCTION__,__LINE__, key);
	punit = &g_conn_fhash_tbl[key];

    pthread_mutex_lock(&punit->lock);
    LIST_REMOVE(conn,fhash);
    pthread_mutex_unlock(&punit->lock);
	conn->in_fhash = 0;
    return ;
}


/*desc
 *  proto: 0: udp, 1:tcp
*/
tcp_conn_t *conn_tcp_lookup(in_addr_t saddr, in_addr_t daddr, 
in_port_t sport,  in_port_t dport) 
{

    int key ;
    conn_hash_tbl * punit;
    tcp_conn_t * curobj;
    conn_hash_head_t *hashlist;
    
    key = hashId(saddr, sport, daddr,  dport);
	printf("%s %d, hash key:%d\n",__FUNCTION__,__LINE__, key);
    punit = &g_conn_hash_tbl[key];
   
    pthread_mutex_lock(&punit->lock);
	
	hashlist = &punit->hash;
    FOREACH_LISTELT(curobj, hashlist, hash)
    {
		
       if(curobj->raw_saddr == saddr 
	   	&& curobj->raw_daddr == daddr 
	   	&& curobj->raw_sport == sport
	   	&& curobj->raw_dport == dport)
       {	
       		
            pthread_mutex_unlock(&punit->lock);
           
            return curobj;
       }
       
    }
    pthread_mutex_unlock(&punit->lock);
    return NULL;
}


/*desc
 *  proto: 0: udp, 1:tcp
*/
tcp_conn_t *conn_tcp_flookup(in_addr_t faddr, in_addr_t laddr, 
in_port_t fport,  in_port_t lport) 
{

    int key ;
    conn_hash_tbl * punit;
    tcp_conn_t * curobj;
    conn_hash_head_t *hashlist;
    
    key = hashId(faddr, fport,  laddr,  lport);
	printf("%s %d, hash key:%d\n",__FUNCTION__,__LINE__, key);
    punit = &g_conn_fhash_tbl[key];
   
    pthread_mutex_lock(&punit->lock);
	
	hashlist = &punit->hash;
    FOREACH_LISTELT(curobj, hashlist, fhash)
    {
		
       if(curobj->nat_faddr == faddr 
	   	&& curobj->nat_laddr == laddr 
	   	&& curobj->raw_sport == fport
	   	&& curobj->raw_dport == lport)
       {	
       		
            pthread_mutex_unlock(&punit->lock);
           
            return curobj;
       }
       
    }
    pthread_mutex_unlock(&punit->lock);
    return NULL;
}

tcp_conn_t * conn_tcp_create(in_addr_t laddr, in_addr_t faddr, in_port_t sport, in_port_t dport){
	int key;
	tcp_conn_t * conn =(tcp_conn_t*) malloc(sizeof(tcp_conn_t))	;
	if(!conn){
		return NULL;
	}
	
	memset(conn, 0x00, sizeof(tcp_conn_t));
	conn->raw_daddr = laddr;
	conn->raw_dport = dport;
	conn->raw_saddr = faddr;
	conn->raw_sport = sport;
	
	conn_hash_insert(conn); 
	conn->in_hash = 1;
	conn->aging_time = 300;
	#ifndef MIRROR 
	conn->tn.func = conn_aging;
	conn->tn.arg = conn;
	
	conn->nat_faddr = ippool_get_id(laddr);

	#else 
	conn->seq[0] = random();
	conn->seq[1] = random();
	#endif
	printf("%s %d, create conn node:0x%x\n",__FILE__,__LINE__,conn);
	g_conn_count++;
	return conn;
}

