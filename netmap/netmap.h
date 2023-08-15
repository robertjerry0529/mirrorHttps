#ifndef NETMAP_HEAD
#define NETMAP_HEAD
enum {
	dir_inside = 0,    /*client ---> local */
	dir_outside = 1,	/*local -> client*/

};
//必须小于256字节
typedef struct app_ext_{
	void * session; 
	void* link_next; //struct rte_mbuf *
	unsigned char kni_portid;
	unsigned char eth_portid;
	unsigned char groupId ;//not used
	unsigned char encrypt;
	
	unsigned char *raw_eth;
	unsigned char * raw_ip;
	unsigned char * raw_udp;

	unsigned char layer_offset;  //当前解析的位置相对与原始报文头的偏移量
	unsigned char ipfrag;
	unsigned char link_type;  //ip linked，id linked
	unsigned char msgtype;
	unsigned int clientid;

	
	//for ipforward feature
	unsigned short sport;   //network order
	unsigned short dport;   //networkd order
	unsigned int   saddr;   //network order
	unsigned int   daddr;	//network order
	unsigned char  proto;
	unsigned char side;
	unsigned char tcp_tunnel;  //add for tcp data tunnel
	unsigned char  reserved;
	unsigned int flags;
	/*end for ipforward feature*/
	void * mbuf; //base addr
	unsigned char * rptr;
	unsigned char *wptr;
	unsigned char *limit;
	unsigned char *base;
	
	unsigned char ip_off;
    unsigned char logic_id;
	unsigned char  icmp_type;
	unsigned char  icmp_code;
//	unsigned char * alloc_by;
//	unsigned char * alloc_line;
	
}mbuf_app_ext;






enum {
	PACKET_DROP = 1,
	PACKET_CONN,
	PACKET_CACHE,
	PACKET_SKIP_TUNNEL,   /*报文不经过隧道处理*/
	PACKET_INJECT,    /*报文直接给kni*/
	PACKET_WAY_MAX
};


#define mbuf_freed_check(x ) 
/*
static void mbuf_freed_check(struct rte_mbuf * mbuf, int line) {
	mbuf_app_ext * app;
	app = (mbuf_app_ext *)mbuf->buf_addr;
	if (app->clientid != 0) {
		assert(0);
	}
	app->clientid = line;
}
*/

#define MBUF_APP_EXT(mbuf)   (mbuf_app_ext *)mbuf->buf_addr
#define MBUF_DATA(m) 		 ((char*)m->buf_addr + m->data_off)
#define MBUF_EXT_LINK(mbuf)  ((mbuf_app_ext *)(mbuf)->buf_addr)->link_next
#define MBUF_GETBY_APPEXT(extapp)   (struct rte_mbuf *  )


int netmap_init();
int netmap_start();
int netmap_packet_conn(struct rte_mbuf * mbuf, int dir);

void* netmap_forward_process(void * arg);


#endif
