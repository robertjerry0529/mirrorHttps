#ifndef SSLCTX_DOMAIN_HEAD
#define SSLCTX_DOMAIN_HEAD


typedef struct ssl_ctx_st_{
	void * ssl;
	char domain[DOMAIN_LEN];
	int ssl_state;
	time_t create_time;
}ssl_ctx_st;




#define MAX_SSL_DOMAIN_HASH_COUNT   2048
typedef void (*ssl_ctx_walk_cb)(ssl_ctx_st * sock, void * arg);
struct ssl_ctx_hash_tbl {
	struct hashtab *table;	/* hash table (keyed on a string) */
	unsigned int nprim;		/* number of primary names in table */
    pthread_mutex_t hash_lock;
};

typedef struct addr_key_{
	in_addr_t addr;
	int port;
}st_addr_key;

typedef struct ssl_map_node_{
	in_addr_t addr;
	int port;
	void * ssl;
}ssl_map_node;

struct ssl_ctx_walk_param
{
	ssl_ctx_walk_cb func;
	void * arg;
};

#define ssl_ctx_SKEY(key)  (key->faddr & key->fport)

#define DOMAIN_SSL_REQUEST  1

//最大的控制通信请求消息长度
#define FIFO_DOMAIN_MSG_LEN  256
typedef struct fifo_domain_msg_t_{
	int id;
	int len;
	char data[];
}fifo_domain_msg_t;


void * ssl_ctx_get_by_local_addr(in_addr_t laddr, unsigned short port, in_addr_t * raddr, unsigned short * rport);
int ssl_ctx_remove_from_redis(char * domain, in_addr_t nat_laddr, unsigned short lport, 
	in_addr_t nat_faddr, unsigned short fport,in_addr_t raw_faddr,in_addr_t raw_laddr);


#endif
