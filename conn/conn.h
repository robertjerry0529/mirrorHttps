#ifndef CONN_HEAD
#define CONN_HEAD


enum {
	ssl_unparse = 0,
	ssl_parse_part = 1,
	ssl_parse_end = 2,
};

typedef struct tcp_conn_t_{
	#ifndef MIRROR 
	TimerNode tn;
	#endif
    LIST_ENTRY (tcp_conn_t_) hash;   /*hash for input raw tuples*/
    LIST_ENTRY (tcp_conn_t_) fhash;  /* hash for output tuples */        
    //LIST_ENTRY (tcp_conn_t_) ihash;    
    time_t last_active;
	int aging_time;
	
    unsigned short ssl_state;
	unsigned char bypass;
	unsigned char reserved;
	
	unsigned short proto;
	unsigned short state;
	in_addr_t raw_saddr;
	in_addr_t raw_daddr;
	in_port_t raw_sport;
	in_port_t raw_dport;

	in_addr_t nat_laddr;
	in_addr_t nat_faddr;

	int in_fhash;
	int in_hash ;
	#ifdef MIRROR
	unsigned int ack[2];
	unsigned int seq[2];
	int mirror_close_state[2];
	#else 
	char host[DOMAIN_LEN];
	#endif

}tcp_conn_t;




//根据hash 域名找到proxy_session_t，返回指针
typedef LIST_HEAD(conn_hash_head,tcp_conn_t_ )  conn_hash_head_t;

typedef struct conn_hash_tbl_t
{
    pthread_mutex_t lock;
    conn_hash_head_t hash;
}conn_hash_tbl;


int conn_init();
int conn_hash_insert(tcp_conn_t * conn);
void conn_hash_remove(tcp_conn_t * conn ) ;
tcp_conn_t *conn_tcp_lookup(in_addr_t saddr, in_addr_t daddr, 
in_port_t sport,  in_port_t dport) ;
tcp_conn_t *conn_tcp_flookup(in_addr_t faddr, in_addr_t laddr, 
in_port_t fport,  in_port_t lport) ;
int conn_fhash_insert(tcp_conn_t * conn);
void conn_node_aging();


tcp_conn_t * conn_tcp_create(in_addr_t laddr, in_addr_t faddr, in_port_t sport, in_port_t dport);
void conn_hash_remove(tcp_conn_t * conn ) ;
void conn_fhash_remove(tcp_conn_t * conn ) ;


#ifdef MIRROR
void conn_free_delay();
void conn_free_force(tcp_conn_t * node);


#endif



#endif
