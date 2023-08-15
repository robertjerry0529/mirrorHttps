#ifndef LOCAL_IP_HEAD
#define LOCAL_IP_HEAD

extern unsigned int g_local_ip_addr;
extern in_addr_t g_ippool_mask ;
extern in_addr_t reject_gateway;
in_addr_t ippool_get_id(in_addr_t saddr);
int kni_netmap_pool_route();


#endif
