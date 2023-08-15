#include <arpa/inet.h>
#include <netinet/in.h> 
#include "common.h"
#include "utils.h"
unsigned int g_local_ip_addr;

in_addr_t g_ippool_mask =  0x0a000000;
in_addr_t reject_gateway;
in_addr_t ippool_get_id(in_addr_t saddr){

	unsigned int haddr;
	in_addr_t  ret;
	
	char sip[32];
	
	//remove first dot
	haddr = ntohl(saddr) & 0x00ffffff;

	
	GETIPSTRING(htonl(haddr), sip);
	//printf("short addr: %s\n", sip);
	
	ret  = (ntohl(g_ippool_mask) | haddr);
	ret = htonl(ret);

	GETIPSTRING(ret, sip);
	//printf("map addr: %s\n", sip);
	
	
	return ret;
}


int kni_netmap_pool_route(){
	char strcmd[512];
	char pool[32];
	char gw[32];

	if(reject_gateway == 0){
		return ;
	}
	
	GETIPSTRING(g_ippool_mask, pool);
	GETIPSTRING(reject_gateway, gw);
	snprintf(strcmd, sizeof(strcmd), "route add -net  %s/24 gateway %s dev vEth0", pool, gw);
	//printf("%s %d,system cmd:%s\n", __FUNCTION__,__LINE__,strcmd);
	system(strcmd);

}