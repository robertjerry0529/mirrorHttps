#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h> 
#include <pthread.h>
#include <semaphore.h>
#include <dlfcn.h>


#include <sys/types.h>
#include <openssl/ssl.h>

#include <openssl/md5.h>
#include <pthread.h>
//redis
#include <hiredis/hiredis.h>
#include "common.h"
#include "utils.h"
#include "plat_log.h"


#include "sslctx_post_domain.h"







int ssl_ctx_port_to_redis(char * domain, in_addr_t nat_laddr, unsigned short lport, 
	in_addr_t nat_faddr, unsigned short fport,in_addr_t raw_faddr,in_addr_t raw_laddr){
	char ipstr1[32];
	char ipstr2[32];
	char ipstr3[32];
	char ipstr4[32];
	char fstr[256];
	redisContext *conn = redisConnect("127.0.0.1", 6379);
	if( conn == NULL || conn->err ) {
		if(conn) {
			printf("connection error: %s\n",conn->errstr);  
		} else {
			printf("NULL, can't allocate redis context\n");
			return 0;
		}
	}

	GETIPSTRING(nat_faddr, ipstr1);
	GETIPSTRING(nat_faddr, ipstr2);
	GETIPSTRING(raw_laddr, ipstr3);
	GETIPSTRING(raw_faddr, ipstr4);
	//key  nat_faddr:fport
	//value: domain:nat_faddr:fport:raw_laddr:raw_faddr
	snprintf(fstr, sizeof(fstr), "SET %s:%d %s:%s:%d:%s:%s EX 5", ipstr1, ntohs(fport), domain,ipstr2,htons(fport),
		ipstr3,ipstr4);
	printf("%s %d, redis set:%s\n",__FILE__,__LINE__, fstr);
	redisReply *reply = (redisReply*)redisCommand((redisContext*)conn, fstr);
	if(reply){
		if((reply->type == REDIS_REPLY_STATUS) && (strncmp(reply->str, "OK", 2)==0 ) ) {
			printf("Redis set ok\n");
		} else {
			printf("redis set failed\n");
		}
		freeReplyObject(reply);
		redisFree(conn);
		return 0;
	} 
	else {
		printf("select cache db failed");
		return 2;
	}
	printf("%s %d, host info put into redis\n",__FILE__,__LINE__,domain);
	
	redisFree(conn);

}






/*desc:

	简化处理，将地址信息和域名，保存到redis中
	
	
*/
int ssl_ctx_post_host_cert(char * domain, in_addr_t nat_laddr, unsigned short dport, in_addr_t nat_faddr, unsigned short fport, in_addr_t raw_saddr,in_addr_t raw_daddr){
	
	//查找sslctx
	
	char sdomain[64];
	ssl_map_node * pssl;
	//trim to short domain
	domain_trim_short(domain, sdomain);
	
	ssl_ctx_port_to_redis(domain, nat_laddr, dport, nat_faddr, fport,raw_saddr, raw_daddr);
	
	return 0;
}




