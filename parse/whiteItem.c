
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include<unistd.h>

#include <sys/time.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <assert.h>
#include <pthread.h>

#include "common.h"
#include "bsd-queue.h"
#include "whiteItem.h"

#define WHITE_ITEM_CFG "whitelist_domain.txt"
#define WHITE_ITEM_IP_CFG "whitelist_ip.txt"

#define NEW_WHITE_ITEM  "newwhite.txt"

struct whiteHash_t * g_hashList;

struct whiteAddrHash_t * g_hashAddrList;


int strhash(char * domain){
	
	int key;
	int h=0;
	char *s = domain;
	for(;*s;s++){
		h = *s + h*31;
	}
	h = h&(WHITE_HASH_LEN-1);
	return h;
}

int haship(in_addr_t dip){
	int key = ntohl(dip)&(WHITE_HASH_ADDR_LEN-1);
	return key;
}


int wl_getline(FILE *fp, char * data, int len){

	int ret;
	char con;
	int tlen = 0;
	while(tlen < len-1){
		ret = fread(&con, 1, 1, fp);
		if(ret <=0) break;
		if(con == '\n') break;
		data[tlen] = con;
		tlen++;
	}
	return tlen;
	
}

/*
	desc:
		add domain into white item hash,
	param:
		line: string including domain,maybe invalid

*/
int whiteItem_add(char * line, int len){
	char * st , * end;
	int count = 0;
	st = line ;
	end = line+len;
	
	while(*st==' '|| *st=='\t') st++;
	while(*end==' ' || *end == '\t' || *end=='\r' || *end=='\n') end--;
	if(st >= end) return -1;

	
	int key = strhash(st);
	struct whiteItem_s * node;
	node = malloc(sizeof(struct whiteItem_s));
	if(!node){
		return -1;
	}
	memset(node, 0x00, sizeof(struct whiteItem_s));
	strncpy(node->domain, st, sizeof(node->domain)-1);
	pthread_rwlock_wrlock(&g_hashList[key].lock);

	SIMPLEQ_INSERT_TAIL(&g_hashList[key].list, node,sentry);
			
	pthread_rwlock_unlock(&g_hashList[key].lock);


	
	return 1;
	
}

int whiteItem_add_addr_inet(in_addr_t addr){

	int key = haship(addr);
	
	struct whiteAddr_s * node;
	node = malloc(sizeof(struct whiteAddr_s));
	if(!node){
		return -1;
	}
	memset(node, 0x00, sizeof(struct whiteAddr_s));
	node->addr = addr;
	pthread_rwlock_wrlock(&g_hashAddrList[key].lock);

	SIMPLEQ_INSERT_TAIL(&g_hashAddrList[key].list, node,sentry);
			
	pthread_rwlock_unlock(&g_hashAddrList[key].lock);
	return 1;

}
/*
	desc:
		add domain into white item hash,
	param:
		line: string including domain,maybe invalid

*/
int whiteItem_add_addr(char * line, int len){
	char * st , * end;
	int count = 0;
	st = line ;
	end = line+len;
	
	while(*st==' '|| *st=='\t') st++;
	while(*end==' ' || *end == '\t' || *end=='\r' || *end=='\n') end--;
	if(st >= end) return -1;
	*end = 0;

	in_addr_t addr = inet_addr(st);

	whiteItem_add_addr_inet(addr);


	return 1;
	
}

int whiteItem_load(){
	FILE * fp;
	char line[256];
	int len;
	fp = fopen(WHITE_ITEM_CFG, "rb");
	if(!fp){
		printf("Error: open white list file:%s failed\n", WHITE_ITEM_CFG);
		return -1;
	}
	do {
		len = wl_getline(fp, line, sizeof(line));
		if(len > 0 ){
			line[len] = 0;
		}
		else {
			break;
		}
		whiteItem_add(line, len);
	}while(1);
	fclose(fp);
	return 1;
}


int whiteItem_load_addr(){
	FILE * fp;
	char line[256];
	int len;
	fp = fopen(WHITE_ITEM_IP_CFG, "rb");
	if(!fp){
		printf("Error: open white list file:%s failed\n", WHITE_ITEM_CFG);
		return -1;
	}
	do {
		len = wl_getline(fp, line, sizeof(line));
		if(len > 0 ){
			line[len] = 0;
		}
		else {
			break;
		}
		whiteItem_add_addr(line, len);
	}while(1);
	fclose(fp);
	return 1;
}

int whiteItem_check_domain(char * domain){
	struct whiteItem_s * node;
	int key = strhash(domain);
	int found = 0; 
	pthread_rwlock_rdlock(&g_hashList[key].lock);
	node = SIMPLEQ_FIRST(&g_hashList[key].list);
	while(node != NULL){
		if(strcmp(node->domain, domain) == 0) {
			found = 1;
			break;
		}
		node = SIMPLEQ_NEXT(node,sentry);
	}

	pthread_rwlock_rdlock(&g_hashList[key].lock);
	return found;
}

/*
desc:

return :
	1: in white item
	0: not in

*/
int whiteItem_check(char * domain){
	int len;
	char * st, *end;
	int ncount = 0;
	int ret;
	
	len = strlen(domain);
	end = domain + len;;
	st = domain;
	
	while (st < end) {
		
		if(*end == '.' ){
			if( ncount>=1) {
				ret = whiteItem_check_domain(end+1);
				if(ret == 1) return ret;
			}
			ncount++;
		}
		end--;
	}

	ret = whiteItem_check_domain(end);
	return ret;

}


int whiteItem_add_cfg(char * domain){
	FILE * fp;
	int len;
	char data[256];
	fp = fopen(WHITE_ITEM_CFG, "a+");
	if (!fp) {
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	len = snprintf(data,sizeof(data), "%s\n", domain);
	fwrite(data, len,1,fp);

	fclose(fp);
	return 1;
}

/*
desc:

return :
	1: in white item
	0: not in

*/
int whiteItem_check_addr(in_addr_t destip){
	struct whiteAddr_s * node;
	int key = haship(destip);
	int found = 0; 
	pthread_rwlock_rdlock(&g_hashAddrList[key].lock);
	node = SIMPLEQ_FIRST(&g_hashAddrList[key].list);
	while(node != NULL){
		if(node->addr == destip) {
			found = 1;
			break;
		}
		node = SIMPLEQ_NEXT(node,sentry);
	}

	pthread_rwlock_rdlock(&g_hashAddrList[key].lock);
	return found;

}


void* whilteItem_loop_sync(void * arg){
	
	int len;
	char line[256];
	FILE * fp;
	arg = arg;

	
	while(1){
		fp = fopen(NEW_WHITE_ITEM, "rb");
		if (!fp) {
			usleep(2*60*1000*1000);
			continue;
		}
		do {
			len = wl_getline(fp, line, sizeof(line));
			if(len > 0 ){
				line[len] = 0;
			}
			else {
				break;
			}
			whiteItem_add(line, len);
			whiteItem_add_cfg(line);
		}while(1);
		fclose(fp);

		//
		unlink(NEW_WHITE_ITEM);
		usleep(2*60*1000*1000);
	}

}


int whiteItem_init(){
	int index;
	g_hashList = malloc(sizeof(struct whiteHash_t*)*WHITE_HASH_LEN);
	if(!g_hashList){
		return -1;
	}
	for(index=0; index<WHITE_HASH_LEN; index++){
		SIMPLEQ_INIT(&g_hashList[index].list);
		pthread_rwlock_init(&g_hashList[index].lock, 0);
	}

	whiteItem_load();

	g_hashAddrList = malloc(sizeof(struct whiteAddr_s*)*WHITE_HASH_ADDR_LEN);
	if(!g_hashAddrList){
		return -1;
	}
	for(index=0; index<WHITE_HASH_LEN; index++){
		SIMPLEQ_INIT(&g_hashAddrList[index].list);
		pthread_rwlock_init(&g_hashAddrList[index].lock, 0);
	}

	whiteItem_load();
	whiteItem_load_addr();
	return 1;
}

int whiteItem_start(){
	int ret;
		
	pthread_t pid1;
	pthread_attr_t attr1;

	

	pthread_attr_init(&attr1);
	pthread_attr_setscope(&attr1, PTHREAD_SCOPE_PROCESS);
	pthread_attr_setdetachstate(&attr1, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&pid1, &attr1, whilteItem_loop_sync, NULL);
	if(ret < 0){
		return -1;
	}
	pthread_attr_destroy(&attr1);
	return 1;
}

