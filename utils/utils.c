#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h> 

#include "common.h"
#include "utils.h"




char * ip_string(in_addr_t nip, char * string, int len)
{
	in_addr_t ip;
	ip = (in_addr_t)ntohl(nip);
	snprintf(string, len , ("%d.%d.%d.%d"), 
		(ip&0xff000000)>>24,
		(ip&0x00ff0000)>>16,
		(ip&0x0000ff00)>>8,
		(ip&0x000000ff));
	return string;
}

char * domain_trim_short(char * wdomain, char *sdomain){
	char * pre = NULL;
	char * last = NULL;
	char * pos;

	pos = wdomain;

	while(*pos){
		if(*pos == '.'){
			pre = last;
			last = pos;
		}
		pos++;
	}

	if(pre){
		pre++;
		strcpy(sdomain, pre);
	}
	else {
		strcpy(sdomain, wdomain);

	}

	return sdomain;
}


//extern sys_timestamp _clock;	
unsigned long
clock_get_millisecs (void)
{
	ulong ret;
	struct timespec time1 = {0};
	clock_gettime(CLOCK_MONOTONIC, &time1);
	ret = time1.tv_sec * 1000+time1.tv_nsec/(1000*1000);
	return ret;
}

