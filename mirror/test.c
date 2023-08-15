#include <stdio.h>
#include <string.h>
#include "pktout.h"



int main(int argc, char * argv []){
	char data[] = {"ABCDEDF!!!!!!!!!!!!!!!!!!!!!!456"};
	int nindex = 0;
	mirror_cfg_set("ens33","00:0c:29:2f:bf:aa", "ens33", "00:0c:29:2f:bb:f6");
	mirror_start();
	//char * data, int len, int dir,
	for(nindex = 0; nindex< 4; nindex++){
		//char* sip, unsigned short sport, char * dip, unsigned short dport
		mirror_pkt_send(data, strlen(data),0, "192.168.75.1",8888, "10.100.2.2", 5543);
		mirror_pkt_send(data, strlen(data),1, "10.100.2.2",5543, "192.168.75.1", 8888);
	}
	return 1;
}

