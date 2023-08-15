#ifndef PKTOUT_HEAD
#define PKTOUT_HEAD



int mirror_cfg_set(char * i_ifname, char * i_mac, char * o_ifname , char * o_mac);
int mirror_start();

int mirror_pkt_send(void * data, int len, int dir,
	char* sip, unsigned short sport, char * dip, unsigned short dport);
int mirror_connection_end(int dir,
	char* sip, unsigned short sport, char * dip, unsigned short dport);



#endif
