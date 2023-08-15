
#include "common.h"
#include "netmap_ip.h"
#include "iputils.h"



unsigned short ip_chksum(unsigned short *p, int n){
    unsigned int sum;

    for (sum = 0; n > 1; n -= 2)
	sum += *p++;
    if (n == 1)
	sum += (unsigned char)*p;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum & 0xFFFF;
}



unsigned short tcp_dosums(struct tcptype *tcp, in_addr_t faddr, in_addr_t laddr,
	int len){
	unsigned int sum;
   	unsigned short *p = (unsigned short *) tcp;
    
	tcp->checksum = 0;

	sum  = (faddr & 0xffff) + (faddr >> 16);
	sum += (laddr & 0xffff) + (laddr >> 16);
	sum += htons(TCP_PROT);
	sum += htons(len);

	/*
	 * a lot of TCP packets have only a header. Lets optimize for that
	 * case.
         */
	while (len >= 20) {
	       	sum += p[0];
		sum += p[1];
		sum += p[2];
		sum += p[3];
		sum += p[4];
		sum += p[5];
		sum += p[6];
		sum += p[7];
		sum += p[8];
		sum += p[9];
		len -= 20;
		p += 10;
	}
    
	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
    
	if (len == 1)
		sum += *(unsigned char *)p;

       	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return ~sum & 0xFFFF;
}

