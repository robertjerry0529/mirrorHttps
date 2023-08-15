#ifndef IPUTILS_HEAD

#define IPUTILS_HEAD

unsigned short ip_chksum(unsigned short *p, int n);

unsigned short tcp_dosums(struct tcptype *tcp, in_addr_t faddr, in_addr_t laddr,	int len);

#endif 
