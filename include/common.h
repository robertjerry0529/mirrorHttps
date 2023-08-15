#ifndef COMMON_HEAD
#define COMMON_HEAD


#ifndef GNU
#define GNU
#endif





#define CERT_DIR   "cert"
#define CFG_CERT_DIR  "conf"


#define DOMAIN_LEN  64


typedef unsigned int in_addr_t;
typedef unsigned short in_port_t;


enum {
	mode_inline = 0,
	mode_bypass = 1,	
};




#endif
