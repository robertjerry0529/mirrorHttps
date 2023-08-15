#ifndef HTTPS_PARSE_HEAD
#define HTTPS_PARSE_HEAD


#define HTTPS_CLIENT_HELLO_PARSE_OK  1
#define HTTPS_CLIENT_HELLO_PART  2
#define HTTPS_CLIENT_HELLO_INVALID -1
#define HTTPS_CLIENT_HELLO_OVERRUN -2
#define HTTPS_CLIENT_HELLO_NOHOST -3
#define HTTPS_CLIENT_HOST_TOO_LONG -4

typedef struct https_msg_header_t_{
	unsigned char Content_type;  //22
	unsigned char major_version;
	unsigned char minor_version;
	unsigned char length_hi;
	unsigned char length_low;
}https_msg_header_t;

typedef struct https_extension_t_{
	unsigned short stype;
	unsigned short slen;  //不包括头本身
	char data[];
}https_extension_t;

#define ARRAY_POS_TEMP 2   /*占位用，不保存具体数值*/

typedef struct handshake_protocol_t_{
	unsigned int length;
	unsigned int type;
	
	unsigned short version;
	unsigned char random[32];
	unsigned char sessionId_len;
	unsigned char sessionId[ARRAY_POS_TEMP];  //
	unsigned short cipher_suites_len;
	unsigned char cipher_suites[ARRAY_POS_TEMP];
	unsigned char compress_len;
	unsigned char compress[ARRAY_POS_TEMP];
	unsigned short extension_len;
	https_extension_t extens[];
}handshake_protocol_t;

typedef struct https_client_hello_t_{
	https_msg_header_t  header;
	handshake_protocol_t  handshake;
	
}https_client_hello_t;

int https_host_parse(char *data, int len, char * host, int hlen);


#endif
