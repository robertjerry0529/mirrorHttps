
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h> 

#include "common.h"
#include "https_parse.h"
/*解析https client_hello,提取host字段
 返回值:
 1: client_hello头没有收完整
 2: 解析完成,提取成功
 -1: 非法client_hello
 -2: client_hello头长度超过1500字节
  -3: client_hello中没有找到host字段
  -4 : host长度太长
*/
int https_host_parse(char *data, int len, char * host, int hlen){
	https_client_hello_t  *client_hello;
	https_msg_header_t  *msgHeader;
	handshake_protocol_t *handshake, hskake;
	https_extension_t  * extens, hextens;
	char * pos;
	int totalLen = 0;
	int left;
	if(len < 5 /*sizeof(https_msg_header_t)*/){
		return HTTPS_CLIENT_HELLO_PART;
	}

	msgHeader = (https_msg_header_t*)data;
	
	if(msgHeader->Content_type != 22){
		return HTTPS_CLIENT_HELLO_INVALID;
	}

	//printf("tls version:%d.%d\n",msgHeader->major_version,msgHeader->minor_version);

	totalLen = (msgHeader->length_hi << 8);
	totalLen += msgHeader->length_low;
	
	if(totalLen > 1500){
		//数据头太长
		return HTTPS_CLIENT_HELLO_OVERRUN;
	}

	if(totalLen < (int)(len - 5 /*sizeof(https_msg_header_t)*/)){
		return HTTPS_CLIENT_HELLO_PART;
	}

	pos = (char*)data + 5/*sizeof(https_msg_header_t)*/;

	handshake = &hskake;
	memset(handshake, 0x00, sizeof(hskake));
	handshake->type = *pos;
	
	//printf("handshake type=0x%x\n",  handshake->type );   
	pos ++;

	char * plen = (char*)&handshake->length;
	*plen++ = 0; 
	*plen++ = *pos++; 
	*plen++ = *pos++;
	*plen++ = *pos++;
	handshake->length = ntohl(handshake->length);
	//printf("handshake len = %d\n", (handshake->length));
	

	handshake->version = (*pos << 8); pos++;
	handshake->version |= *pos;  pos++;

	handshake->version = ntohs(handshake->version);
	//printf("handshake version = %d\n", (handshake->version));

	
	
	//printf("handshake random len:32\n");
	pos+=32;

	handshake->sessionId_len = *pos;
	//printf("handshake sessionId len:%d\n", handshake->sessionId_len);
	pos ++;
	//skip sessionId
	pos +=handshake->sessionId_len;
	
	plen  =  (char*)&handshake->cipher_suites_len;
	*plen++ = (*pos++);
	*plen++ = (*pos++);
	
	handshake->cipher_suites_len = ntohs(handshake->cipher_suites_len );
	//printf("handshake cipher suite len =%d\n", handshake->cipher_suites_len);
	pos += handshake->cipher_suites_len;

	handshake->compress_len = *pos;  
	//printf("handshake compress len = %d\n",handshake->compress_len );
	pos++;

	pos+= handshake->compress_len;

	plen =(char*) &handshake->extension_len;
	
	*plen++ = (*pos++);
	*plen++ = (*pos++);

	handshake->extension_len = ntohs(handshake->extension_len);
	
	left = totalLen - (pos - data);
	extens = &hextens;
	while(left > (int)sizeof(https_extension_t)){
		
		

		plen = (char*)&extens->stype ;
		
		*plen++ = (*pos++);
		*plen++ = (*pos++);
		extens->stype = ntohs(extens->stype);
		
		plen = (char*)& extens->slen ;
		
		*plen++ = (*pos++);
		*plen++ = (*pos++);
		extens->slen = ntohs(extens->slen);
		
		if(extens->stype == 0) {		
			// server name
			short namelistlen ;
			char name_type;
			short namelen;
			char * namepos;

			namepos = pos;
			plen = (char*)&namelistlen;
			*plen++ = *namepos++;
			*plen++ = *namepos++;
			namelistlen = ntohs(namelistlen);
			char * start = namepos;
			char * end = namepos + namelistlen;

			if(namelistlen+2 > extens->slen ) break;
			
			while(namepos +3 < end){
				name_type = *namepos++;
				plen = (char*)&namelen;
				*plen++ = *namepos++;
				*plen++ = *namepos++;
				namelen = ntohs(namelen);
				
				if(namelen + namepos > end ) break;
				
				if(name_type == 0){
					if(namelen > hlen){
						return HTTPS_CLIENT_HOST_TOO_LONG;
					}
					strncpy(host,namepos,namelen);
					host[namelen] = '\0';
					
					return HTTPS_CLIENT_HELLO_PARSE_OK;
				}
				else {
					namepos += namelen;
				}
			}
			return HTTPS_CLIENT_HELLO_NOHOST;
		}
		pos += extens->slen;
		left -= sizeof(https_extension_t) - extens->slen;
	}
	
	return HTTPS_CLIENT_HELLO_NOHOST;
}

