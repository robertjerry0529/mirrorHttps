
#include <sys/types.h>
#include <openssl/sha.h>


#include "common.h"

int data_hash(unsigned char * data, unsigned char *hash, int len){
	
	SHA_CTX c;
	int offset = 0;  

	if(len == 0) return 0;
	
	SHA1_Init(&c);
	

	for(offset = 0; (offset + 16) <= len; offset += 16){	
		SHA1_Update(&c,data+offset,16);
	}
	
	
	if(len > offset ){
		SHA1_Update(&c,data+offset,len-offset);
	}
	SHA1_Final(hash,&c);
	return 1;
}



