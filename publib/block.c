#include <stdlib.h>
#include <string.h>

void ipservice_block_free(void * bp){
	free(bp);
	
}



void * ipservice_block_alloc(int size, void * * data, int * len)
{
     void * bp;
	 
	 bp = malloc(size);
	 
	 if(bp){
			*data = bp;
			*len = size;
	 }

    return (void *)bp;
}
