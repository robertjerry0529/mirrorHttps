#ifndef BLOCK_HEAD
#define BLOCK_HEAD

void ipservice_block_free(void * bp);
void * ipservice_block_alloc(int size, void * * data, int * len);

#endif