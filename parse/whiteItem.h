#ifndef WHITEITEM_HEAD
#define WHITEITEM_HEAD

#define DOMAIN_LEN  64

#define WHITE_HASH_LEN  1024
#define WHITE_HASH_ADDR_LEN  4096


typedef SIMPLEQ_HEAD(whitelist,whiteItem_s)  white_item_list_t;

struct whiteItem_s{
	SIMPLEQ_ENTRY(whiteItem_s) sentry;
	char domain[DOMAIN_LEN];
};

struct whiteHash_t{
	white_item_list_t  list;
	pthread_rwlock_t lock;

};



typedef SIMPLEQ_HEAD(whiteAddrlist,whiteAddr_s)  white_item_addr_list_t;

struct whiteAddr_s{
	SIMPLEQ_ENTRY(whiteAddr_s) sentry;
	in_addr_t addr;
};

struct whiteAddrHash_t{
	white_item_addr_list_t  list;
	pthread_rwlock_t lock;

};


int whiteItem_init();
int whiteItem_start();
int whiteItem_check(char * domain);
int whiteItem_check_addr(in_addr_t destip);


#endif
