/*

 */

 #include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>



#include "common.h"
#include "hashtab.h"

struct hashtab *hashtab_create(u32 (*hash_value)(struct hashtab *h, const void *key),
                               int (*keycmp)(struct hashtab *h, const void *key1, const void *key2),
                               u32 size)
{
	struct hashtab *p;
	u32 i;

	p = malloc(sizeof(*p));
	if (p == NULL)
		return p;
	memset(p, 0x00, sizeof(*p));
	p->size = size;
	p->nel = 0;
	p->hash_value = hash_value;
	p->keycmp = keycmp;

	p->lock = malloc(sizeof(*(p->lock)) * size);
	if(!p->lock){
		free(p);
		return NULL;
	}
	p->htable = malloc(sizeof(*(p->htable)) * size);
	if (p->htable == NULL) {
		free(p);
		free(p->lock);
		return NULL;
	}

	for (i = 0; i < size; i++){
		p->htable[i] = NULL;
		pthread_mutex_init(&p->lock[i], 0);
	}


	return p;
}

int hashtab_insert(struct hashtab *h, void *key, void *datum)
{
	u32 hvalue;
	struct hashtab_node *prev, *cur, *newnode;

	if (!h || h->nel == HASHTAB_MAX_NODES)
		return -EINVAL;

	hvalue = h->hash_value(h, key);
	prev = NULL;

	pthread_mutex_lock(&h->lock[hvalue]);
	cur = h->htable[hvalue];
	while (cur && h->keycmp(h, key, cur->key) != 0) {
		prev = cur;
		cur = cur->next;
	}

	if (cur ){
		pthread_mutex_unlock(&h->lock[hvalue]);
		return -EEXIST;
	}

	newnode = malloc(sizeof(*newnode));
	if (newnode == NULL){
		pthread_mutex_unlock(&h->lock[hvalue]);
		return -ENOMEM;
	}
	memset(newnode, 0x00, sizeof(*newnode));

	newnode->key = key;
	newnode->datum = datum;
	if (prev) {
		newnode->next = prev->next;
		prev->next = newnode;
	} else {
		newnode->next = h->htable[hvalue];
		h->htable[hvalue] = newnode;
	}

	h->nel++;
	pthread_mutex_unlock(&h->lock[hvalue]);
	return 0;
}

void *hashtab_search(struct hashtab *h, const void *key)
{
	u32 hvalue;
	struct hashtab_node *cur;

	if (!h)
		return NULL;

	hvalue = h->hash_value(h, key);

	pthread_mutex_lock(&h->lock[hvalue]);
	cur = h->htable[hvalue];
	while (cur != NULL && h->keycmp(h, key, cur->key) != 0)
		cur = cur->next;

	if (cur == NULL ){
		pthread_mutex_unlock(&h->lock[hvalue]);
		return NULL;

	}
	pthread_mutex_unlock(&h->lock[hvalue]);
	return cur->datum;
}

/*added by yaocs*/
void* hashtab_free(struct hashtab*h, const void * key)
{
	u32 hvalue;
	struct hashtab_node *cur, *pre;
	void * datam = NULL;	

	if (!h)
		return NULL;

	hvalue = h->hash_value(h, key);

	pthread_mutex_lock(&h->lock[hvalue]);
	cur = h->htable[hvalue];
	pre = NULL;
	while (cur != NULL && h->keycmp(h, key, cur->key) != 0){
		pre = cur;
		cur = cur->next;
	}
	if (cur == NULL){
		pthread_mutex_unlock(&h->lock[hvalue]);
		return NULL;
	}
	datam = cur->datum;
	
	if(NULL==pre)  {
		h->htable[hvalue] = cur->next;
		free(cur);
	}
	else {
		pre->next = cur->next;
		free(cur);
	}

    h->nel--;
	pthread_mutex_unlock(&h->lock[hvalue]);
	return datam;
}
/*end of yaocs added*/

void hashtab_destroy(struct hashtab *h)
{
	u32 i;
	struct hashtab_node *cur, *temp;

	if (!h)
		return;

	for (i = 0; i < h->size; i++) {
		cur = h->htable[i];
		while (cur != NULL) {
			temp = cur;
			cur = cur->next;
			free(temp);
		}
		h->htable[i] = NULL;
	}

	free(h->htable);
	h->htable = NULL;

	free(h->lock);
	h->lock = NULL;
	free(h);
}

int hashtab_map(struct hashtab *h,
		int (*apply)(void *k, void *d, void *args, int * del),
		void *args)
{
	u32 i;
	int ret;
	int deleted = 0;
	int us;
	struct hashtab_node *cur, *pnext, *prev;

	if (!h)
		return 0;

	for (i = 0; i < h->size; i++) {
		pnext = prev = NULL;
		pthread_mutex_lock(&h->lock[i]);
		cur = h->htable[i];
		us = 0;
		while (cur != NULL) {
			pnext = cur->next; //当在apply中删除节点时，需要同步删除hash表中的节点内存
			
			ret = apply(cur->key, cur->datum, args, &deleted);

			if(deleted){
				//该节点已经删除，需要同步删除hash节点
				if(prev) {
					prev->next = pnext;
					
				}
				else {
					h->htable[i] = pnext;	
				}
				free(cur);
				h->nel--;
				cur = pnext;
				if(us == 0 && deleted == 2) us = 1;
				
			}
			else {
		
				prev = cur;
				cur = pnext;
			}
			
		}
		pthread_mutex_unlock(&h->lock[i]);
		if(us == 1) usleep(200);
	}
	return 0;
}


void hashtab_stat(struct hashtab *h, struct hashtab_info *info)
{
	u32 i, chain_len, slots_used, max_chain_len;
	struct hashtab_node *cur;

	slots_used = 0;
	max_chain_len = 0;
	for (slots_used = max_chain_len = i = 0; i < h->size; i++) {
		pthread_mutex_lock(&h->lock[i]);
		cur = h->htable[i];
		if (cur) {
			slots_used++;
			chain_len = 0;
			while (cur) {
				chain_len++;
				cur = cur->next;
			}

			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
		pthread_mutex_unlock(&h->lock[i]);
	}

	info->slots_used = slots_used;
	info->max_chain_len = max_chain_len;
}

