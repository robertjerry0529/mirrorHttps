#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include <assert.h>
#include <pthread.h>
#include "timewheel.h"




TimeWheel *tw_create(){
	TimeWheel	 * g_twheel;
	TimerNodeList * list;
	int slotsize ;
	int index;
	
	g_twheel = malloc(sizeof(TimeWheel));
	if(g_twheel == NULL) return NULL;

	slotsize = MAX_TIME_WHEEL_LEN/WALK_STEP;
	list = malloc(slotsize *sizeof(TimerNodeList));
	if (!list)  {
		free(g_twheel);
		return NULL;
	}
	
	memset(list, 0x00, sizeof(slotsize *sizeof(TimerNodeList)));


	g_twheel->slots = malloc(slotsize * sizeof(TimerNodeList*));
	if(!g_twheel){
		free(list);
		free(g_twheel);
		return NULL;
	}
	
	for(index = 0; index < slotsize; index++){
		g_twheel->slots[index] = &list[index];
		pthread_mutex_init(&list[index].lock, 0);
	}
	g_twheel->current_slot = 0;
	g_twheel->interval_sec = WALK_STEP;
	g_twheel->wheel_power = 1;
	g_twheel->interval_sec = 10;
	g_twheel->wheel_size = slotsize;
	return g_twheel;
}

int InsertTimerNode(TimeWheel *tw, TimerNode *node, int expire_sec) {
   
	
	if (expire_sec < 0) return -1;
	
	
	tw->conwait = 1;
	int idx = (tw->current_slot + expire_sec / tw->interval_sec) % tw->wheel_size;
	TimerNodeList *list = tw->slots[idx];

	pthread_mutex_lock(&list->lock);

    
    node->slot = idx;

	node->prev = node->next = NULL;
   
    if(list->head == NULL){
		list->head = node;
		assert(list->tail == NULL);
		list->tail = node;
		list->count = 0;
		pthread_mutex_unlock(&list->lock);
		return 1;
    }

	
	node->prev = list->tail;
	list->tail->next = node;
	list->tail = node;
	
	list->count ++;
	tw->conwait = 0;
	pthread_mutex_unlock(&list->lock);
    return 0;
}

int DeleteTimerNode(TimeWheel *tw, TimerNode *node, int locked) {
    int idx = node->slot;
    TimerNodeList *list = tw->slots[idx];
	if(locked == 0){
		tw->conwait = 1;
		pthread_mutex_lock(&list->lock);
	} 
		
	
	if(node->next){
		node->next->prev = node->prev;
	}
	if(node->prev){
    	node->prev->next = node->next;
	}
	if(node==list->head) {
		list->head = node->next;
	}
	if(node == list->tail){
		list->tail = node->prev;
	}
	list->count--;
	if(locked == 0){
		tw->conwait = 0;
		pthread_mutex_unlock(&list->lock);
	}

    return 0;
}

void TimeWheelTick(TimeWheel *tw) {
	int tofree = 0;
	struct timeval tv;
    struct timezone tz;   
	unsigned long curtime;
	int ret;
	time_t now;
    gettimeofday(&tv, &tz);
	curtime = tv.tv_sec*1000+tv.tv_usec/1000;
	
	
	if(tw->last_check_ms + 10 > curtime)  return ;

	TimerNodeList *list = tw->slots[tw->current_slot];
    TimerNode *cur = list->head;
	ret = pthread_mutex_trylock(&list->lock);
	if(ret != 0) return ;

  
    TimerNode *prev = NULL;
	time(&now);
	
    while (cur) {
        if (cur->func) {
            tofree = cur->func(cur->arg, now);
        } else {
			tofree = 0;
        }
        prev = cur;
        cur = cur->next;
		if (tofree){
			DeleteTimerNode(tw,prev,1);
        	free(prev);
		}
		if(tw->conwait){
			tw->conwait = 0;
			pthread_mutex_unlock(&list->lock);
			return ;
		}
    }
	tw->current_slot = (tw->current_slot + 1) % tw->wheel_size;
	tw->last_check_ms = curtime;
		  
	pthread_mutex_unlock(&list->lock);
	return ;
    
}


