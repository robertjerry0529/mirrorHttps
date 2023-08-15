#ifndef TIME_WHEEL_HEAD
#define TIME_WHEEL_HEAD


#define MAX_TIME_WHEEL_LEN 30*60*1000
#define WALK_STEP  10

// 定时器节点结构体
typedef struct TimerNode {
    int slot;                  // 定时器所在槽的位置
    int (*func)(void *, unsigned int arg1);      // 定时器回调函数
    void *arg;                 // 回调函数参数
    struct TimerNode *next;    // 下一个定时器节点指针
    struct TimerNode *prev;    // 下一个定时器节点指针
} TimerNode;

typedef struct TimerNodeList {
	struct TimerNode  * head;
	struct TimerNode *  tail;
	pthread_mutex_t lock;
	int count;
}TimerNodeList;


// 时间轮结构体
typedef struct TimeWheel {
	unsigned long last_check_ms;
	int conwait;
    int wheel_power;         // 时间轮的级数
    int wheel_size;          // 时间轮槽的数量
    int interval_sec;        // 时间轮的单位时间长度（秒）
    int current_slot;        // 当前时间轮的槽位置
    TimerNodeList **slots;       // 时间轮的槽数组指针
} TimeWheel;


void TimeWheelTick(TimeWheel *tw);

int DeleteTimerNode(TimeWheel *tw, TimerNode *node, int locked) ;

int InsertTimerNode(TimeWheel *tw, TimerNode *node, int expire_sec);
TimeWheel *tw_create();








#endif
