#ifndef TIME_WHEEL_HEAD
#define TIME_WHEEL_HEAD


#define MAX_TIME_WHEEL_LEN 30*60*1000
#define WALK_STEP  10

// ��ʱ���ڵ�ṹ��
typedef struct TimerNode {
    int slot;                  // ��ʱ�����ڲ۵�λ��
    int (*func)(void *, unsigned int arg1);      // ��ʱ���ص�����
    void *arg;                 // �ص���������
    struct TimerNode *next;    // ��һ����ʱ���ڵ�ָ��
    struct TimerNode *prev;    // ��һ����ʱ���ڵ�ָ��
} TimerNode;

typedef struct TimerNodeList {
	struct TimerNode  * head;
	struct TimerNode *  tail;
	pthread_mutex_t lock;
	int count;
}TimerNodeList;


// ʱ���ֽṹ��
typedef struct TimeWheel {
	unsigned long last_check_ms;
	int conwait;
    int wheel_power;         // ʱ���ֵļ���
    int wheel_size;          // ʱ���ֲ۵�����
    int interval_sec;        // ʱ���ֵĵ�λʱ�䳤�ȣ��룩
    int current_slot;        // ��ǰʱ���ֵĲ�λ��
    TimerNodeList **slots;       // ʱ���ֵĲ�����ָ��
} TimeWheel;


void TimeWheelTick(TimeWheel *tw);

int DeleteTimerNode(TimeWheel *tw, TimerNode *node, int locked) ;

int InsertTimerNode(TimeWheel *tw, TimerNode *node, int expire_sec);
TimeWheel *tw_create();








#endif
