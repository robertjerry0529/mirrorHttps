#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h> 
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <semaphore.h>
#include <arpa/inet.h>
#include <netinet/in.h> 

#include "common.h"
#include "plat_log.h"
#include "kfifo.h"
#include "utils.h"

#define pri_mng_output  printf 

const char *logname[LOGTYPE_MAX] = {
	"running",
	"operation",
	"access",
	"security"
	};

static const char *FacilityCode = "WETRUST";

#define SYSLOG_FAC(f)   ((f)<<3)


#define SYSLOG_BUFFER_COUNT  8192
#define MAX_SYSLOG_BUFFER_LEN 256


struct syslog_msg_t 
{
	
	unsigned char  level;
	unsigned char  type;
	unsigned char  blen;
	unsigned char  reserved;
	unsigned int syslogid;
};

struct syslog_severity_t {
	int level;
	const char * name;
};

struct syslog_facility_t {
	int level;
	const char * name;
};


struct syslog_buf_list{
	struct syslog_buf_list * next;
	struct syslog_msg_t  sysh;
	char buffer[MAX_SYSLOG_BUFFER_LEN];    //最长不超过256
};


struct syslog_server_conn{
	int sock;
	int proto;
	int state;
	int level;
	in_addr_t hostip;
	int port;
};

static int global_msg_count = 0;
static	pthread_mutex_t loglock;

struct syslog_cfg_t syslog_cfg ;
struct syslog_show_ctrl  syslog_show = {0,0,0};
struct syslog_buf_list * logbuf_freelist, *logbuf;

static	pthread_mutex_t log_msg_lock;
struct syslog_buf_list * logmsg_head, *logmsg_tail;

 sem_t log_t_signal_object;


static const struct syslog_severity_t syslog_severity_values[] = { 
	{ 0,      "emergency" },  
	{ 1,      "alert" },  
	{ 2,      "critical" },  
	{ 3,      "error" },  
	{ 4,      "warning" },  
	{ 5,      "notice" },  
	{ 6,      "info" },  
	{ 7,      "debug" },  
	{ 0, NULL },
};

static const struct  syslog_facility_t  syslog_facility_values[] = {  
	{ 0,     "kernel" },  
	{ 1,     "user" },  
	{ 2,     "mail" },  
	{ 3,     "daemon" }, 
	{ 4,     "auth" }, 
	{ 5,     "syslog" }, 
	{ 6,     "lpr" },  
	{ 7,     "news" }, 
	{ 8,     "uucp" }, 
	{ 9,     "cron" },  
	{ 10,    "authpriv" },  
	{ 11,    "ftp" }, 
	{ 12,    "ntp" },  
	{ 13,    "security" }, 
	{ 14,    "console" }, 
	{ 15,    "cron" },  

};


struct syslog_server_conn logserver_conn[MAX_SYSLOG_SERVER_COUNT];

int syslog_flush(int count);
int syslog_write(int level, int type, int syslogid,char * buffer, int len);

int plat_log_console(int type, int level, char * wzLog);
int plat_log_inner(int type,const char* wzLog, int len);
extern int is_booting	();

int plat_syslog_server_add(int index,char * ip, int port, int ilevel){
	logserver_conn[index].hostip = inet_addr(ip);
	logserver_conn[index].port = port;
	logserver_conn[index].proto = 0; //udp
	if(logserver_conn[index].sock == 0){
		logserver_conn[index].sock = socket(AF_INET,SOCK_DGRAM,0);
		if(logserver_conn[index].sock <= 0){
			logserver_conn[index].sock = 0;
			pri_mng_output("create syslog socket failed : %d\n", errno);
			return -1;
		}
	}
	logserver_conn[index].level = ilevel;
	logserver_conn[index].state = 1; 
	
	if(syslog_cfg.maxhost_level < ilevel)  {
		syslog_cfg.maxhost_level = ilevel;
	}
	return 1;
}


int plat_syslog_server_del(int index){
	int ncount;
	int nlevel = -1;
	if(logserver_conn[index].sock ){
		close(logserver_conn[index].sock);
		logserver_conn[index].sock = 0;
	}
	memset(&logserver_conn[index], 0x00, sizeof(logserver_conn[index]));
	logserver_conn[index].level = -1;
	for(ncount < 0; ncount<MAX_SYSLOG_SERVER_COUNT; ncount++){
		if(logserver_conn[ncount].level > nlevel) {
			nlevel = logserver_conn[ncount].level ;
		}
	}

	syslog_cfg.maxhost_level = nlevel;
	
	return 1;
}


int log_t_signal_init(){
	sem_init(&log_t_signal_object,0, 0);
	return 1;
}

int  log_t_wait_signal(int timeout){

	struct timespec ts;
	int ret;

    ret = clock_gettime(CLOCK_REALTIME,&ts); //这里返回0秒，调用失败
    ts.tv_sec += timeout/1000;
    ts.tv_nsec += (timeout%1000)*1000;
    
    ret= sem_timedwait (&log_t_signal_object, &ts);

	return 1;
}

void log_t_post_signal_os(){
	sem_post(&log_t_signal_object);
}



void *plat_log_timer(void * arg){

	arg = arg;

	while(1){
		syslog_flush(0);
		log_t_wait_signal(5000000);
		usleep(500);
		
		

	}

}

int plat_log_timer_start(){
	
   int ret ;
	  
   pthread_t pid;
   pthread_attr_t attr;
   pthread_attr_init(&attr);
   pthread_attr_setscope(&attr, PTHREAD_SCOPE_PROCESS);
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
   ret = pthread_create(&pid, &attr, plat_log_timer, NULL);
 
   pthread_attr_destroy(&attr);
   return ret;

}
int syslog_init(){
	
	int index;
	
	pthread_mutex_init(&loglock, 0);
	pthread_mutex_init(&log_msg_lock, 0);

	memset(&syslog_cfg, 0x00, sizeof(syslog_cfg));
	syslog_cfg.enable = 1;
	syslog_cfg.level = LOG_INFO;
	syslog_cfg.timestamp = 1;
	syslog_cfg.syslog2file = 1;
	syslog_cfg.hostname = 0;
	syslog_cfg.facility = DEFAULT_SYSLOG_FACILITY;
	
	memset(&syslog_cfg.hosts, 0x00, sizeof(syslog_cfg.hosts));
	
	global_msg_count = 0;

	logmsg_head = logmsg_tail = NULL;
	logbuf = (struct syslog_buf_list*)malloc(sizeof(struct syslog_buf_list) * SYSLOG_BUFFER_COUNT);
	if(!logbuf) return -1;

	logbuf_freelist = NULL;
	for(index=0; index<SYSLOG_BUFFER_COUNT; index++){
		struct syslog_buf_list * tmp = &logbuf[index];
		tmp->next = logbuf_freelist;
		logbuf_freelist = tmp;
	}
	//kfifo_init(&plogfifo,fifobuf,sizeof(fifobuf));
	log_t_signal_init();

	plat_log_timer_start();
	return 1;
}


struct syslog_buf_list * syslog_buf_get(){
	struct syslog_buf_list *ret;
	
	pthread_mutex_lock(&loglock);
	if(logbuf_freelist == NULL) {
		pthread_mutex_unlock(&loglock);
		return NULL;
	}
	ret = logbuf_freelist;
	logbuf_freelist = ret->next;
	global_msg_count++;
	pthread_mutex_unlock(&loglock);
	return ret;
}


void syslog_buf_put(struct syslog_buf_list * node){
	pthread_mutex_lock(&loglock);
	
	node->next = logbuf_freelist;
	logbuf_freelist = node;
	global_msg_count--;
	pthread_mutex_unlock(&loglock);
	return;
}


//log cache list
struct syslog_buf_list * syslog_msg_get(){
	struct syslog_buf_list *ret;
	
	pthread_mutex_lock(&log_msg_lock);
	if(logmsg_head == NULL) {
		pthread_mutex_unlock(&log_msg_lock);
		return NULL;
	}
	ret = logmsg_head;
	logmsg_head = ret->next;
	if(logmsg_head == NULL) logmsg_tail = NULL;
	
	pthread_mutex_unlock(&log_msg_lock);
	return ret;
}


void syslog_msg_put(struct syslog_buf_list * node){
	node->next = NULL;
	pthread_mutex_lock(&log_msg_lock);
	if(logmsg_head == NULL) {
		logmsg_head = node;
		logmsg_tail = node;
	}
	else {
		logmsg_tail->next = node;
		logmsg_tail = node;

	}
	pthread_mutex_unlock(&log_msg_lock);
	return;
}


const char *syslog_severity_string(int id)
{
	if(id <0 || id>7)
		return "";
	return syslog_severity_values[id].name;
}

int syslog_string2level(const char * str)
{
	int i;
	for(i=0;syslog_severity_values[i].name;i++)
	{
		if(!strcmp(str, syslog_severity_values[i].name))
			return syslog_severity_values[i].level;
	}
	return 6; /*default is 6*/
}

int plat_log_file(int level, int type,int syslogid, const char * fmt,...){
	
    char wzLog[1024] = {0};  
    char buffer[1024] = {0};  
    char filename[128] = {0};
    char timesz [64] = {0};
    unsigned len  = 0;
    time_t now; 
    va_list args; 
 	char sdate[64];
    struct tm *local;  
    FILE * file;

	if(type >= LOGTYPE_MAX){
		
		return -1;
	}
	syslogid = syslogid;
	
    va_start(args, fmt);  
    vsnprintf(wzLog , sizeof(wzLog),fmt,args);  
    va_end(args);  
  
    time(&now);  
  
    local = localtime(&now);  
    snprintf(timesz,sizeof(timesz),"%04d%02d%02d %02d:%02d:%02d", local->tm_year+1900, 
    local->tm_mon+1,  
            local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);  
	
	snprintf(sdate, sizeof(sdate),"%04d%02d%02d",local->tm_year+1900, 
    		local->tm_mon+1,  local->tm_mday);
	
    len = snprintf(buffer,sizeof(buffer), "[%s]%s %s",syslog_severity_string(level),timesz, wzLog);  

	snprintf(filename, sizeof(filename),"../log/%s-%s.log",logname[type],sdate) ; 
	
    file = fopen(filename,"ab+");  
    if(file == NULL)
    {
        printf("%s %d plat dialog open file:%s failed, error:%d\n",__FILE__,__LINE__,filename,errno);
        return -1;
    }
   
    fwrite(buffer,1,len,file);  
    fclose(file);  
    return len;


}

const char *month_des[] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sept",
	"Oct",
	"Nov",
	"Dec"
};
char * syslog_format_time(char * timestr, int nlen, int hasyear){
	struct tm *local; 
	time_t now;
	char * argv[16];
	char tstr[128];
	int ncount;
	int day;
	time(&now);
	local = localtime(&now);  
	#if 1
    snprintf(tstr,sizeof(tstr),"%04d%02d%02d %02d:%02d:%02d", local->tm_year+1900, 
	local->tm_mon+1,  
			local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);
	if(hasyear){
		snprintf(timestr,nlen,"%s %02d %02d:%02d:%02d %d", month_des[local->tm_mon], local->tm_mday,
			local->tm_hour, local->tm_min, local->tm_sec,local->tm_year+1900);
	}else {
		snprintf(timestr,nlen,"%s %02d %02d:%02d:%02d", month_des[local->tm_mon], local->tm_mday,
			local->tm_hour, local->tm_min, local->tm_sec);
	}
	
	#else 
	//Thu Aug 23 14:55:02 2001
	//snprintf(tstr, sizeof(tstr), "%c", local);
	
	day = atol(argv[2]);
	ncount = split(tstr,argv,nlen);
	if(ncount < 5) return "";
	if(hasyear){
		snprintf(timestr,nlen,"%s %2d %s %s", argv[1], day, argv[3], argv[4]);
	}else {
		snprintf(timestr,nlen,"%s %2d %s", argv[1], day, argv[3]);
	}
	#endif
	return timestr;
}

int plat_log(int level, int type, int syslogid,const char * fmt,...)
{
	char buffer[512] = {0};
	char msg[1024];
	int len;
	char timestr[64] = {0};
	char * ptime;
	int tlen;
	
	
    	
	if((level & SYSLOG_SEVERITY_MASK) > LOG_DEBUG)
		return -1;

  
  	if(level > syslog_cfg.level && (level > syslog_cfg.maxhost_level && syslog_cfg.maxhost_level > 0) )
		return -1;
	

	va_list ap;
    va_start(ap, fmt);
	vsnprintf(msg,sizeof(msg), fmt, ap);
	va_end(ap);


	ptime = syslog_format_time(timestr,sizeof(timestr), syslog_cfg.timestamp);
	
	
	/*level:facility,time,string*/
	//<30>Oct 9 22:33:20 deviceid auditd[1787]: The audit daemon is exiting.
	
	len =snprintf(buffer, sizeof(buffer), "<%d>%s %s %d-%d:%s", 
		SYSLOG_FAC(syslog_cfg.facility)|level,
		timestr,
		FacilityCode, level, syslogid,msg
	);
	

	if(global_msg_count > SYSLOG_BUFFER_COUNT/2){
		syslog_flush(100);
	}
	
	syslog_write(level, type, syslogid,buffer, len);
	if(is_booting()){
		//启动异常时候，来不及调度就死掉，没有记录日志，所以需要实时记录
		syslog_flush(100);
	}
	log_t_post_signal_os();
	
    return 1;
}



int plat_log_server(int index,int type, char * buf, int buflen){
	int ret;
	type  = type;;
	struct sockaddr_in ser_addr; 
	 memset(&ser_addr, 0, sizeof(ser_addr));
     ser_addr.sin_family = AF_INET;
     ser_addr.sin_addr.s_addr = logserver_conn[index].hostip; //IP地址，需要进行网络序转换，INADDR_ANY：本地地址
     ser_addr.sin_port = htons(logserver_conn[index].port);  //端口号，需要网络序转换
	
	if(logserver_conn[index].sock <= 0) return -1;
	ret = sendto(logserver_conn[index].sock, buf, buflen, 0, (struct sockaddr *)&ser_addr, sizeof(ser_addr));
	return ret;
}

int syslog_flush(int count)
{
	struct syslog_buf_list * plog;
	int loop;
	int ret;
	int index;
	
	if(global_msg_count == 0)
		return -1;
	
	
	loop = 0;
	
	
	while(1)
	{
		if(count > 0 && loop++>count) break;
		
		plog = syslog_msg_get();
		if(!plog) break;

		if(plog->sysh.level <= syslog_cfg.level){
			if(syslog_show.ctrl && syslog_show.count < syslog_show.limit){
				plat_log_console(plog->sysh.type,plog->sysh.level,plog->buffer);
				syslog_show.count++;
				if(syslog_show.count>= syslog_show.limit){
					syslog_show.ctrl = 0;
					syslog_show.limit = 0;
					syslog_show.count = 0;
				}
			}
			
			if(syslog_cfg.syslog2file){
				ret = plat_log_inner(plog->sysh.type,plog->buffer, plog->sysh.blen);
			}
		
		}
		
		for(index=0; index<MAX_SYSLOG_SERVER_COUNT; index++){
			if(syslog_cfg.hosts[index].hostip[0] == 0) continue;
			if(plog->sysh.level <= syslog_cfg.hosts[index].level){
				plat_log_server(index,plog->sysh.type,plog->buffer, plog->sysh.blen);
			}
		}
		syslog_buf_put(plog);
	}
	
	return loop;
}

int syslog_write(int level, int type,int syslogid,char * buffer, int len)
{
	struct syslog_buf_list * pbuf;

	pbuf = syslog_buf_get();
	if(!pbuf) return -1;

	if(len >= MAX_SYSLOG_BUFFER_LEN-1) len = MAX_SYSLOG_BUFFER_LEN-1;
	buffer[len] = 0;
	if(buffer[len-1] != '\n') buffer[len-1] == '\n';
	
	pbuf->sysh.level = (unsigned char)level;
	pbuf->sysh.type =  (unsigned char)type;
	pbuf->sysh.blen =  (unsigned char)len;
	pbuf->sysh.syslogid = syslogid;
	memcpy(pbuf->buffer, buffer, len+1 );

	syslog_msg_put(pbuf);
	return 1;
}


void syslog_exit()
{
	syslog_flush(0);
	return ;
}



/*网络序列*/
int  syslogcfg_get(struct syslog_cfg_t * cfg)
{
	memcpy(cfg,&syslog_cfg, sizeof(struct syslog_cfg_t) );
	
	cfg->enable = htonl(syslog_cfg.enable);
	cfg->timestamp = htonl(syslog_cfg.timestamp);
	cfg->level = htonl(syslog_cfg.level);
	cfg->hostname = htonl(syslog_cfg.hostname);

	cfg->hosts[0].level = htonl(cfg->hosts[0].level);
	cfg->hosts[0].port = htonl(cfg->hosts[0].port);
	cfg->hosts[1].level = htonl(cfg->hosts[1].level);
	cfg->hosts[1].port = htonl(cfg->hosts[1].port);
	
	return 1;
}


 
unsigned long plat_file_size(const char *path)  
{  
    unsigned long filesize = 0;      
    struct stat statbuff;  
    
    if(stat(path, &statbuff) < 0){  
        return filesize;  
    }else{  
        filesize = statbuff.st_size;  
    }  
    return filesize;  
}  




int plat_log_console(int type, int level, char * wzLog){

   type = type;
   level = level;
   pri_mng_output("%s", wzLog);  
   return 1;
}
 
int plat_log_inner(int type,const char* wzLog, int len)
{
    char filename[128] = {0};
    char newfilename[128] = {0};
    unsigned long ulfilesize ;
    char timesz [64] = {0};
   
    time_t now; 
    va_list args; 
 	char sdate[64];
    struct tm *local;  
    FILE * file;

	if(type >= LOGTYPE_MAX){
		return -1;
	}

	
    
    time(&now);  
  
    local = localtime(&now);  
    snprintf(timesz,sizeof(timesz),"%04d%02d%02d %02d:%02d:%02d", local->tm_year+1900, 
    local->tm_mon+1,  
            local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);  
	
	snprintf(sdate, sizeof(sdate),"%04d%02d%02d",local->tm_year+1900, 
    		local->tm_mon+1,  local->tm_mday);
	
   

	snprintf(filename, sizeof(filename),"../log/%s-%s.log",logname[type],sdate) ; 
	
    file = fopen(filename,"ab+");  
    if(file == NULL)
    {
        printf("%s %d plat dialog open file %s failed error:%d\n",__FILE__,__LINE__,filename,errno);
        return -1;
    }
   
    fwrite(wzLog,1,len,file);  
    fclose(file);  
    return len;
}

