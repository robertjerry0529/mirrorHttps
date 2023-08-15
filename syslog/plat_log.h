#ifndef PLAT_LOG_H
#define PLAT_LOG_H

#include "syslogid.h"

#define SYSLOG_SEVERITY_MASK 0x0007  /* 0000 0000 0000 0111 */
#define SYSLOG_FACILITY_MASK 0x03f8  /* 0000 0011 1111 1000 */
#define SYSLOG_MAX_DIGITS 3 /* The maximum number if priority digits to read in. */


#define LOG_EMERGENCY	0X00
#define LOG_ALERT		0X01
#define LOG_CRITICAL		0X02
#define LOG_ERROR			0X03
#define LOG_WARNING		0X04
#define LOG_NOTICE		0X05
#define LOG_INFO			0X06
#define LOG_DEBUG			0X07


#define MAX_FACILITY	23 
#define MIN_FACILITY	16 

#define DEFAULT_SYSLOG_FACILITY  20

#define MAX_SYSLOG_SERVER_COUNT  2
struct loghost_cfg{
	char hostip[32];
	int port;
	int level;
};

struct syslog_cfg_t
{
	int enable;
	int timestamp;
	int level;
	int maxhost_level;
	int hostname;
	int syslog2file;
	int facility;
	//char FacilityCode[];
	struct loghost_cfg  hosts[MAX_SYSLOG_SERVER_COUNT];
};

struct syslog_show_ctrl{
	int ctrl ;
	int count;
	int limit;
};
#define QL_OK  0
#define QL_ERR  -1

enum {
	LOGTYPE_RUNNING 	  =    0, //运行日志
	LOGTYPE_OPERATION 	  =    1,  //管理操作日志   
	LOGTYPE_ACCESS    	  =	   2,  //接入日志
	LOGTYPE_SECURITY 	  =    3,
	LOGTYPE_MAX = 4,
};


int syslog_ratelimit(int level,int facility, int id,char * fmt, va_list ap);
int syslog_init();
void syslog_exit();
int syslog_get(char * buf, int len);
int  syslogcfg_get(struct syslog_cfg_t * cfg);
const char *syslog_severity_string(int id);
int syslog_string2level(const char * str);
int plat_syslog_server_add(int index,char * ip, int port, int ilevel);
int plat_syslog_server_del(int index);



int plat_log(int level, int type,int syslogid,const char* ms, ...);

int plat_log_file(int level, int type,int syslogid, const char * fmt,...);



#endif
