#include <sys/types.h>

#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <time.h>   
#include <unistd.h>

#include <sys/stat.h> 
#include <unistd.h> 
  
#include <stdio.h>

/*文件名中获取日期，将日期超过30天的删除
  文件中提取日期: 移除
  catalina.out文件大于每天改名
*/
void clear_tomcat_private_file(char * name){
	
	char * st;
	char * end;
	char date[32] = {0};
	char sdate[32] = {0};
	int lfdate;
	int ndate;
	time_t now;
	struct tm *local;  
	struct stat statbuf;
	time_t createTime;
	char fname[128];
	 /* 从文件中读取 */

	if(!name) return ;
	
	time(&now);  
	int slen = strlen(name);
	snprintf(fname,sizeof(fname),"/opt/wsvpn/tomcat/logs/%s",name);
	
	if(slen >4 && strcmp(name+slen-4, ".log") == 0){
		char newName[256];
	    local = localtime(&now);  
		snprintf(sdate, sizeof(sdate),"%04d-%02d-%02d",local->tm_year+1900, 
    		local->tm_mon+1,  local->tm_mday);
		snprintf(newName,sizeof(newName), "/opt/wsvpn/tomcat/logs/%s.%s.bak",name,sdate);
		rename(fname,newName);
		return ;
	}

	
  	if(stat(fname,&statbuf)==0){
		createTime = statbuf.st_ctime ;  //属性改变时间代替创建时间
  	}
	else {
		return ;
	}

	
	
	local = localtime(&now);  

	if(now - createTime > 31*24*3600) {
		
		
		unlink(fname);
	}
	return ;

}

/*文件名中获取日期，将日期超过30天的删除
  文件中提取日期: 移除
  catalina.out文件大于每天改名
*/
void clear_tomcat_file(char * name){
	
	char * st;
	char * end;
	char date[32] = {0};
	char sdate[32] = {0};
	int lfdate;
	int ndate;
	time_t now;
	struct tm *local;  
	struct stat statbuf;
	time_t createTime;
	char fname[128];
	 /* 从文件中读取 */

	if(!name) return ;
	
	time(&now);  
	snprintf(fname,sizeof(fname),"/opt/wsvpn/tomcat/logs/%s",name);

	if(strcmp(name, "catalina.out") == 0){
		char newName[256];
	    local = localtime(&now);  
		snprintf(sdate, sizeof(sdate),"%04d-%02d-%02d",local->tm_year+1900, 
    		local->tm_mon+1,  local->tm_mday);
		snprintf(newName,sizeof(newName), "/opt/wsvpn/tomcat/logs/catalina.%s.out",sdate);
		rename(fname,newName);
		return ;
	}
	
  	if(stat(fname,&statbuf)==0){
		createTime = statbuf.st_ctime ;  //属性改变时间代替创建时间
  	}
	else {
		return ;
	}

	
	
	local = localtime(&now);  

	if(now - createTime > 31*24*3600) {
		unlink(fname);
	}
	return ;

}

// name: running-20200519.log	
void clear_vpn_logfile(char * name){
	char * st;
	char * end;
	char date[32] = {0};
	char sdate[32] = {0};
	int lfdate;
	int ndate;
	time_t now;
	struct tm *local;  
	
	st = strchr(name, '-');
	if(!st){
		return ;
	}
	st++;
	if(!st) return ;
	
	end = strchr(name, '.');
	if(!end) {
		return ;
	}
	if(end - st > sizeof(date) -1) {
		return ;
	}

	
	memcpy(date, st,end-st);
	
	lfdate = atol(date);

	time(&now);  
    local = localtime(&now);  
	snprintf(sdate, sizeof(sdate),"%04d%02d%02d",local->tm_year+1900, 
    		local->tm_mon+1,  local->tm_mday);
	ndate = atol(sdate);
	//printf("file date:%d, now :%d\n", lfdate, ndate);
	if(ndate - lfdate > 200) {
		char fname[128];
		snprintf(fname,sizeof(fname),"/opt/wsvpn/app/log/%s",name);
		unlink(fname);
	}
	return ;
}


/*文件名中获取日期，将日期超过30天的删除
  文件中提取日期: 移除
  catalina.out文件大于每天改名
*/
void clear_var_log_file(char * name){
	
	char * st;
	char * end;
	char date[32] = {0};
	char sdate[32] = {0};
	int lfdate;
	int ndate;
	time_t now;
	struct tm *local;  
	struct stat statbuf;
	time_t createTime;
	char fname[128];
	ulong expire;
	
	 /* 从文件中读取 */

	if(!name) return ;
	
	time(&now);  


	snprintf(fname,sizeof(fname),"/var/log/%s",name);
  	if(stat(fname,&statbuf)==0){
		createTime = statbuf.st_ctime ;  //属性改变时间代替创建时间
  	}
	else {
		return ;
	}

	
	
	local = localtime(&now);  
	if(strncmp(name, "cas", 3) == 0 ){
		expire  = 31*24*3600;
	}
	else {
		expire = 180*30*3600;
	}
	if(now - createTime > expire) {
		
		unlink(fname);
	}
	return ;

}

int main(){

	DIR	  *dir;
	char name[128];
	struct	 dirent    *ptr;
	dir = opendir("/opt/wsvpn/app/log");
	int count;
	struct stat info;

	stat("/opt/wsvpn/app/log",&info);

	if(S_ISDIR(info.st_mode)){

	    printf("Start checkc log files...\n");
	}
	else {
		printf("log dir doen't not exist, exit now\n");
		return -1;
	}

	count = 0;
	while(1){
		if(count == 0){
			dir = opendir("/opt/wsvpn/app/log");
			if(!dir) {
				printf(" opendir for vpn app failed\n");
			}
			else {
				while((ptr = readdir(dir)) != NULL){
					snprintf(name,sizeof(name), ptr->d_name);
					clear_vpn_logfile(name);
				}
				closedir(dir);
			}
			

			dir = opendir("/opt/wsvpn/tomcat/logs");
			if(!dir) {
				printf("opendir for tomcat logs failed\n");
			}
			else {
				while((ptr = readdir(dir)) != NULL){
					snprintf(name,sizeof(name), ptr->d_name);
					clear_tomcat_file(name);
				}
				closedir(dir);
			}

			dir = opendir("/var/log");
			if(!dir) {
				printf("opendir for cas logs failed\n");
			}
			else {
				while((ptr = readdir(dir)) != NULL){
					snprintf(name,sizeof(name), ptr->d_name);
					clear_var_log_file(name);
				}
				closedir(dir);
			}
					

		}

		usleep(2*60*1000*1000);
		if(count ++ > 24*12) {
			count = 0;
		}
	}

	
	return 0;

}

