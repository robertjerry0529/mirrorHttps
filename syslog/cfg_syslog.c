#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <arpa/inet.h>



#include "common.h"
//#include  "debug.h"
#include "mng.h"
#include "plat_log.h"
/*
[delete|show]  syslog timestamp
[delete|show]  syslog enable
[clear] syslog 
syslog level [0-7]
*/

extern  struct syslog_cfg_t syslog_cfg;
extern  struct syslog_show_ctrl  syslog_show;
int syslog_usage()
{
	
	pri_mng_output( "[delete|show] syslog enable\n");
	pri_mng_output("[delete|show] syslog timestamp\n");
	pri_mng_output("clear syslog\n");
	pri_mng_output("syslog level <0-7>\n");
	pri_mng_output("syslog file {enable|disable}\n");
	pri_mng_output("syslog hostname enable\n");
	pri_mng_output("show syslog buffer <number> \t number:0-512\n");
	pri_mng_output("syslog server <ip> <port> level <level>  \t  support 2 items\n");
	pri_mng_output("syslog facility <number> \t  default:20\n");
	
	return CMD_ERROR;

}

int syslog_cfg_host(char * sip, char *sport, char * level, int type){
	in_addr_t  ip;
	int index;
	int idle;
	int port;
	int ilevel;
	ip = inet_addr(sip);
	if(ip == 0xffffffff || ip == 0 ){
		pri_mng_output("host ip in invalid:%s\n", sip);
		return CMD_NO_USAGE_ERROR;
	}
	if( level[0] >= '0' && level[0]<='7' ){
		ilevel = atol(level);
	} else {
		ilevel =  syslog_string2level(level);
	}
	
	if(ilevel > 7 || ilevel < 0){
		pri_mng_output("Error: syslog level is between 0~7\n");
		return CMD_ERROR;
	}
		

	idle = -1;
	port = atol(sport);
	if(port <= 0 || port >= 65535){
		pri_mng_output("port in invalid, must in range 0-65535\n");
		return CMD_NO_USAGE_ERROR;
	}
	for(index = 0; index < MAX_SYSLOG_SERVER_COUNT; index++){
		if(syslog_cfg.hosts[index].hostip[0] == 0 && idle == -1) {
			idle = index;
		}
		if(strcmp(syslog_cfg.hosts[index].hostip,sip)  == 0
			&& syslog_cfg.hosts[index].port == port ){
			if(type == CLI_DELETE){
				syslog_cfg.hosts[index].hostip[0] = 0;
				syslog_cfg.hosts[index].port = 0;
				syslog_cfg.hosts[index].level = -1;
				plat_syslog_server_del(index);
			}else {
				syslog_cfg.hosts[index].level = ilevel;
			}
			return CMD_SUCCESS;
		}
	}
	if(type == CLI_DELETE) return CMD_SUCCESS;
	if(idle == -1){
		pri_mng_output("max syslog server number is %d\n",MAX_SYSLOG_SERVER_COUNT );
		return CMD_NO_USAGE_ERROR;
	}
	memset(syslog_cfg.hosts[idle].hostip, 0x00, sizeof(syslog_cfg.hosts[idle].hostip));
	strncpy(syslog_cfg.hosts[idle].hostip, sip, sizeof(syslog_cfg.hosts[idle].hostip)-1);
	syslog_cfg.hosts[idle].port = port;
	syslog_cfg.hosts[idle].level = ilevel;
	plat_syslog_server_add(idle, sip, port, ilevel);
	return CMD_SUCCESS;
}
int cli_syslog(int argc, char * argv[],  int type)
{
	FILE * fp;
	int level;
	int index;
	
	fp = global_ofd_get();
	if(type == CLI_DOCFG )
	{
		fprintf(fp, "%ssyslog enable\n", syslog_cfg.enable?"":"delete ");
		
		fprintf(fp, "syslog level %s\n", syslog_severity_string(syslog_cfg.level));
		if(syslog_cfg.hostname){
			fprintf(fp, "syslog hostname enable\n");
		}
		if(syslog_cfg.timestamp){
			fprintf(fp, "syslog timestamp enable\n");
		}
		if(syslog_cfg.syslog2file){
			fprintf(fp, "syslog file enable\n");
		}
		else {
			fprintf(fp, "syslog file disable\n");
		}
		if(syslog_cfg.facility != DEFAULT_SYSLOG_FACILITY){
			fprintf(fp, "syslog facility %d\n", syslog_cfg.facility );
		}
		for(index = 0; index<MAX_SYSLOG_SERVER_COUNT; index++){
			if(syslog_cfg.hosts[index].hostip[0]) {
				fprintf(fp,"syslog server %s %d level %d\n", syslog_cfg.hosts[index].hostip,
					syslog_cfg.hosts[index].port, syslog_cfg.hosts[index].level);
			}
		}
		return CMD_SUCCESS;
	}
	else if(type == CLI_SHOW){
		if(argc <= 1){
			pri_mng_output("%ssyslog enable\n", syslog_cfg.enable?"":"delete ");
			
			pri_mng_output("syslog level %s\n", syslog_severity_string(syslog_cfg.level));
			if(syslog_cfg.hostname){
				pri_mng_output("syslog hostname enable\n");
			}
			if(syslog_cfg.timestamp){
				pri_mng_output("syslog timestamp enable\n");
			}

			if(syslog_cfg.syslog2file){
				pri_mng_output("syslog file enable\n");
			}
			else {
				pri_mng_output("syslog file disable\n");
			}
			if(syslog_cfg.facility != DEFAULT_SYSLOG_FACILITY){
				pri_mng_output("syslog facility %d\n", syslog_cfg.facility );
			}
			for(index = 0; index<MAX_SYSLOG_SERVER_COUNT; index++){
				if(syslog_cfg.hosts[index].hostip[0]) {
					pri_mng_output("syslog server %s %d level %d\n", syslog_cfg.hosts[index].hostip,
						syslog_cfg.hosts[index].port,syslog_cfg.hosts[index].level);
				}
			}
			return CMD_SUCCESS;
		}
		else if(argc >= 2 && strcmp(argv[1], "buffer") == 0 ){
			int num = 0;
			if(argc == 3 ) {
				num = atol(argv[2]);
				if(num > 512) num = 512;
			}
			
			if(num > 0){
				syslog_show.ctrl = 1;
				syslog_show.count = 0;
				syslog_show.limit = num;
			}
			else {
				syslog_show.ctrl = 0;
				syslog_show.count = 0;
				syslog_show.limit = 0;
			}
			
		}
		return CMD_SUCCESS;
	}

	
	if(type == CLI_CLEAR)
	{
		if(argc == 1) {
			syslog_cfg.enable = 1;
			syslog_cfg.level = LOG_INFO;
			syslog_cfg.hostname = 0;
			syslog_cfg.syslog2file = 1;
			syslog_cfg.facility = DEFAULT_SYSLOG_FACILITY;
			memset(&syslog_cfg.hosts, 0x00, sizeof(syslog_cfg.hosts));
			return CMD_SUCCESS;
		}
				
		return CMD_SUCCESS;
	}



	if(type == CLI_CMD || type == CLI_DELELE)
	{
		if(argc<2) {
			return syslog_usage();
		}
		
		else if(!strcmp(argv[1], "enable"))
		{
			if(type == CLI_DELELE)
				syslog_cfg.enable = 0;
			else 
				syslog_cfg.enable = 1;
			return CMD_SUCCESS;
		}
		else if(!strcmp(argv[1], "level")){
			if(argc != 3) return syslog_usage();
			level =  syslog_string2level(argv[2]);
			if(0<= level && level<=7)
				syslog_cfg.level =level;
			else {
				pri_mng_output("Error: syslog level is between 0~7\n");
				return CMD_ERROR;
			}
				
			return CMD_SUCCESS;
		}
		else if(argc==3 && !strcmp(argv[1], "hostname") && 
			!strcmp(argv[2], "enable")){
			if(type == CLI_CMD){
				syslog_cfg.hostname = 1;
			}
			else {
				syslog_cfg.hostname = 0;
			}
			return CMD_SUCCESS;
		}
		else if(argc==3 && !strcmp(argv[1], "timestamp") && 
			!strcmp(argv[2], "enable")){
			if(type == CLI_CMD){
				syslog_cfg.timestamp = 1;
			}
			else {
				syslog_cfg.timestamp = 0;
			}
			return CMD_SUCCESS;
		}
		else if(argc ==3 && !strcmp(argv[1], "file") ){
			if(!strcmp(argv[2], "enable")){
				syslog_cfg.syslog2file = 1;
			}
			else if(!strcmp(argv[2], "disable")){
				syslog_cfg.syslog2file = 0;
			}
			return CMD_SUCCESS;
		}
		else if(argc == 3 && !strcmp(argv[1],"facility" )){
			if(type == CLI_CMD){
				int fac = atol(argv[2]);
				if(fac < MIN_FACILITY || fac > MAX_FACILITY){
					pri_mng_output("Error: facility range is %d-%d\n",MIN_FACILITY,
						MAX_FACILITY);
					return CMD_NO_USAGE_ERROR;
				}
				syslog_cfg.facility = fac;
			} else {
				syslog_cfg.facility = DEFAULT_SYSLOG_FACILITY;
				
			}

			return CMD_SUCCESS;
		}
		//syslog server <ip> <port> level <level> 
		else if(argc == 6 && strcmp(argv[1], "server") ==0 &&
			strcmp(argv[4], "level") == 0){
			
			int ret = syslog_cfg_host(argv[2], argv[3],argv[5], type);
			return  ret;
		}
	}

	
	return CMD_ERROR;
		
}




