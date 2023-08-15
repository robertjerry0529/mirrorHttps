#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <stdlib.h>

int netmap_init();
int kni_init(void);
int netmap_signal_init();

int conn_init();
int ssl_base_init()  ;
int wv_proxy_init();
int syslog_init();


int debug_boot;
void check_boot_debug(){
	FILE * fp;
	fp = fopen("_debug.dat", "rb");
	if(!fp) return ;
	fclose(fp);
	
	debug_boot = 1;
	while(debug_boot){

		usleep(1000000);
	}

	

}


int module_uninit(/*int sig, int type, int *reglist*/){
	
	return 1;
}

void sys_sighandler(int sg ){
	printf("recv signal 0x%x\n", sg);
	//plat_log(LOG_INFO,LOGTYPE_RUNNING,SYSLOG_system_signal_handler, "recv signal 0x%x, exit now\n", sg);
	module_uninit();
	exit(-1);
}



int module_init() {
	
	check_boot_debug();
	syslog_init();
	netmap_init();
	kni_init();
	netmap_signal_init();
	conn_init();
	whiteItem_init();
	
	
	return 1;
}





