#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int dpdk_start();
int kni_start();
int netmap_start();
int ssl_ctx_start();
int whiteItem_start();
int booting = 0;
int is_booting(){
	return !booting ;
}

int module_kickoff(){
	int ret;

	ret = dpdk_start();
	if(ret < 0){
		printf("failed config start\n");
		exit(-1);
	}
	ret = kni_start();
	if(ret < 0){
		printf("failed config start\n");
		exit(-1);
	}
	ret = netmap_start();
	if(ret < 0){
		printf("failed config start\n");
		exit(-1);
	}

	whiteItem_start();

	booting  = 0;
	//set_boot_end();
	usleep(60*000*1000);
	
	
	return 1;
}
