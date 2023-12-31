
#include <stdio.h>
#include <unistd.h>
#include "common.h"
#include "init.h"

extern char * __version ;

#define DEBUG_SERIAL_CTRL "duart.debug"
#define DEBUG_FILE "debug_flag"
int g_wait_for_debug = 0;



void wait_for_debug(){
	int count;
	FILE * fp;
	fp = fopen(DEBUG_FILE, "rb");
	if(!fp){
		
		return ;
	}
	else {
		
		fclose(fp);
		g_wait_for_debug = 1;
		printf("Wait for debug, pid=%d, set g_wait_for_debug=0 to continue\n",getpid());
		while(count++ < 90 && g_wait_for_debug == 1){
			usleep(1000000);
		}
	}
}

int main(int argc, char * argv[])
{
	int ret;
	argc = argc ;
	argv = argv;

	wait_for_debug();


	module_init();

	module_kickoff();
	
	
	//never returun;
	while(1){
		usleep(10000);
	}
	return 1;
}
