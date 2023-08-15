#ifndef IFACE_HEAD
#define IFACE_HEAD

enum {
	eth_mirror ,
	eth_inject_inside ,
	//eth_inject_outside ,
	eth_role_max
};
	
typedef struct iface_cfg{
	int id;
	int type;

	char mac[6];
	
	int kni;  //kni id
	void *pkni;
	char kni_name[32];
	
}iface_cfg_t;



typedef struct iface_role_t{
	int port_id;
	int valid ;
	char mac[10];
}iface_role;

extern iface_cfg_t  g_iface_cfg[RTE_MAX_ETHPORTS];

#endif
