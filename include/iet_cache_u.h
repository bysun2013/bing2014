/*
 * ietd_cache_u.h - ietd cache management program
 */

#ifndef _IET_CACHE_U_H
#define _IET_CACHE_U_H


#define  IET_CACHE_VERSION "Inspur"
#define  IETADM_NAMESPACE  "IET_ABSTRACT_NAMESPACE"


#define NETLINK_IET_CACHE			23
#define NETLINK_IETADM_CACHE		24


struct cache_module_info {
	char version[20];
};


enum ip_m {
	MA = 100,
	MB,
};

#define  CACHE_NAME_LEN      20

struct cache_machine_info {
	enum ip_m  who;
	char mach[CACHE_NAME_LEN];
};

struct cache_ip_info {
	u32 tid;
	enum ip_m  who;
	char addr[CACHE_NAME_LEN];
};

enum ietadm_cache_cmnd {
	CACHE_UPDATE,
	CACHE_RESPONSE,
};


struct ietadm_cache_req {
	char name[10];
	enum ietadm_cache_cmnd rcmnd;
	u8   response;
	u32 lun;

};

#define MAX_MSG_LEN    10
struct ctrl_msg_info {
	char msg[MAX_MSG_LEN];
};


#define CACHE_MODULE_GET  		_IOW('i', 20, struct cache_module_info)
#define CACHE_MACH_SET 	    	 _IOWR('i', 21, struct cache_machine_info)
#define CACHE_IP_SET 	   		 _IOWR('i', 22, struct cache_ip_info)
#define CACHE_LUN_UPD 	    	 	_IOWR('i', 24, struct ietadm_cache_req)
#define CTRL_MSG_SEND 	    	 _IOWR('i', 25, struct ctrl_msg_info)



#endif
