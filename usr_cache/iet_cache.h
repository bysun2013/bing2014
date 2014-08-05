/*
 * ietd_cache.h - ietd cache management program
 */

#ifndef _IET_CACHE_H
#define _IET_CACHE_H

#include "types.h"
#include <linux/netlink.h>
#include "iet_cache_u.h"


enum ietadm_cache_op {
	OP_NEW,
	OP_DELETE,
	OP_UPDATE,
	OP_SHOW,
};

enum {
	POLL_ADM,
	POLL_MAX,
};

struct config_operations {
	void (*init) (char *, int *);
	int (*update) (struct ietadm_cache_req *);
};

/* ctldev.c */
struct cache_kernel_interface {
	int (*ctldev_open) (void);
	int (*module_info) (struct cache_module_info *);
       int (*machine_init) (u32 *, char *, int);
       int (*ip_init) (u32 *, char *, int);
       int (*cache_update) (struct ietadm_cache_req *);	
	   
};

extern struct cache_kernel_interface *cache_ki;

/* event.c */
extern int nl_open_ietd(void);
extern int nl_read_ietd(int fd, void *data, int len);
extern int nl_write_ietd(int fd, void *data, int len);

/* log.c */
extern int log_daemon;
extern int log_level;

extern void log_init(void);
extern void log_warning(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void log_error(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void log_debug(int level, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

/* message.c */
extern void ietadm_cache_request_handle(int fd);



#endif
