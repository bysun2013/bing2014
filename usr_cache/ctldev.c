/*
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "iet_cache.h"

#define CTL_DEVICE	"/dev/dcache_ctl"
#define CTL_DEVICE_NAME	"dcache_ctl"


extern int ctrl_fd_cache;

static int cache_ctrdev_open(void)
{
	FILE *f;
	char devname[256];
	char buf[256];
	int devn;
	int ctlfd;

	if (!(f = fopen("/proc/devices", "r"))) {
		log_error("cannot open control path to the driver: %m");
		return -1;
	}

	devn = 0;
	while (!feof(f)) {
		if (!fgets(buf, sizeof (buf), f)) {
			break;
		}
		if (sscanf(buf, "%d %s", &devn, devname) != 2) {
			continue;
		}
		if (!strcmp(devname, CTL_DEVICE_NAME)) {
			break;
		}
		devn = 0;
	}

	fclose(f);
	if (!devn) {
		log_error("cannot find %s in /proc/devices - make sure the kernel module is loaded", CTL_DEVICE_NAME);
		return -1;
	}

	unlink(CTL_DEVICE);
	if (mknod(CTL_DEVICE, (S_IFCHR | 0600), (devn << 8))) {
		log_error("cannot create %s: %m", CTL_DEVICE);
		return -1;
	}

	ctlfd = open(CTL_DEVICE, O_RDWR);
	if (ctlfd < 0) {
		log_error("cannot open %s: %m", CTL_DEVICE);
		return -1;
	}

	return ctlfd;
}

static int cache_module_info_get(struct cache_module_info *info)
{
	int err;
	
	err = ioctl(ctrl_fd_cache, CACHE_MODULE_GET, info);
	if (err < 0 && errno == EFAULT)
		log_error("error calling ioctl CACHE_MODULE_GET: %m");

	return (err < 0) ? -errno : 0;
}

static int cache_machine_init(u32 *tid, char *name, int type)
{
	struct cache_machine_info info;
	int err;
	
	memset(&info, 0, sizeof(info));

	snprintf(info.mach, sizeof(info.mach), "%s", name);
	log_error("error config machine type  %d\n",CACHE_MACH_SET);

	err = ioctl(ctrl_fd_cache, CACHE_MACH_SET, &info);
	if (err < 0 )
		log_error("error config machine type \n");

	return err;
}

static int cache_ip_check(char *name)
{
	return 0;
}

static int cache_ip_init(u32 *tid, char *name, int type)
{
	struct cache_ip_info info;
	int err;
	
	if (cache_ip_check(name)) {
		log_error("ip format unvalid  %s", name);
		return -EINVAL;
	}

	memset(&info, 0, sizeof(info));

	snprintf(info.addr, sizeof(info.addr), "%s", name);
	info.tid = *tid;
	info.who = type;

	err = ioctl(ctrl_fd_cache, CACHE_IP_SET, &info);
	if (err < 0 )
		log_error("error reading ip address \n");

	return err;
}

static int cache_update_lun(struct ietadm_cache_req *req)
{	
	struct ietadm_cache_req req1;
	int err;
	log_error("cache_update_lun req.rcmnd =%d  req.lun =%d  req.name=%s  req.response =%d \n",
		   req->rcmnd,req->lun,req->name,req->response);

	req1.rcmnd =req->rcmnd;
	req1.lun =req->lun;  
	strcpy(req1.name,req->name);
	req1.response =req->response; 
	err = ioctl(ctrl_fd_cache, CACHE_LUN_UPD, &req1);
	if (err < 0 )
		log_error("error update cache lun \n");

	req->rcmnd = req1.rcmnd;
	req->lun = req1.lun;  
	strcpy(req->name,req1.name);
	req->response = req1.response; 

	return err;
}

struct cache_kernel_interface cache_ioctl_ki = {
	.ctldev_open = cache_ctrdev_open,
	.module_info = cache_module_info_get,
	.machine_init= cache_machine_init,
       .ip_init  = cache_ip_init,
	.cache_update = cache_update_lun,

};

struct cache_kernel_interface *cache_ki = &cache_ioctl_ki;

