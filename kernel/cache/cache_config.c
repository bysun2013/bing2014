/*
 * cache_config.c
 *
 * file operations for char device, used to pass parameters
 *
 * Copyright (C) 2014-2015 Gongchen Li <ligongchen@163.com>
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

 
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/inet.h>

#include "cache_def.h"
#include "cache_wb.h"
#include "cache_conn/cache_conn.h"
#include "iet_cache_u.h"

int machine_type;
char echo_host[PATH_LEN]="127.0.0.1";
char echo_peer[PATH_LEN]="127.0.0.1";
bool owner = true;

static DEFINE_MUTEX(ioctl_mutex);

static int get_module_info(unsigned long ptr)
{
	struct cache_module_info info;
	int err;

	snprintf(info.version, sizeof(info.version), "%s", IET_CACHE_VERSION);

	err = copy_to_user((void *) ptr, &info, sizeof(info));
	if (err)
		return -EFAULT;

	return 0;
}

static int machine_set(unsigned long ptr)
{
	struct cache_machine_info info;

	int err;

	err = copy_from_user(&info, (void *) ptr, sizeof(info));
	if (err)
		return -EFAULT;
	
	if(!strcmp(info.mach, "MA")) 
	{
		machine_type = MA;
		cache_info("our machine is  MA\n");
	}
	else if(!strcmp(info.mach, "MB")) 
	{
		machine_type = MB;
		cache_info("our machine is MB\n");
	}
	else
	{
		cache_alert("error machine type %s\n", info.mach);
		return -EFAULT;
	}
	
	return 0;

}


static int ip_set(unsigned long ptr)
{
	struct cache_ip_info info;

	int err;

	err = copy_from_user(&info, (void *) ptr, sizeof(info));
	if (err)
		return -EFAULT;

	 if((info.who != MA) && (info.who != MB) ) 
	{
		cache_info("error owner \n");
		return -1;
	}
	 
	if(((machine_type == MA) && (info.who == MA)) ||  \
		((machine_type == MB) && (info.who == MB)))
	{
		memset(echo_host, 0, sizeof(echo_host));
		strncpy(echo_host, info.addr, sizeof(echo_host));
		cache_info("our machine echo_host ip address is  %s\n", echo_host);
	}
	if(((machine_type == MA) && (info.who == MB)) ||   \
	       ((machine_type == MB) && (info.who == MA)))
		
	{
		memset(echo_peer, 0, sizeof(echo_peer));
		strncpy(echo_peer, info.addr, sizeof(echo_peer));
		cache_info("our machine echo_peer ip address is  %s\n", echo_peer);
	}

	return 0;

}

/* manual flush all data of volume */
static int lun_update(unsigned long ptr)
{
	struct ietadm_cache_req req;

	int err;

	err = copy_from_user(&req, (void *) ptr, sizeof(req));
	if (err)
		return -EFAULT;
	
	cache_info("req.rcmnd =%d  req.lun =%d  req.name=%s  req.response =%d \n",
		   req.rcmnd,req.lun,req.name,req.response);

	if( req.rcmnd == CACHE_UPDATE) 
	{
		cache_alert("lun_update is  ok\n");
		req.rcmnd = CACHE_RESPONSE;
		req.lun =6;
		strcpy(req.name, "ok");
		req.response =9;
	}
	else
	{
		cache_alert("lun_update is  err\n");
		return -EFAULT;
	}

	err = copy_to_user((void *) ptr, &req, sizeof(req));

	if (err)
		return -EFAULT;

	return 0;

}

/* 
* called when peer recovery,  
* it's experimental, and need coordinate with iscsi client
*/
void hb_restore_owner(void)
{
	struct dcache *dcache;
	
	if(peer_is_good)
		return;	

	/* FIXME: the sequence between peer_is_good and writeback, yes? */
	mutex_lock(&dcache_list_lock);
	list_for_each_entry(dcache, &dcache_list, list) {
		if(dcache->origin_owner == false){
			if(dcache->task){
				kthread_stop(dcache->task);
				dcache->task = NULL;
			}
			dcache->owner = false;
			writeback_single(dcache, DCACHE_WB_SYNC_ALL, LONG_MAX, false);
		}
	}
	mutex_unlock(&dcache_list_lock);

	peer_is_good = true;
}

/* called when peer crash */
void hb_change_state(void)
{
	struct dcache *dcache;

	if(!peer_is_good)
		return;

	peer_is_good = false;
	
	mutex_lock(&dcache_list_lock);
	list_for_each_entry(dcache, &dcache_list, list) {
		dcache->owner = true;
	}
	mutex_unlock(&dcache_list_lock);
}

/*
*	$0 represent peer work well
*	$1 represent peer crash 
*/
static int hb_report_peer_state(unsigned long ptr)
{
	struct ctrl_msg_info info;
	char * msg;
	int err;
	msg = info.msg;

	err = copy_from_user(&info, (void *)ptr, sizeof(info));
	if (err)
		return -EFAULT;

	cache_dbg("HB sent signal to dcache\n");
	if(peer_is_good){
		if(strcmp(msg, "$1") ==0){
			hb_change_state();
			cache_alert("peer crash, take over all the volumes.\n");
		}
	}else{
		if(strcmp(msg, "$0") == 0){
			hb_restore_owner();
			cache_alert("peer recover, restore the owner of volumes.\n");
		}
	}

	return 0;
}

static long ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long err;
	u32 id;

	err = mutex_lock_interruptible(&ioctl_mutex);
	if (err < 0)
		return err;


	if (cmd == CACHE_MODULE_GET) {
		err = get_module_info(arg);
		goto done;
	}

	err = get_user(id, (u32 *) arg);
	if (err < 0)
		goto done;

	switch (cmd) {
	case CACHE_MACH_SET:
		err = machine_set(arg);
		break;
	case CACHE_IP_SET:
		err = ip_set(arg);
		break;		
	case CACHE_LUN_UPD:
		err = lun_update(arg);
		break;
	case CTRL_MSG_SEND:
		err = hb_report_peer_state(arg);
	default:
		cache_alert("invalid ioctl cmd  %d   \n", cmd);
		err = -EINVAL;
	}

done:
	mutex_unlock(&ioctl_mutex);

	return err;
}

static int release(struct inode *i __attribute__((unused)),
		   struct file *f __attribute__((unused)))
{
	mutex_lock(&ioctl_mutex);
	//target_del_all();
	cache_alert("release ioctl \n");

	mutex_unlock(&ioctl_mutex);

	return 0;
}

struct file_operations dcache_ctr_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= ioctl,
	.compat_ioctl	= ioctl,
	.release	= release
};
