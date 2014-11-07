/*
 * cache_proc.c
 *
 * user interface within /proc filesystem
 *
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
#include <linux/seq_file.h>

#include "cache_def.h"
#include "cache_lru.h"

extern atomic_t inactive_list_length;
extern atomic_t active_list_length;

long inactive_locked_length(void);
long active_locked_length(void);


typedef void (cache_show_info_t)(struct seq_file *seq, void *p);

struct proc_entries {
	const char *name;
	struct file_operations *fops;
};

static void *cache_seq_start(struct seq_file *m, loff_t *pos)
{
	unsigned long pages_dirty = 0;
	int active,inactive;
	int err;

	err = mutex_lock_interruptible(&dcache_list_lock);
	if (err < 0)
		return ERR_PTR(err);

	inactive = atomic_read(&inactive_list_length);
	active = atomic_read(&active_list_length);
	pages_dirty = dcache_total_pages - inactive - active;
	seq_printf(m, "iSCSI Cache Status:\n");
	seq_printf(m, "\tpage_dirty:%ld, inactive:%d, active:%d,  peer: %d\n", 
		pages_dirty, inactive, active, peer_is_good);

	seq_printf(m, "\tLocked, inactive: %ld, active: %ld\n", inactive_locked_length(), active_locked_length());
	seq_printf(m, "iSCSI Cache include %d volumes:\n", dcache_total_volume);

	return seq_list_start(&dcache_list, *pos);
}

static void *cache_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &dcache_list, pos);
}

static void cache_seq_stop(struct seq_file *m, void *v)
{
	if (PTR_ERR(v) != -EINTR)
		mutex_unlock(&dcache_list_lock);
}

static int cache_seq_show(struct seq_file *m, void *p)
{
	cache_show_info_t *func = (cache_show_info_t *)m->private;

	func(m, p);

	return 0;
}

struct seq_operations cache_seq_op = {
	.start = cache_seq_start,
	.next = cache_seq_next,
	.stop = cache_seq_stop,
	.show = cache_seq_show,
};


static void cache_volume_info_show(struct seq_file *seq, void *p)
{
	struct dcache * volume = list_entry(p, struct dcache, list);
	
	seq_printf(seq, "\tCache Path:%s total:%u dirty:%u Owner = %s\n",
		&volume->path[0], atomic_read(&volume->total_pages), atomic_read(&volume->dirty_pages),
		volume->owner? "true":"false");
}

static int cache_status_seq_open(struct inode *inode, struct file *file)
{
	int res;
	res = seq_open(file, &cache_seq_op);
	if (!res)
		((struct seq_file *)file->private_data)->private =
			cache_volume_info_show;
	return res;
}

struct file_operations cache_status_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= cache_status_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static struct proc_entries cache_proc_entries[] =
{
	{"status", &cache_status_seq_fops},
};

static struct proc_dir_entry *proc_cache_dir;

void cache_procfs_exit(void)
{
	int i;

	if (!proc_cache_dir)
		return;

	for (i = 0; i < ARRAY_SIZE(cache_proc_entries); i++)
		remove_proc_entry(cache_proc_entries[i].name, proc_cache_dir);

	remove_proc_entry(proc_cache_dir->name, NULL);
}

int cache_procfs_init(void)
{
	int i;
	struct proc_dir_entry *ent;
	
	if (!(proc_cache_dir = proc_mkdir("cache", NULL)))
		goto err;

	for (i = 0; i < ARRAY_SIZE(cache_proc_entries); i++) {
		ent = create_proc_entry(cache_proc_entries[i].name, 0, proc_cache_dir);
		if (ent)
			ent->proc_fops = cache_proc_entries[i].fops;
		else
			goto err;
	}

	return 0;

err:
	cache_err("Error occurs when initialize procfs.\n");
	return -ENOMEM;
}

