/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "cache.h"

typedef void (cache_show_info_t)(struct seq_file *seq);

struct proc_entries {
	const char *name;
	struct file_operations *fops;
};

static void *cache_seq_start(struct seq_file *m, loff_t *pos)
{
	int err;

	err = mutex_lock_interruptible(&iscsi_cache_list_lock);
	if (err < 0)
		return ERR_PTR(err);

	return seq_list_start(&iscsi_cache_list, *pos);
}

static void *cache_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &iscsi_cache_list, pos);
}

static void cache_seq_stop(struct seq_file *m, void *v)
{
	if (PTR_ERR(v) != -EINTR)
		mutex_unlock(&iscsi_cache_list_lock);
}

static int cache_seq_show(struct seq_file *m, void *p)
{
	cache_show_info_t *func = (cache_show_info_t *)m->private;

	seq_printf(m, "iSCSI Cache Status:\n");

	func(m);

	return 0;
}

struct seq_operations cache_seq_op = {
	.start = cache_seq_start,
	.next = cache_seq_next,
	.stop = cache_seq_stop,
	.show = cache_seq_show,
};


static void cache_volume_info_show(struct seq_file *seq)
{
	struct iscsi_cache * volume;
	
	list_for_each_entry(volume, &iscsi_cache_list, list) {
		seq_printf(seq, "\tcache Path:%s total:%u dirty:%u\n",
			&volume->path[0], atomic_read(&volume->total_pages), atomic_read(&volume->dirty_pages));
	}
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

