/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef CACHE_ISCSI_CACHE_H
#define CACHE_ISCSI_CACHE_H

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/radix-tree.h>
#include <linux/pagemap.h>
#include <linux/timer.h>

#include "cache_dbg.h"

#define CACHE_VERSION "0.2"

extern struct list_head iscsi_cache_list;
extern struct mutex iscsi_cache_list_lock;

extern unsigned long iscsi_cache_total_pages;

/*
 * Bits in iscsi_cache.state
 */
enum cache_state {
	CACHE_pending,		/* On its way to being activated */
	CACHE_wb_alloc,		/* Default embedded wb allocated */
	CACHE_async_congested,	/* The async (write) queue is getting full */
	CACHE_sync_congested,	/* The sync queue is getting full */
	CACHE_writeback_running,	/* Writeback is in progress */
	CACHE_unused,		/* Available bits start here */
};

struct iscsi_cache_page{
	/* initialize when isolated, no lock needed*/
	struct iscsi_cache  *iscsi_cache;

	dev_t	device_id;
	pgoff_t	index;

	/* block is 512 Byte, and page is 4KB */
	unsigned char valid_bitmap;
	unsigned char dirty_bitmap;
	unsigned long dirtied_when;	/* jiffies of first dirtying */
	
	struct page *page;
	spinlock_t page_lock;

	unsigned long flag;
	struct mutex write;

	struct list_head lru_list;
};

#define PATH_LEN 16

struct iscsi_cache{
	u32 id;
	char path[PATH_LEN];
	struct block_device *bdev;
	
	struct list_head list;		/* list all of radix tree in cache */
	
	struct radix_tree_root page_tree;	/* radix tree of all cache pages */
	spinlock_t	 tree_lock;	 /* and lock protecting it */

	/* Writeback */
	unsigned long state;	/* Always use atomic bitops on this */
	
	unsigned long last_old_flush;	/* last old data flush */
	unsigned long last_active;	/* last time wb thread was active */

	unsigned long dirty_pages;	/* should be atomic */
	unsigned long total_pages;
	
	struct task_struct *task;	/* writeback thread */
	struct timer_list wakeup_timer; /* used for delayed thread wakeup */

};

/* cache IO */
struct cio {
       loff_t offset; /* byte offset on target */
       u32 size; /* total io bytes */

       u32 pg_cnt; /* total page count */
       struct page **pvec; /* array of pages holding data */

       atomic_t count; /* ref count */
};

/* cache_rw.c */
int cache_write_page_blocks(struct iscsi_cache_page *iet_page);
int cache_check_read_blocks(struct iscsi_cache_page *iet_page, 
	unsigned char valid, unsigned char read);
int cache_rw_page(struct iscsi_cache_page *iet_page, int rw);


#endif
