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

extern struct list_head iscsi_cache_list;
extern struct mutex iscsi_cache_list_lock;

enum{
	WRITE_BACK,
	HOST,
	LOCKED,
};

enum iscsi_wb_sync_modes {
	ISCSI_WB_SYNC_NONE,	/* Don't wait on anything */
	ISCSI_WB_SYNC_ALL,	/* Wait on every mapping */
};

#define ISCSICACHE_TAG_DIRTY	0
#define ISCSICACHE_TAG_WRITEBACK	1
#define ISCSICACHE_TAG_TOWRITE	2

struct iscsi_cache_page{
	/* initialize when isolated, no lock needed*/
	struct iscsi_cache  *iscsi_cache;

	struct block_device *bdev;
	pgoff_t	index;

	/* block is 512 Byte, and page is 4KB */
	unsigned char valid_bitmap;
	unsigned char dirty_bitmap;
	
	struct page *page;
	spinlock_t page_lock;

	unsigned long flag;
	struct mutex write;

	struct list_head lru_list;
};

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

#define MAX_NAME_LEN 5

struct iscsi_cache{
	char name[MAX_NAME_LEN];
	
	struct radix_tree_root page_tree;	/* radix tree of all cache pages */
	spinlock_t	 tree_lock;	 /* and lock protecting it */

	unsigned long state;	/* Always use atomic bitops on this */
	
	unsigned long last_old_flush;	/* last old data flush */
	unsigned long last_active;	/* last time wb thread was active */

	unsigned long dirty_pages;
	unsigned long total_pages;
	
	struct task_struct *task;	/* writeback thread */
	struct timer_list wakeup_timer; /* used for delayed thread wakeup */

	spinlock_t wb_lock;

	struct list_head list;		/* list all of radix tree in cache */
	struct mutex mutex;
};

/* iscsi_cache.c */
unsigned char get_bitmap(sector_t lba_off, u32 num);

void add_to_lru_list(struct list_head *list);
void throw_to_lru_list(struct list_head *list);
void update_lru_list(struct list_head *list);

void copy_tio_to_cache(struct page* page, struct iscsi_cache_page *iscsi_page, 
	char bitmap, unsigned int skip_blk, unsigned int bytes);
void copy_cache_to_tio(struct iscsi_cache_page *iscsi_page, struct page* page, 
	char bitmap, unsigned int skip_blk, unsigned int bytes);


int iscsi_add_page(struct iscsi_cache *iscsi_cache,  struct iscsi_cache_page* iscsi_page);
int iscsi_del_page(struct iscsi_cache_page *iscsi_page);
struct iscsi_cache_page* iscsi_get_free_page(struct iscsi_cache *iscsi_cache);
struct iscsi_cache_page* iscsi_find_get_page(struct iscsi_cache *iscsi_cache, pgoff_t index);


/* cache_rw.c */
int blockio_start_write_page_blocks(struct iscsi_cache_page *iet_page, struct block_device *bdev);


/* writeback.c */
extern struct task_struct *iscsi_wb_forker;
void iscsi_set_page_tag(struct iscsi_cache_page *iscsi_page, unsigned int tag);
void iscsi_clear_page_tag(struct iscsi_cache_page *iscsi_page, unsigned int tag);
int writeback_single(struct iscsi_cache *iscsi_cache, unsigned int mode, unsigned long pages_to_write);
bool over_bground_thresh(struct iscsi_cache *iscsi_cache);
void cache_wakeup_timer_fn(unsigned long data);
void wakeup_cache_flusher(struct iscsi_cache *iscsi_cache);
int wb_thread_init(void);
void wb_thread_exit(void);

/* cache_proc.c*/

int cache_procfs_init(void);
void cache_procfs_exit(void);



#endif
