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
#include "cache_conn/cache_conn.h"
#include "iet_cache_u.h"

#define CACHE_VERSION "0.04"

extern bool peer_is_good;

extern struct list_head iscsi_cache_list;
extern struct mutex iscsi_cache_list_lock;

extern unsigned long iscsi_cache_total_pages;
extern unsigned int iscsi_cache_total_volume;
extern struct kmem_cache *cache_request_cache;

#define PVEC_SIZE		64
#define ADDR_LEN 		16
#define PATH_LEN 		32

/* dynamic writeback, to improve performance */
#define PVEC_NORMAL_SIZE		16
#define PVEC_MAX_SIZE           64

enum request_from{
	REQUEST_FROM_PEER = 0,
	REQUEST_FROM_OUT,
};

enum page_site {
	inactive = 0, /* active list*/
	active,   /*inactive list*/
	radix,     /*radix tree*/
	temp,     /*temp list*/
};
	

struct iscsi_cache_page{
	/* initialize when isolated, no lock needed*/
	struct iscsi_cache  *iscsi_cache;

	dev_t	device_id;
	pgoff_t	index;

	unsigned long dirtied_when;	/* jiffies of first dirtying */
	
	struct page *page;

	unsigned long flag;

	struct list_head list;
	enum page_site  site;
	/* block is 512 Byte, and page is 4KB */
	unsigned char valid_bitmap;
	unsigned char dirty_bitmap;
}__attribute__((aligned(sizeof(u64))));

struct iscsi_cache{
	u32 id;
	char path[PATH_LEN];

	/* Inter-connection of Cache */
	bool owner;
	bool origin_owner;

	char inet_addr[ADDR_LEN];
	char inet_peer_addr[ADDR_LEN];
	int port;
	
	struct block_device *bdev;
	
	struct cache_connection * conn;
	
	struct list_head list;		/* list all of volume in cache */
	
	struct radix_tree_root page_tree;	/* radix tree of all cache pages */
	spinlock_t	 tree_lock;	 /* and lock protecting it */

	/* Writeback */
	unsigned long state;	/* Always use atomic bitops on this */
	unsigned long last_old_flush;	/* last old data flush */
	unsigned long last_active;	/* last time wb thread was active */
	pgoff_t writeback_index;		/* for cyclic writeback */
	atomic_t dirty_pages;	/* should be atomic */
	atomic_t total_pages;
	struct task_struct *task;	/* writeback thread */
	struct completion wb_completion; /* wait for writeback thread exit */
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

int cache_clean_page(struct iscsi_cache * iscsi_cache, pgoff_t index);
int _iscsi_write_cache(void *iscsi_cachep, struct page **pages, 
	u32 pg_cnt, u32 size, loff_t ppos, enum request_from from);


/* cache_rw.c */
int cache_write_page_blocks(struct iscsi_cache_page *iet_page);
int cache_check_read_blocks(struct iscsi_cache_page *iet_page, 
	unsigned char valid, unsigned char read);
int cache_read_mpage(struct iscsi_cache *iscsi_cache, 
	struct iscsi_cache_page **iscsi_pages, int pg_cnt);
void iscsi_delete_radix_tree(struct iscsi_cache *iscsi_cache);

/* cache_config.c */
extern int machine_type;
extern char echo_host[];
extern char echo_peer[];

#endif
