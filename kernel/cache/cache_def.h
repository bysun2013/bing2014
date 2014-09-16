/*
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

#ifndef DCACHE_DEF_H
#define DCACHE_DEF_H

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

#define ADDR_LEN 		16
#define PATH_LEN 		32

#define SECTOR_SHIFT	9
#define SECTOR_SIZE	512
#define SECTORS_ONE_PAGE	8
#define SECTORS_ONE_PAGE_SHIFT 3

extern bool peer_is_good;

extern struct list_head dcache_list;
extern struct mutex dcache_list_lock;

extern unsigned long dcache_total_pages;
extern unsigned int dcache_total_volume;
extern struct kmem_cache *cache_request_cache;

/* dynamic writeback, to improve performance */
#define PVEC_NORMAL_SIZE		16
#define PVEC_MAX_SIZE           512

enum request_from {
	REQUEST_FROM_PEER = 0,
	REQUEST_FROM_OUT,
};

enum page_site {
	inactive = 0, /* active list*/
	active,   /*inactive list*/
	radix,     /*radix tree*/
	temp,     /*temp list*/
};

struct dcache_page{
	/* initialize when isolated, no lock needed*/
	struct dcache  *dcache;

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

struct dcache{
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

/* cache IO, to receive data synced */
struct cio {
       loff_t offset; /* byte offset on target */
       u32 size; /* total io bytes */

       u32 pg_cnt; /* total page count */
       struct page **pvec; /* array of pages holding data */

       atomic_t count; /* ref count */
};

#endif

