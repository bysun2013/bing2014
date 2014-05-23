/*
 * Copyright (C) 2013-2014 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSI_CACHE_H
#define ISCSI_CACHE_H

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/radix-tree.h>
#include <linux/pagemap.h>

enum{
	WRITE_BACK,
	HOST,
	LOCKED,
};

#define ISCSICACHE_TAG_DIRTY	0
#define ISCSICACHE_TAG_WRITEBACK	1
#define ISCSICACHE_TAG_TOWRITE	2


static struct list_head iscsi_cache_list;
static struct mutex iscsi_cache_list_mutex;

struct iscsi_cache_page{
	/* initialize when isolated, no lock needed*/
	struct iscsi_cache  *iscsi_cache;
	pgoff_t	index;

	/* block is 512 Byte, and page is 4KB */
	char valid_bitmap;
	char dirty_bitmap;
	
	struct page *page;
	spinlock_t page_lock;

	unsigned long flag;
	struct mutex write;

	struct list_head lru_list;
};

struct iscsi_cache{
	struct radix_tree_root page_tree;	/* radix tree of all cache pages */
	spinlock_t	 tree_lock;	 /* and lock protecting it */
	struct list_head list;		/* list all of radix tree in cache */
};

char get_bitmap(sector_t lba_off, u32 num);

void add_to_lru_list(struct list_head *list);
void throw_to_lru_list(struct list_head *list);
void update_lru_list(struct list_head *list);

void copy_tio_to_cache(struct page* page, struct iscsi_cache_page *iscsi_page, 
	char bitmap, unsigned int skip_blk, unsigned int bytes);
void copy_cache_to_tio(struct iscsi_cache_page *iscsi_page, struct page* page, 
	char bitmap, unsigned int skip_blk, unsigned int bytes);


int iscsi_add_page(struct iscsi_cache *iscsi_cache,  struct iscsi_cache_page* iscsi_page);
int iscsi_del_page(struct iscsi_cache_page *iscsi_page);
struct iscsi_cache_page* iscsi_get_free_page(void);
struct iscsi_cache_page* iscsi_find_get_page(struct iscsi_cache *iscsi_cache, pgoff_t index);

int blockio_start_rw_page_blocks(struct iscsi_cache_page * iscsi_page,int rw);

int writeback_thread(void *args);
int writeback_all(void);

void iscsi_set_page_tag(struct iscsi_cache_page *iscsi_page, unsigned int tag);
void iscsi_clear_page_tag(struct iscsi_cache_page *iscsi_page, unsigned int tag);

#endif
