/*
 * Copyright (C) 2013-2014 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSI_CACHE_H
#define ISCSI_CACHE_H

#include <linux/kthread.h>
#include "iscsi.h"

enum{
	WRITE_BACK,
	HOST,
	LOCKED,
};

#define IETCACHE_TAG_DIRTY	0
#define IETCACHE_TAG_WRITEBACK	1
#define IETCACHE_TAG_TOWRITE	2

/**
*	define it if you want to use list to writeback. 
*	By default, radix tree is used to implement it.
*/
#ifdef WRITEBACK_LIST
#undef WRITEBACK_LIST
#endif

struct iet_cache_page{
	/* initialize when isolated, no lock needed*/
	struct iet_volume *volume;
	pgoff_t	index;

	/* block is 512 Byte, and page is 4KB */
	char valid_bitmap;
	char dirty_bitmap;
	
	struct page *page;
	spinlock_t page_lock;

	unsigned long flag;
	struct mutex write;
	
#ifdef WRITEBACK_LIST	
	struct list_head wb_list;
#endif

	struct list_head lru_list;
};

char get_bitmap(sector_t lba_off, u32 num);

void add_to_lru_list(struct list_head *list);
void throw_to_lru_list(struct list_head *list);
void update_lru_list(struct list_head *list);

void copy_tio_to_cache(struct page* page, struct iet_cache_page *iet_page, 
	char bitmap, unsigned int skip_blk, unsigned int bytes);
void copy_cache_to_tio(struct iet_cache_page *iet_page, struct page* page, 
	char bitmap, unsigned int skip_blk, unsigned int bytes);


int iet_add_page(struct iet_volume *volume,  struct iet_cache_page* iet_page);
int iet_del_page(struct iet_cache_page *iet_page);
struct iet_cache_page* iet_get_free_page(void);
struct iet_cache_page* iet_find_get_page(struct iet_volume *volume, pgoff_t index);

extern int blockio_start_rw_page_blocks(struct iet_cache_page * iet_page,int rw);

#ifdef WRITEBACK_LIST
void add_to_wb_list(struct list_head *list);
struct iet_cache_page* get_wb_page(void);
extern int writeback_all(void);
#endif

extern int writeback_all_target(void);

extern int writeback_thread(void *args);

void iet_set_page_tag(struct iet_cache_page *iet_page, unsigned int tag);
void iet_clear_page_tag(struct iet_cache_page *iet_page, unsigned int tag);


int iet_cache_init(void);

int iet_cache_exit(void);


#endif


