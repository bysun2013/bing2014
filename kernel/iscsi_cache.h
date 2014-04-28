/*
 * Copyright (C) 2013-2014 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSI_CACHE_H
#define ISCSI_CACHE_H

#include "iscsi.h"

extern int iet_page_num;

#define SECTOR_SIZE	512
#define SECTOR_PER_PAGE	8


struct iet_cache_page{
	struct iet_volume *volume;
	struct page *page;
	pgoff_t	index;

	/* block is 512 Byte, and page is 4KB */
	char valid_bitmap;
	char dirty_bitmap;
	
	struct list_head wb_list;
	struct list_head lru_list;
	atomic_t count;
	spinlock_t lock;
};

int iet_add_page(struct iet_volume *volume,  struct page* page); 

struct iet_cache_page* iet_find_get_page(struct iet_volume *volume, sector_t sector);

int iet_del_page_from_cache(struct iet_cache_page *iet_page);



int iet_cache_init(void);

int iet_cache_exit(void);


#endif


