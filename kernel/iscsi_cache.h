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
	struct page *page;
	char bitmap;    /* block is 512 Byte, and page is 4KB, so 8 bit are used */
	
	struct iet_volume *volume;
	pgoff_t	index;
	
	struct list_head lru_list;
	atomic_t count;
};

int iet_add_page_to_cache(struct iet_volume *volume,  struct page* page,  
		sector_t sector, int rw); 

struct iet_cache_page* iet_find_page_from_cache(struct iet_volume *volume, sector_t sector);

int iet_del_page_from_cache(struct iet_cache_page *iet_page);



int iet_cache_init(void);

int iet_cache_exit(void);


#endif


