/*
 * Copyright (C) 2013-2014 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSI_CACHE_H
#define ISCSI_CACHE_H

#include "iscsi.h"

extern int iet_page_num;

/*LRU link all of pages and devices*/
extern struct list_head lru;
extern struct list_head iet_devices;


struct iet_cache_page{
	struct page *page;
//	dev_t bdev;
//	sector_t		sector;
	struct list_head lru_list;
//	struct iet_device *device;
	atomic_t count;
};

struct iet_device{
	struct address_space mapping;
	struct list_head list;
	dev_t bdev;
};



int iet_cache_add(dev_t dev, unsigned long page_index, struct page *page);


struct iet_cache_page* iet_cache_find(dev_t dev, unsigned long offset);


int iet_cache_release(struct iet_cache_page *);


int iet_cache_init(void);

int iet_cache_exit(void);


#endif


