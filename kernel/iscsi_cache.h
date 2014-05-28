/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSI_CACHE_H
#define ISCSI_CACHE_H

extern char get_bitmap(sector_t lba_off, u32 num);

extern int iscsi_read_from_cache(void *iscsi_cachep, struct block_device *bdev, pgoff_t page_index, struct page* page, 
		char bitmap, unsigned int current_bytes, unsigned int skip_blk);
extern int iscsi_write_into_cache(void *iscsi_cachep, struct block_device *bdev, pgoff_t page_index, struct page* page, 
		char bitmap, unsigned int current_bytes, unsigned int skip_blk);

extern void * init_iscsi_cache(void);
extern void del_iscsi_cache(void *iscsi_cachep);

#endif
