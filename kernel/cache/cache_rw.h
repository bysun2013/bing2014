/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */
 
#ifndef CACHE_RW_H
#define CACHE_RW_H

int dcache_check_read_blocks(struct dcache_page *dcache_page, 
	unsigned char valid, unsigned char read);
int dcache_read_mpage(struct dcache *dcache, 
	struct dcache_page **dcache_pages, int pg_cnt);
void dcache_delete_radix_tree(struct dcache *dcache);

#endif

