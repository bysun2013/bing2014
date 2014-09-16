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

 
#ifndef CACHE_RW_H
#define CACHE_RW_H

#include "cache_conn/cache_conn.h"

#define DCACHE_TAG_DIRTY	0
#define DCACHE_TAG_WRITEBACK	1
#define DCACHE_TAG_TOWRITE	2

enum iscsi_wb_sync_modes {
	DCACHE_WB_SYNC_NONE,	/* Don't wait on anything */
	DCACHE_WB_SYNC_ALL,	/* Wait on every mapping */
};

/*
 * A control structure which tells the writeback code what to do.  These are
 * always on the stack, and hence need no locking.  They are always initialised
 * in a manner such that unspecified fields are set to zero.
 */
struct cache_writeback_control {
	long nr_to_write;		/* Write this many pages, and decrement
					   		this for each page written */
					   	
	loff_t range_start;
	loff_t range_end;

	enum iscsi_wb_sync_modes mode;

	unsigned for_kupdate:1;		/* A kupdate writeback */
	unsigned for_background:1;	/* A background writeback */
	unsigned range_cyclic:1;	/* range_start is cyclic */
};

int dcache_check_read_blocks(struct dcache_page *dcache_page, 
	unsigned char valid, unsigned char read);
int dcache_read_mpage(struct dcache *dcache, 
	struct dcache_page **dcache_pages, int pg_cnt);
void dcache_delete_radix_tree(struct dcache *dcache);

void dcache_set_page_tag(struct dcache_page *dcache_page, unsigned int tag);
long writeback_single(struct dcache *dcache, unsigned int mode, long pages_to_write, bool cyclic);

#endif

