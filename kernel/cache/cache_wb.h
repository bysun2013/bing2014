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

#ifndef CACHE_WB_H
#define CACHE_WB_H

#include "cache_def.h"
#include "cache_rw.h"

/*
 * why some writeback work was initiated
 */
enum cache_wb_reason {
	DCACHE_WB_REASON_BACKGROUND,
	DCACHE_WB_REASON_SYNC,
	DCACHE_WB_REASON_PERIODIC,
	DCACHE_WB_REASON_FORKER_THREAD,

	DCACHE_WB_REASON_MAX,
};

/*
 * Passed into cache_wb_writeback(), essentially a subset of writeback_control
 */
struct cache_writeback_work {
	long nr_pages;
	struct dcache *cache;
	unsigned long *older_than_this;   /* may be used in the future */
	enum iscsi_wb_sync_modes sync_mode;
	
	unsigned int for_kupdate:1;
	unsigned int range_cyclic:1;
	unsigned int for_background:1;
	enum cache_wb_reason reason;		/* why was writeback initiated? */

	struct list_head list;		/* pending work list */
	struct completion *done;	/* set if the caller waits */
};

extern struct task_struct *dcache_wb_forker;

bool over_bground_thresh(struct dcache *dcache);
void cache_wakeup_timer_fn(unsigned long data);
void wakeup_cache_flusher(struct dcache *dcache);
int wb_thread_init(void);
void wb_thread_exit(void);

#endif
