/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef CACHE_ISCSI_WB_H
#define CACHE_ISCSI_WB_H

#include "cache.h"

#define ISCSICACHE_TAG_DIRTY	0
#define ISCSICACHE_TAG_WRITEBACK	1
#define ISCSICACHE_TAG_TOWRITE	2

enum{
	WRITE_BACK,
	HOST,
	LOCKED,
};

enum iscsi_wb_sync_modes {
	ISCSI_WB_SYNC_NONE,	/* Don't wait on anything */
	ISCSI_WB_SYNC_ALL,	/* Wait on every mapping */
};

/*
 * why some writeback work was initiated
 */
enum cache_wb_reason {
	ISCSI_WB_REASON_BACKGROUND,
	ISCSI_WB_REASON_SYNC,
	ISCSI_WB_REASON_PERIODIC,
	ISCSI_WB_REASON_FORKER_THREAD,

	ISCSI_WB_REASON_MAX,
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

/*
 * Passed into cache_wb_writeback(), essentially a subset of writeback_control
 */
struct cache_writeback_work {
	long nr_pages;
	struct iscsi_cache *cache;
	unsigned long *older_than_this;   /* may be used in the future */
	enum iscsi_wb_sync_modes sync_mode;
	
	unsigned int for_kupdate:1;
	unsigned int range_cyclic:1;
	unsigned int for_background:1;
	enum cache_wb_reason reason;		/* why was writeback initiated? */

	struct list_head list;		/* pending work list */
	struct completion *done;	/* set if the caller waits */
};

extern struct task_struct *iscsi_wb_forker;

void iscsi_set_page_tag(struct iscsi_cache_page *iscsi_page, unsigned int tag);
void iscsi_clear_page_tag(struct iscsi_cache_page *iscsi_page, unsigned int tag);
int writeback_single(struct iscsi_cache *iscsi_cache, unsigned int mode, unsigned long pages_to_write);
bool over_bground_thresh(struct iscsi_cache *iscsi_cache);
void cache_wakeup_timer_fn(unsigned long data);
void wakeup_cache_flusher(struct iscsi_cache *iscsi_cache);
int wb_thread_init(void);
void wb_thread_exit(void);

#endif
