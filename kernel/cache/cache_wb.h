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
