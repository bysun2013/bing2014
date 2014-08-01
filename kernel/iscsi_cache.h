/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSI_CACHE_H
#define ISCSI_CACHE_H

extern int iscsi_read_cache(void *iscsi_cache, struct page **pages,
		u32 pg_cnt, u32 size, loff_t ppos);

extern int iscsi_write_cache(void *iscsi_cache, struct page **pages,
		u32 pg_cnt, u32 size, loff_t ppos);

extern void* init_iscsi_cache(const char *path, int owner, int port);

extern void del_iscsi_cache(void *iscsi_cachep);

#endif
