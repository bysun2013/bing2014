/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSI_CACHE_H
#define ISCSI_CACHE_H

extern int dcache_read(void *volume_dcache, struct page **pages,
		u32 pg_cnt, u32 size, loff_t ppos);

extern int dcache_write(void *volume_dcache, struct page **pages,
		u32 pg_cnt, u32 size, loff_t ppos);

extern void* init_volume_dcache(const char *path, int owner, int port);

extern void del_volume_dcache(void *volume_dcachep);

#endif
