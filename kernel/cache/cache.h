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


#ifndef DCACHE_H
#define DCACHE_H

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/radix-tree.h>
#include <linux/pagemap.h>
#include <linux/timer.h>

#include "cache_def.h"
#include "cache_conn/cache_conn.h"
#include "iet_cache_u.h"

/* parameter of reserved memory at boot */
extern unsigned int iet_mem_size;
extern char *iet_mem_virt;
/* preferred starting address of the region */
//extern unsigned long iscsi_mem_goal; 

int dcache_clean_page(struct dcache * dcache, pgoff_t index);
int _dcache_write(void *dcachep, struct page **pages, 
	u32 pg_cnt, u32 size, loff_t ppos, enum request_from from);

#endif

