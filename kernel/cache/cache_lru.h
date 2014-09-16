/*
 * Copyright (C) 2014-2015 Hearto <hearto1314@gmail.com>
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

#ifndef CACHE_LRU_H
#define CACHE_LRU_H

#include <linux/mm_types.h>
#include <linux/list.h>
#include "cache_def.h"

extern atomic_t inactive_list_length;
extern atomic_t active_list_length;

#define ACTIVE_TIMEOUT	20

/* move all active to inactive if inactive < MIN_INACTIVE_LEN */
#define MIN_INACTIVE_LEN    100 
/* total_pages :inactive_list_length > (1<<LRU_TOTAL_RATIO)? */
#define LRU_TOTAL_RATIO     1
/* inactive_list_length:active_list_length > (1<<LRU_LIST_RATIO) ? */
#define LRU_LIST_RATIO      1

/*
 * alloc a new page from inactive list
 * if there is no page ,return NULL
 */
struct dcache_page* lru_alloc_page(void);

/*
 * check if inactive list is in low, move some active pages into inactive list when it is low
 * use it before call lru_alloc_page 
 */
void check_list_status(void);

/*
 * add a page into inactive/active list
 */
void inactive_add_page(struct dcache_page *dcache_page);
void active_add_page(struct dcache_page *dcache_page);

/*
 * add a page into inactive list or active list, according to page active flag 
 */
void lru_add_page(struct dcache_page *dcache_page);

/*
 * set a  free page back to inactive list
 * after lru_alloc_page success and the page can not add into radix tree ,call it
 */
void lru_set_page_back(struct dcache_page *dcache_page);

/*
 * used in writeback thread,add temp list to inactive/active list
 */
void inactive_writeback_add_list(struct list_head *list);
void active_writeback_add_list(struct list_head *list);

/*
 * move one inactive list page to active list,make sure the page is locked before use it
 */
void move_page_to_active(struct dcache_page *dcache_page);

/*
 * when a page is referened,call it to change the page state
 * @move : decide whether move the page or not
 */
void lru_mark_page_accessed(struct dcache_page *dcache_page,int move);

/*
 * when read miss/hit ,call it
 */
void lru_read_miss_handle(struct dcache_page *dcache_page);
void lru_read_hit_handle(struct dcache_page *dcache_page);

/*
 * when write miss/hit ,call it
 */
void lru_write_miss_handle(struct dcache_page *dcache_page);
void lru_write_hit_handle(struct dcache_page *dcache_page);

/*
 * shrink inactive list and active list thread
 * shrink every ACTIVE_TIMEOUT(default 20) seconds
 */
int lru_shrink_thread_init(void);
void lru_shrink_thread_exit(void);

/*
 * include lru list,list length,list spinlock and shrink thread initialization
 */
int lru_list_init(void);

#endif
