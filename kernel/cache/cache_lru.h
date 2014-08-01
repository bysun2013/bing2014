/*
 * Copyright (C) 2014-2015 Hearto <hearto1314@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef CACHE_LRU_H
#define CACHE_LRU_H

#include <linux/mm_types.h>
#include <linux/list.h>
#include "cache.h"

#define ACTIVE_TIMEOUT 20   //unit : s

#define MIN_INACTIVE_LEN    100  //move all active to inactive if inactive < MIN_INACTIVE_LEN
#define LRU_TOTAL_RATIO     1    // total_pages :inactive_list_length > (1<<LRU_TOTAL_RATIO)?
#define LRU_LIST_RATIO      1  // inactive_list_length:active_list_length > (1<<LRU_LIST_RATIO) ?

struct iscsi_cache_page* lru_alloc_page(void);

void check_list_status(void);

void inactive_add_page(struct iscsi_cache_page *cache_page);
void active_add_page(struct iscsi_cache_page *cache_page);
void lru_add_page(struct iscsi_cache_page *cache_page);
void lru_set_page_back(struct iscsi_cache_page *cache_page);

void lru_del_page(struct iscsi_cache_page *cache_page);


void inactive_writeback_add_list(struct list_head *list);
void active_writeback_add_list(struct list_head *list);

void move_page_to_active(struct iscsi_cache_page *cache_page);
void lru_mark_page_accessed(struct iscsi_cache_page *cache_page,int move);

void lru_read_miss_handle(struct iscsi_cache_page *cache_page);
void lru_read_hit_handle(struct iscsi_cache_page *cache_page);
void lru_write_miss_handle(struct iscsi_cache_page *cache_page);
void lru_write_hit_handle(struct iscsi_cache_page *cache_page);


int lru_shrink_thread_init(void);
void lru_shrink_thread_exit(void);

int lru_list_init(void);

#endif
