/*
 * cache_lru.c
 * 
 * find available page with modified LRU, O(1)
 *
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

#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <asm/atomic.h>
#include <asm/page.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/err.h>

#include "cache_lru.h"

LIST_HEAD(inactive_list);
LIST_HEAD(active_list);

spinlock_t inactive_lock;
spinlock_t active_lock;

atomic_t inactive_list_length;
atomic_t active_list_length;

struct task_struct *lru_shrink_thread;

extern unsigned long dcache_total_pages;
extern void dcache_end_page_writeback(struct dcache_page *dcache_page);

static long list_locked_length(struct list_head *lru, spinlock_t *lock)
{
	struct list_head *list;
	struct dcache_page *dcache_page;
	long total = 0;
	
	spin_lock_irq(lock);
	list_for_each(list, lru) {
		dcache_page = list_entry(list, struct dcache_page, list);
		if(PageLocked(dcache_page->page))
			total++;
	}
	spin_unlock_irq(lock);

	return total;
}

long inactive_locked_length(void)
{
	return list_locked_length(&inactive_list, &inactive_lock);
}

long active_locked_length(void)
{
	return list_locked_length(&active_list, &active_lock);
}


static void lru_page_add(struct list_head *list,struct list_head *lru, spinlock_t * lock)
{
	spin_lock_irq(lock);
	list_add(list, lru);
	spin_unlock_irq(lock);	
}

static void lru_page_add_tail(struct list_head *list,struct list_head *lru,spinlock_t * lock)
{
	spin_lock_irq(lock);
	list_add_tail(list, lru);
	spin_unlock_irq(lock);
}

/*
  * get a new page from inactive_list. if there are no pages,return NULL
  * after function ,the page is locked, cache site is not set here
*/
struct dcache_page* lru_alloc_page(void)
{
	struct dcache_page *dcache_page = NULL;
	struct list_head * pos,*temp;
	
	spin_lock(&inactive_lock);
	if(!list_empty(&inactive_list)){
		list_for_each_prev_safe(pos,temp, &inactive_list) {
			dcache_page = list_entry(pos, struct dcache_page, list);
			if(!trylock_page(dcache_page->page))
				continue;
			list_del_init(pos);
			if(PageReferenced(dcache_page->page))
				ClearPageReferenced(dcache_page->page);
			if(PageActive(dcache_page->page))
				ClearPageActive(dcache_page->page);
			spin_unlock_irq(&inactive_lock);
			atomic_dec(&inactive_list_length);
			return dcache_page;
		}
		dcache_page = NULL;
	}
	spin_unlock(&inactive_lock);
	return dcache_page;
}

/*
 *  add src list to the head of dst
 */
static void list_connect(struct list_head *dst,struct list_head *src)
{
	if(list_empty(src))
		return;
	src->next->prev = dst;
	src->prev->next = dst->next;
	dst->next->prev = src->prev;
	dst->next = src->next;
}

/*
 * add list to lru,the page in list should be locked already
 * @list :it is usually a temporary list
 * @lru :should be inactive_list or active_list
 */
static void lru_add_list(struct list_head *list,struct list_head *lru,spinlock_t * lock)
{
	struct list_head *first,*last;
	struct dcache_page * dcache_page;

	spin_lock_irq(lock);
	if(list_empty(list)){
		spin_unlock_irq(lock);
		return;
	}

	first = list->next;
	last = list->prev;
	
	list_connect(lru,list);
	while(first != (last->next)){
		dcache_page = list_entry(first,struct dcache_page,list);
		unlock_page(dcache_page->page);
		first = first->next;
	}
	spin_unlock_irq(lock);	
}

/*
 * judge if inactive is low,by (inactive_len : total_pages) and (inactive_len : active_len)
 * if is low ,remember the moved pages number in @len
 */
static int inactive_is_low(int *len)
{
	int inactive,active;
	inactive = atomic_read(&inactive_list_length);
	active = atomic_read(&active_list_length);
	if((inactive<<LRU_TOTAL_RATIO) > dcache_total_pages)
		return 0;
	if(inactive < MIN_INACTIVE_LEN){
		*len = active;
		return 1;
	}
	if((active<<LRU_LIST_RATIO) > inactive){
		*len = (active>>1);
		return 1;
	}
	return 0;
}

static void move_active_to_inactive(int len)
{
	int active;
	struct list_head *pos;
	struct dcache_page * dcache_page;
	LIST_HEAD(list);

	spin_lock_irq(&active_lock);
	if(list_empty(&active_list)){
		spin_unlock_irq(&active_lock);
		return;
	}
	
	/*as multi-thread happens ,check again ,*/
	if(!inactive_is_low(&len)){
		spin_unlock_irq(&active_lock);
		return ;
	}	
	
	active = atomic_read(&active_list_length);
	len = (len < active ? len : active);
	cache_dbg("active ready move %d pages to inactive\n",len);
	pos = (&active_list)->prev;
	while(active-- && pos != &active_list){
		dcache_page = list_entry(pos,struct dcache_page,list);
		if(!trylock_page(dcache_page->page)){
			active++;
			pos = pos->prev;
			continue;
		}
		pos = pos->prev;
		list_move(pos->next,&list);
		dcache_page->site = inactive;
		if(PageReferenced(dcache_page->page))
			ClearPageReferenced(dcache_page->page);
		ClearPageActive(dcache_page->page);
		atomic_dec(&active_list_length);
		atomic_inc(&inactive_list_length);
	}
	spin_unlock_irq(&active_lock);
	
	lru_add_list(&list,&inactive_list,&inactive_lock);
}

/*
 * before remove a page from inactive list,use it 
 */
void check_list_status(void)
{
	int len = 0;
	if(inactive_is_low(&len)){
		move_active_to_inactive(len);
	}
}

/*
 * before use it ,make sure that  the page is locked. page_locked()?
 * and not in other list.  list_del()?
 */
void inactive_add_page(struct dcache_page *dcache_page)
{
	lru_page_add(&dcache_page->list, &inactive_list, &inactive_lock);
	dcache_page->site = inactive;
	atomic_inc(&inactive_list_length);
}
void active_add_page(struct dcache_page *dcache_page)
{
	lru_page_add(&dcache_page->list, &active_list, &active_lock);
	dcache_page->site = active;
	atomic_inc(&active_list_length);
}

void lru_add_page(struct dcache_page *dcache_page)
{
	if(!PageActive(dcache_page->page))
		inactive_add_page(dcache_page);
	else
		active_add_page(dcache_page);
}

void lru_set_page_back(struct dcache_page *dcache_page)
{
	lru_page_add_tail(&dcache_page->list, &inactive_list, &inactive_lock);
	dcache_page->site = inactive;
	atomic_inc(&inactive_list_length);
}

/*
 * delete one page from lru,make sure the page is locked before use it
 */
void lru_del_page(struct dcache_page * dcache_page)
{
	if(dcache_page->site == inactive){
		spin_lock_irq(&inactive_lock);
		list_del_init(&dcache_page->list);
		spin_unlock_irq(&inactive_lock);
		atomic_dec(&inactive_list_length);
	}
	else if(dcache_page->site == active){
		spin_lock_irq(&active_lock);
		list_del_init(&dcache_page->list);
		spin_unlock_irq(&active_lock);
		atomic_dec(&active_list_length);
	}
}

/*
 * move one inactive list page to active list,make sure the page is locked before use it
 */
void move_page_to_active(struct dcache_page * dcache_page)
{
	lru_del_page(dcache_page);
	active_add_page(dcache_page);
}

void lru_mark_page_accessed(struct dcache_page *dcache_page,int move)
{
	if(!PageReferenced(dcache_page->page))
		SetPageReferenced(dcache_page->page);
	else{
		if(!PageActive(dcache_page->page)){
			if(move){
				//cache_dbg("lru mark need to move to active\n");
				move_page_to_active(dcache_page);
			}
			ClearPageReferenced(dcache_page->page);
			SetPageActive(dcache_page->page);
		}	
	}
}

/*
 * call lru_alloc_page before use it, make sure that the cache page is locked
 */
void lru_read_miss_handle(struct dcache_page *dcache_page)
{
	inactive_add_page(dcache_page);
	SetPageReferenced(dcache_page->page);
}

void lru_read_hit_handle(struct dcache_page *dcache_page)
{
	if(PageWriteback(dcache_page->page)) {
		/* don't move from inactive to active, moved by bio_endio */
		if(!PageActive(dcache_page->page) && PageReferenced(dcache_page->page)){
			;
		}else
			lru_mark_page_accessed(dcache_page, 0);
	}
	else{
		if(dcache_page->site == inactive)
			lru_mark_page_accessed(dcache_page, 1);
		else
			lru_mark_page_accessed(dcache_page, 0);
	}
}


/*
 * call lru_alloc_page before use it, make sure that the cache page is locked
 */
void lru_write_miss_handle(struct dcache_page *dcache_page)
{
	SetPageReferenced(dcache_page->page);
	dcache_page->site = radix; 
}

/*
 * before call it ,the cache page is not dirty,in active list or inactive list
 */
void lru_write_hit_handle(struct dcache_page *dcache_page)
{
	lru_del_page(dcache_page);
	lru_mark_page_accessed(dcache_page,0);
	dcache_page->site = radix;
}

/*
 * just use for writeback
 */
void lru_writeback_add_list(struct list_head *list,struct list_head *lru,
			spinlock_t *lock,atomic_t *list_len,enum page_site site)
{
	struct list_head *first,*last;
	struct dcache_page *dcache_page = NULL;

	spin_lock_irq(lock);
	if(list_empty(list)){
		spin_unlock_irq(lock);
		return;
	}
	first = list->next;
	last = list->prev;
	list_connect(lru,list);
	while(first != last->next){
		dcache_page = list_entry(first,struct dcache_page,list);
		dcache_page->site = site;
		dcache_page->dirty_bitmap = 0x00;
		dcache_end_page_writeback(dcache_page);
		atomic_inc(list_len);
		first = first->next;
	}
	spin_unlock_irq(lock);
}

void inactive_writeback_add_list(struct list_head *list)
{
	lru_writeback_add_list(list,&inactive_list,&inactive_lock,&inactive_list_length,inactive);
}
void active_writeback_add_list(struct list_head *list)
{
	lru_writeback_add_list(list,&active_list,&active_lock,&active_list_length,active);
}


/*
 *  change flag in active_list and move pages from active_list to inactive_list
 */
static void shrink_active_list(void)
{
	struct list_head * pos,*tmp;
	struct dcache_page * dcache_page;
	LIST_HEAD(list);
	spin_lock_irq(&active_lock);
	list_for_each_prev_safe(pos,tmp,&active_list){
		dcache_page = list_entry(pos,struct dcache_page,list);
		if(!trylock_page(dcache_page->page))
			continue;
		if(PageReferenced(dcache_page->page)){
			ClearPageReferenced(dcache_page->page);
			unlock_page(dcache_page->page);
		}
		else{
			list_move(&dcache_page->list,&list);
			dcache_page->site = inactive;
			ClearPageActive(dcache_page->page);
			atomic_dec(&active_list_length);
			atomic_inc(&inactive_list_length);
		}
		//unlock_page(page);
	}
	spin_unlock_irq(&active_lock);
	
	lru_add_list(&list,&inactive_list,&inactive_lock);
}

static void shrink_inactive_list(void)
{
	struct list_head * pos;
	struct dcache_page * dcache_page;
	spin_lock_irq(&inactive_lock);
	list_for_each(pos,&inactive_list){
		dcache_page = list_entry(pos,struct dcache_page,list);
		if(!trylock_page(dcache_page->page))
			continue;
		if(PageReferenced(dcache_page->page))
			ClearPageReferenced(dcache_page->page);
		unlock_page(dcache_page->page);
	}
	spin_unlock_irq(&inactive_lock);
}

static int lru_list_shrink(void * args)
{
	while(!kthread_should_stop())
	{
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()){
				__set_current_state(TASK_RUNNING);
				continue;
		}
		schedule_timeout(msecs_to_jiffies(ACTIVE_TIMEOUT * 1000)); /* transform second to millisecond */
		cache_dbg("shrink list begin,inactive is %d,active is %d\n", \
					atomic_read(&inactive_list_length),atomic_read(&active_list_length));
		shrink_inactive_list();
		shrink_active_list();
		cache_dbg("shrink list finish,inactive is %d,active is %d\n", \
					atomic_read(&inactive_list_length),atomic_read(&active_list_length));
	}
	return 0;
}
int lru_shrink_thread_init(void)
{
	int err;
	lru_shrink_thread = kthread_run(lru_list_shrink,NULL,"lru_shrink");
	if(IS_ERR(lru_shrink_thread)){
       cache_err("create lru shrink thread failed\n");
       err = PTR_ERR(lru_shrink_thread);
       lru_shrink_thread = NULL;
       return err;
	}
	return 0;
}

void lru_shrink_thread_exit(void)
{
	if(lru_shrink_thread){
		kthread_stop(lru_shrink_thread);
		lru_shrink_thread = NULL;
	}
}

int lru_list_init(void)
{
	atomic_set(&inactive_list_length,0);
	atomic_set(&active_list_length,0);
	spin_lock_init(&inactive_lock);
	spin_lock_init(&active_lock);
	return lru_shrink_thread_init();
}

