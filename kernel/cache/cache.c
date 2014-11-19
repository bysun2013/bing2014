/*
 * cache.c
 *
 * handle dcache Read/Write operations
 *
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
 
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <asm/atomic.h>
#include <linux/blkdev.h>
#include <asm/page.h>
#include <linux/list.h>

#include "cache_def.h"
#include "cache.h"
#include "cache_rw.h"
#include "cache_wb.h"
#include "cache_lru.h"
#include "cache_proc.h"
#include "cache_config.h"

#define CACHE_VERSION "0.11-r18"

/* by default, peer is false */
bool peer_is_good = false;

static int ctr_major_cache;
static char dcache_ctr_name[] = "dcache_ctl";
extern struct file_operations dcache_ctr_fops;

unsigned long dcache_total_pages;
unsigned int dcache_total_volume;

struct kmem_cache *cache_request_cache;

/* list all of caches, which represent volumes. */
struct list_head dcache_list;
struct mutex dcache_list_lock;

/* list of threads, which wait for free pages */
static struct list_head cache_wait_queue_head;
static spinlock_t cache_wait_queue_lock;

/*
* when dirty pages is over the high thresh, writeback a fixed number
* of dirty pages. It's to guarantee enough free clean pages.
*/
static int over_high_watermark(struct dcache * dcache)
{
	long dirty_pages = atomic_read(&dcache->dirty_pages);
	long inactive_pages = atomic_read(&inactive_list_length);
	long active_pages = atomic_read(&active_list_length);

	/* if clean pages is above 1/16 of total pages, do nothing */
	long level = dcache_total_pages >> 4;
	if(level < 256)
		level = 256;

	if((inactive_pages + active_pages) > level)
		return 0;
	if(dirty_pages * dcache_total_volume < dcache_total_pages)
		return 0;

	return 1;
}

static int decrease_dirty_ratio(struct dcache * dcache)
{
	int wrote = 0;
	if(over_high_watermark(dcache))
		wrote = writeback_single(dcache, DCACHE_WB_SYNC_NONE, 512, true);

	return wrote;
}

static void del_page_from_radix(struct dcache_page *dcache_page)
{
	struct  dcache *dcache = dcache_page->dcache;

	spin_lock_irq(&dcache->tree_lock);
	radix_tree_delete(&dcache->page_tree, dcache_page->index);
	dcache_page->dcache = NULL;
	spin_unlock_irq(&dcache->tree_lock);
}

typedef struct cache_wait_queue
{
	struct list_head list;
	struct task_struct *tsk;
}cache_wait_queue;

static inline void cache_wait_queue_init(cache_wait_queue *wait)
{
	INIT_LIST_HEAD(&(wait->list));
	wait->tsk = current;
}

/* cache_wait_queue_lock MUST be hold */
static inline void cache_add_wait_queue(struct dcache * dcache, cache_wait_queue *wait, int state)
{
	list_add_tail(&(wait->list), &cache_wait_queue_head);

	while(wait != list_first_entry(&cache_wait_queue_head, cache_wait_queue, list)){
		__set_current_state(state);
		spin_unlock(&cache_wait_queue_lock);
		schedule_timeout(LONG_MAX);
		__set_current_state(TASK_RUNNING);
		spin_lock(&cache_wait_queue_lock);
	}
	spin_unlock(&cache_wait_queue_lock);
}
static void cache_wait_free_page(struct dcache *dcache, cache_wait_queue *wait, int state)
{
	spin_lock(&cache_wait_queue_lock);

	if(list_empty(&cache_wait_queue_head)){
		spin_unlock(&cache_wait_queue_lock);
	}else{
		cache_add_wait_queue(dcache, wait, state);
	}
}

static void  cache_finish_wait_free_page(cache_wait_queue *wait)
{
	cache_wait_queue *next_wait;
	struct list_head *next;

	if(wait->list.prev != (struct list_head *)&cache_wait_queue_head){
		cache_alert("prev=%p, next=%p, self=%p, head=%p,h.next=%p\n",
			wait->list.prev,wait->list.next, &(wait->list), &cache_wait_queue_head, cache_wait_queue_head.next);
	}

	spin_lock(&cache_wait_queue_lock);
	list_del_init(&(wait->list));
	next = cache_wait_queue_head.next;

	if(next != &cache_wait_queue_head){
		next_wait = list_entry(next, cache_wait_queue, list);
		wake_up_process(next_wait->tsk);
	}
	spin_unlock(&cache_wait_queue_lock);
}

static struct dcache_page* dcache_get_free_page(struct dcache * dcache, int block)
{
	struct dcache_page *dcache_page;
	cache_wait_queue wait;

	cache_wait_queue_init(&wait);
	if(block)
		cache_wait_free_page(dcache, &wait, TASK_UNINTERRUPTIBLE);
	
	for(;;){
		check_list_status();
		dcache_page = lru_alloc_page();
		if(dcache_page) {
			dcache_page->valid_bitmap = 0x00;
			if(dcache_page->dcache){
				atomic_dec(&dcache_page->dcache->total_pages);
				del_page_from_radix(dcache_page);
			}
			
			if(!list_empty(&(wait.list)))
				cache_finish_wait_free_page(&wait);
			
			cache_dbg("get free page\n");
			return dcache_page;
		}else{
			if(!block)
				return NULL;
			
			if(!list_empty(&(wait.list))){
				schedule();
				continue;
			}
			spin_lock(&cache_wait_queue_lock);
			if(list_empty(&cache_wait_queue_head)){
				cache_add_wait_queue(dcache, &wait, TASK_RUNNING);
			}else{
				cache_add_wait_queue(dcache, &wait, TASK_UNINTERRUPTIBLE);
			}
		}
	}

	return NULL;
}

static struct dcache_page* dcache_read_get_free_page(struct dcache * dcache, int block)
{
	struct dcache_page *dcache_page;
/*
	spin_lock(&cache_wait_queue_lock);
	if(!block && !list_empty(&cache_wait_queue_head)){
		spin_unlock(&cache_wait_queue_lock);
		return NULL;
	}
	spin_unlock(&cache_wait_queue_lock);
*/
	dcache_page = dcache_get_free_page(dcache, block);

	return dcache_page;
}

static struct dcache_page* dcache_write_get_free_page(struct dcache * dcache)
{
	struct dcache_page *dcache_page;

	dcache_page = dcache_get_free_page(dcache, 1);

	return dcache_page;	
}

/*
* copy data to wrote into cache
*/
static void copy_pages_to_dcache(struct page* page, struct dcache_page *dcache_page, 
	unsigned char bitmap, unsigned int skip_blk, unsigned int bytes)
{
	char *dest, *source;
	unsigned int i=0;
	
	BUG_ON(page == NULL);
	BUG_ON(dcache_page == NULL);
	
	if(!bitmap)
		return;
	
	dest = page_address(dcache_page->page);
	source = page_address(page);
	
	source += (skip_blk<<SECTOR_SHIFT);
	
	for(i=0; i<SECTORS_ONE_PAGE; i++){
		if(bitmap & (0x01<<i)){
			memcpy(dest, source, SECTOR_SIZE);
			source += SECTOR_SIZE;
		}
		dest += SECTOR_SIZE;
	}
	
}

/*
* copy data to read from cache
*/
static void copy_dcache_to_pages(struct dcache_page *dcache_page, struct page* page, 
	unsigned char bitmap, unsigned int skip_blk)
{
	char *dest, *source;
	unsigned int i=0;
	
	BUG_ON(page  == NULL);
	BUG_ON(dcache_page == NULL);
	
	if(!bitmap)
		return;
	
	dest = page_address(page);
	source = page_address(dcache_page->page);
	
	source += (skip_blk<<SECTOR_SHIFT);
	
	for(i=0; i<SECTORS_ONE_PAGE; i++){
		if(bitmap & (0x01<<i)){
			memcpy(dest, source, SECTOR_SIZE);
			source += SECTOR_SIZE;
		}
		dest += SECTOR_SIZE;
	}
}

static int dcache_add_page(struct dcache *dcache,  struct dcache_page* dcache_page)
{
	int error;

	error = radix_tree_preload(GFP_KERNEL & ~__GFP_HIGHMEM);
	if (error == 0) {
		spin_lock_irq(&dcache->tree_lock);
		error = radix_tree_insert(&dcache->page_tree, dcache_page->index, dcache_page);
		spin_unlock_irq(&dcache->tree_lock);

		radix_tree_preload_end();
	}else
		cache_err("Error occurs when preload cache!\n");
	
	return error;
}

/*
* find the exact page pointer, or return NULL 
*/
static struct dcache_page* dcache_find_get_page(struct dcache *dcache, pgoff_t index)
{
	struct dcache_page * dcache_page;
	void **pagep;
	
	rcu_read_lock();
repeat:
	dcache_page = NULL;
	pagep = radix_tree_lookup_slot(&dcache->page_tree, index);
	if (pagep) {
		dcache_page = radix_tree_deref_slot(pagep);
		if (unlikely(!dcache_page))
			goto out;
		if (radix_tree_deref_retry(dcache_page))
			goto repeat;
		if (unlikely(dcache_page != *pagep)) {
			cache_warn("page has been moved.\n");
			goto repeat;
		}
	}
out:
	rcu_read_unlock();

	return dcache_page;

}

/*
* sync dirty pages, clean dirty bitmap 
*/
int dcache_clean_page(struct dcache * dcache, pgoff_t index)
{
	struct dcache_page *dcache_page;
again:
	dcache_page = dcache_find_get_page(dcache, index);
	if(!dcache_page){
		cache_dbg("page to delete is not found, index = %ld\n", index);
		return 0;
	}
	cache_dbg("Write out one page, index = %ld\n", index);
	lock_page(dcache_page->page);
	if(dcache_page->index !=index ||dcache_page->dcache !=dcache) {
		unlock_page(dcache_page->page);
		goto again;
	}
	
	dcache_page->dirty_bitmap = 0x00;
	lru_add_page(dcache_page);
	atomic_dec(&dcache->dirty_pages);
	
	unlock_page(dcache_page->page);

	return 0;
}

/*
* bitmap is 7-0, Notice the sequence of bitmap
*/
static unsigned char get_bitmap(sector_t lba_off, u32 num)
{
	unsigned char a, b;
	unsigned char bitmap = 0xff;
	
	if((lba_off == 0 && num == SECTORS_ONE_PAGE))
		return bitmap;
	
	a = 0xff << lba_off;
	b = 0xff >>(SECTORS_ONE_PAGE-(lba_off + num));
	bitmap = (a & b);

	return bitmap;
}

static int  dcache_write_page(void *dcachep, pgoff_t page_index, struct page* page, 
		unsigned char bitmap, unsigned int current_bytes, unsigned int skip_blk)
{
	struct dcache *dcache = (struct dcache *)dcachep;
	struct dcache_page *dcache_page;
	int err=0;

again:
	dcache_page= dcache_find_get_page(dcache, page_index);

	if(dcache_page == NULL){	/* Write Miss */
		dcache_page=dcache_write_get_free_page(dcache);
		dcache_page->dcache=dcache;
		dcache_page->index=page_index;

		err=dcache_add_page(dcache, dcache_page);
		if(unlikely(err)){
			if(err==-EEXIST){
				cache_dbg("This page exists, try again!\n");
				dcache_page->dcache= NULL;
				dcache_page->index= -1;
				unlock_page(dcache_page->page);
				lru_set_page_back(dcache_page);
				err = 0;
				goto again;
			}
			unlock_page(dcache_page->page);
			lru_set_page_back(dcache_page);
			cache_err("Error occurs when read miss, err = %d\n", err);
			return err;
		}
		
		copy_pages_to_dcache(page, dcache_page, bitmap, skip_blk, current_bytes);

		dcache_page->valid_bitmap |= bitmap;
		dcache_page->dirty_bitmap |=bitmap;
		dcache_page->dirtied_when = jiffies;
		
		dcache_set_page_tag(dcache_page, DCACHE_TAG_DIRTY);

		atomic_inc(&dcache->total_pages);
		atomic_inc(&dcache->dirty_pages);

		lru_write_miss_handle(dcache_page);
		unlock_page(dcache_page->page);
		
		if(dcache->owner && over_bground_thresh(dcache))
			wakeup_cache_flusher(dcache);
	}else{		/* Write Hit */

		lock_page(dcache_page->page);
		
		if(unlikely(dcache_page->dcache !=dcache || dcache_page->index != page_index)){
			cache_dbg("write page have been changed.\n");
			unlock_page(dcache_page->page);
			goto again;
		}
		
		wait_on_page_writeback(dcache_page->page);
		BUG_ON(PageWriteback(dcache_page->page));
		
		copy_pages_to_dcache(page, dcache_page, bitmap, skip_blk, current_bytes);

		dcache_page->valid_bitmap |= bitmap;
		if(dcache_page->dirty_bitmap == 0x00){
			dcache_set_page_tag(dcache_page, DCACHE_TAG_DIRTY);
			atomic_inc(&dcache->dirty_pages);
			dcache_page->dirtied_when = jiffies;
			if(dcache->owner && over_bground_thresh(dcache))
				wakeup_cache_flusher(dcache);
		}
		dcache_page->dirty_bitmap |= bitmap;

		lru_write_hit_handle(dcache_page);
		unlock_page(dcache_page->page);
	}
	return err;
}

/*
* copy data from cache page to page of request
*/
static void dcache_read_page(struct dcache_page * dcache_page, struct page** pages, 
		unsigned int pg_cnt, u32 size, loff_t ppos)
{
	int cache_sector_index = dcache_page->index << SECTORS_ONE_PAGE_SHIFT;
	int sector_start = ppos >> SECTOR_SHIFT;
	int sector_end = (ppos + size -1) >> SECTOR_SHIFT;
	int sector_off;
	unsigned char bitmap;
	unsigned int skip_blk;
	int done = 0;
	
	pgoff_t page_index;
	sector_t alba, lba_off;
	u32 sector_num;
	
	/* read portion of page */
	if(cache_sector_index < sector_start) {
		skip_blk = sector_start - cache_sector_index;
		sector_off = 0;
		page_index = 0;
		lba_off = skip_blk;
		
		sector_num = SECTORS_ONE_PAGE - (lba_off % SECTORS_ONE_PAGE);
		if(sector_end < sector_start + sector_num){
			sector_num = sector_end - sector_start + 1;
		}
		
		bitmap = get_bitmap(sector_off, sector_num);
		copy_dcache_to_pages(dcache_page, pages[page_index], bitmap, skip_blk);
	}else{
		skip_blk = 0;
		sector_off = cache_sector_index - sector_start;

		while(!done){
			page_index = sector_off >> SECTORS_ONE_PAGE_SHIFT;
			alba = page_index << SECTORS_ONE_PAGE_SHIFT;
			lba_off = sector_off -alba;
			sector_num = SECTORS_ONE_PAGE - (lba_off % SECTORS_ONE_PAGE);
			if(sector_num > SECTORS_ONE_PAGE - skip_blk)
				sector_num = SECTORS_ONE_PAGE - skip_blk;
			if(sector_end < cache_sector_index + skip_blk + sector_num) { 
				sector_num = sector_end - cache_sector_index - skip_blk + 1;
				done = 1;
			}
			bitmap = get_bitmap(lba_off, sector_num);
			copy_dcache_to_pages(dcache_page, pages[page_index], bitmap, skip_blk);
			skip_blk += sector_num;
			sector_off += sector_num;
			if(skip_blk >= SECTORS_ONE_PAGE)
				break;
		}
		
	}
}

/**
* according to size of request, read all the data one time
*/
static int _dcache_read(void *dcachep, struct page **pages, u32 pg_cnt, u32 size, loff_t ppos, enum request_from from)
{
	struct dcache *dcache = (struct dcache *)dcachep;
	struct dcache_page **dcache_pages;
	int err = 0;
	int index;
	pgoff_t page_start, page_end;
	
	page_start = ppos >> PAGE_SHIFT;
	page_end =  (ppos +size -1) >> PAGE_SHIFT;
	index = page_start;
	
	dcache_pages = kzalloc((page_end - page_start + 1) * sizeof(struct dcache_page *), GFP_KERNEL);
	if(!dcache_pages)
		return -ENOMEM;
	
	while(index <= page_end) {
		struct dcache_page *dcache_page;
		int i, page_to_read = 0;

		for(; index<= page_end; index++) {
again:
			dcache_page= dcache_find_get_page(dcache, index);

			if(dcache_page) {	/* Read Hit */
				
				if(!trylock_page(dcache_page->page)){
					if(dcache_page->dcache == dcache && dcache_page->index == index) {
						if(unlikely(current->plug))
							cache_err("plug is not flushed.\n");
						lock_page(dcache_page->page);
					}else	{
						cache_dbg("read page have been changed.\n");
						goto again;
					}
				}
				if(dcache_page->dcache != dcache || dcache_page->index != index){
					cache_dbg("read page have been changed.\n");
					unlock_page(dcache_page->page);
					goto again;
				}
				
				/* if page to read is invalid, read from disk */
				if(dcache_page->valid_bitmap != 0xff) {
					cache_ignore("data to read isn't 0xff, try to read from disk.\n");
					
					err=dcache_check_read_blocks(dcache_page, dcache_page->valid_bitmap, 0xff);
					if(unlikely(err)) {
						cache_err("Error occurs when read missed blocks.\n");
						unlock_page(dcache_page->page);
						kfree(dcache_pages);
						return err;
					}
					dcache_page->valid_bitmap = 0xff;
				}

				dcache_read_page(dcache_page, pages, pg_cnt, size, ppos);
				lru_read_hit_handle(dcache_page);
				unlock_page(dcache_page->page);
			}else{	/* Read Miss */
				/*if(page_to_read){
					dcache_page = dcache_read_get_free_page(dcache, 0);
					if(!dcache_page)
						break;
				}else
				*/	dcache_page = dcache_read_get_free_page(dcache, 1);
				
				dcache_page->dcache=dcache;
				dcache_page->index=index;

				err=dcache_add_page(dcache, dcache_page);
				if(err){
					if(err==-EEXIST){
						cache_dbg("This page exists, try again!\n");
						dcache_page->dcache= NULL;
						dcache_page->index= -1;
						unlock_page(dcache_page->page);
						lru_set_page_back(dcache_page);
						err = 0;
						goto again;
					}
					cache_err("Error occurs when read miss, err = %d\n", err);
					unlock_page(dcache_page->page);
					lru_set_page_back(dcache_page);
					kfree(dcache_pages);
					return err;
				}
				dcache_pages[page_to_read++] = dcache_page;
			}
		}

		dcache_read_mpage(dcache, dcache_pages, page_to_read);

		for(i=0; i < page_to_read; i++) {
			dcache_read_page(dcache_pages[i], pages, pg_cnt, size, ppos);
			lru_read_miss_handle(dcache_pages[i]);
			unlock_page(dcache_pages[i]->page);
			atomic_inc(&dcache->total_pages);
		}
	}

	kfree(dcache_pages);
	return err;
}

/*
* sync data with peer first, it can improve efficiency, 
* but may result in slave's starvation for clean pages.
*/
int _dcache_write(void *dcachep, struct page **pages, u32 pg_cnt, u32 size, loff_t ppos, enum request_from from)
{
	struct dcache *dcache = (struct dcache *)dcachep;
	struct cache_request * req;
	u32 tio_index = 0;
	u32 sector_num;
	int err = 0;
	unsigned char bitmap;
	u32 real_size = size;
	loff_t real_ppos = ppos;
	sector_t lba, alba, lba_off;
	pgoff_t page_index;
	
	if(from == REQUEST_FROM_OUT && peer_is_good) {
		err = cache_send_dblock(dcache->conn, pages, pg_cnt, real_size, real_ppos>>SECTOR_SHIFT, &req);
		if(err){
			cache_err("Send data block fails.\n");
			return err;
		}
	}
	
	while (size && tio_index < pg_cnt) {
			unsigned int current_bytes, bytes = PAGE_SIZE;
			unsigned int  skip_blk=0;

			if (bytes > size)
				bytes = size;

			while(bytes>0){
				lba=ppos>>SECTOR_SHIFT;
				page_index=lba>>SECTORS_ONE_PAGE_SHIFT;
				alba=page_index<<SECTORS_ONE_PAGE_SHIFT;
				lba_off=lba-alba;
				
				current_bytes=PAGE_SIZE-(lba_off<<SECTOR_SHIFT);
				if(current_bytes>bytes)
					current_bytes=bytes;
				sector_num=current_bytes>>SECTOR_SHIFT;
				bitmap=get_bitmap(lba_off, sector_num);

				err = dcache_write_page(dcache, page_index, pages[tio_index],
					bitmap, current_bytes, skip_blk);
				if(unlikely(err))
					return err;
				bytes-=current_bytes;
				size -=current_bytes;
				skip_blk+=sector_num;
				ppos+=current_bytes;
			}
			
			tio_index++;
	}

	if(from == REQUEST_FROM_OUT && peer_is_good) {
		cache_dbg("wait for data ack.\n");
		if(wait_for_completion_timeout(&req->done, HZ*15) == 0) {  
			cache_warn("timeout when wait for data ack.\n");
			cache_request_dequeue(req);
		}else
			kmem_cache_free(cache_request_cache, req);
		cache_dbg("ok, get data ack, go on!\n");
	}
/*
	if(dcache->owner)
		decrease_dirty_ratio(dcache);
*/
	return err;
}

/**
* The global interface for read disk cache
*/
int dcache_read(void *dcachep, struct page **pages, u32 pg_cnt, u32 size, loff_t ppos)
{
	int err;
	
	BUG_ON(ppos % SECTOR_SIZE != 0);
	err = _dcache_read(dcachep, pages, pg_cnt, size, ppos, REQUEST_FROM_OUT);
	if(err)
		cache_err("read err, err is %d\n", err);
	
	return err;
}

/**
* The global interface for write disk cache
*/
int dcache_write(void *dcachep, struct page **pages, u32 pg_cnt, u32 size, loff_t ppos)
{
	int err;
	
	BUG_ON(ppos % SECTOR_SIZE != 0);
	err = _dcache_write(dcachep, pages, pg_cnt, size, ppos, REQUEST_FROM_OUT);
	if(err)
		cache_err("write err, err is %d\n", err);

	return err;
}

/**
* it's called when add one volume
*/
void* init_volume_dcache(const char *path, int owner, int port)
{
	struct dcache *dcache;
	int vol_owner;
	
	dcache=kzalloc(sizeof(*dcache),GFP_KERNEL);
	if(!dcache)
		return NULL;

	memcpy(&dcache->path, path, strlen(path));

	dcache->bdev = blkdev_get_by_path(path, 
		(FMODE_READ |FMODE_WRITE), THIS_MODULE);
	if(IS_ERR(dcache->bdev)){
		dcache->bdev = NULL;
		cache_err("Error occurs when get block device.\n");
		kfree(dcache);
		return NULL;
	}
	
	spin_lock_init(&dcache->tree_lock);
	INIT_RADIX_TREE(&dcache->page_tree, GFP_ATOMIC);

	setup_timer(&dcache->wakeup_timer, cache_wakeup_timer_fn, (unsigned long)dcache);
	dcache->task = NULL;
	dcache->writeback_index = 0;
	atomic_set(&dcache->dirty_pages, 0);
	atomic_set(&dcache->total_pages, 0);
	
	mutex_lock(&dcache_list_lock);
	list_add_tail(&dcache->list, &dcache_list);
	mutex_unlock(&dcache_list_lock);

	if(((machine_type == MA) && (owner == MA)) ||  \
		((machine_type == MB) && (owner == MB)))
	{
		vol_owner = true;
	}
	if(((machine_type == MA) && (owner == MB)) ||   \
	       ((machine_type == MB) && (owner == MA)))
	{
		vol_owner = false;
	}
	
	cache_info("for %s: echo_host = %s  echo_peer = %s  echo_port = %d  owner = %s \n", \
				dcache->path, echo_host, echo_peer, port, (vol_owner ? "true" : "false"));

	memcpy(dcache->inet_addr, echo_host, strlen(echo_host));
	memcpy(dcache->inet_peer_addr, echo_peer, strlen(echo_peer));
	dcache->port = port;
	dcache->owner = vol_owner;
	dcache->origin_owner = vol_owner;

	//dcache->conn = cache_conn_init(dcache);

	dcache_total_volume++;
	
	return (void *)dcache;
}

/**
* It's called when delete one volume
*/
void del_volume_dcache(void *volume_dcachep)
{
	struct dcache *dcache=(struct dcache *)volume_dcachep;
	if(!dcache)
		return;
	
	mutex_lock(&dcache_list_lock);
	list_del_init(&dcache->list);
	mutex_unlock(&dcache_list_lock);

	if(dcache->task){
		kthread_stop(dcache->task);
		wait_for_completion(&dcache->wb_completion);
	}

	if(dcache->owner && !peer_is_good)
		writeback_single(dcache, DCACHE_WB_SYNC_ALL, LONG_MAX, false);

	//cache_conn_exit(dcache);
	
	dcache_delete_radix_tree(dcache);
	
	blkdev_put(dcache->bdev, (FMODE_READ |FMODE_WRITE));
	cache_dbg("OK, block device %s is released.\n", dcache->path);

	dcache_total_volume--;

	kfree(dcache);
}

EXPORT_SYMBOL_GPL(dcache_write);
EXPORT_SYMBOL_GPL(dcache_read);
EXPORT_SYMBOL_GPL(del_volume_dcache);
EXPORT_SYMBOL_GPL(init_volume_dcache);

static int dcache_request_init(void)
{
	cache_request_cache = KMEM_CACHE(cache_request, 0);
	return  cache_request_cache ? 0 : -ENOMEM;
}

static void dcache_global_exit(void)
{

	unregister_chrdev(ctr_major_cache, dcache_ctr_name);
	
	cache_procfs_exit();

	lru_shrink_thread_exit();

	wb_thread_exit();

	if(cache_request_cache)
		kmem_cache_destroy(cache_request_cache);

	cio_exit();
	
	cache_info("Unload iSCSI Cache Module. All right \n");
}

static int dcache_global_init(void)
{
	int err = 0;
	unsigned int i = 0;
	phys_addr_t reserve_phys_addr;
	char *dcache_struct_addr, *dcache_data_addr;
	unsigned int dcache_page_size = sizeof(struct dcache_page);

	BUG_ON(PAGE_SIZE != 4096);
	BUG_ON(iet_mem_size % PAGE_SIZE);
	BUG_ON((long)iet_mem_virt % PAGE_SIZE);
//	BUG_ON(reserve_phys_addr != iscsi_mem_goal);

	reserve_phys_addr=virt_to_phys(iet_mem_virt);

	cache_info("iSCSI Cache Module  version %s \n", CACHE_VERSION);
	cache_info("reserved_virt_addr = 0x%lx reserved_phys_addr = 0x%lx size=%dMB \n", 
		(unsigned long)iet_mem_virt, (unsigned long)reserve_phys_addr, (iet_mem_size>>20));
	
	cache_dbg("The size of struct dcache_page is %d.\n", dcache_page_size);

	if ((ctr_major_cache= register_chrdev(0, dcache_ctr_name, &dcache_ctr_fops)) < 0) {
		cache_alert("failed to register the control device %d\n", ctr_major_cache);
		err = ctr_major_cache;
		goto error;
	}
	
	if((err = dcache_request_init())< 0)
		goto error;
	
	if((err = cio_init())< 0)
		goto error;

	if((err = lru_list_init()) < 0)
		goto error;
	
	INIT_LIST_HEAD(&dcache_list);
	mutex_init(&dcache_list_lock);
	
	/* wait queue for get free page */
	INIT_LIST_HEAD(&cache_wait_queue_head);
	spin_lock_init(&cache_wait_queue_lock);

	dcache_struct_addr = iet_mem_virt;
	dcache_data_addr = iet_mem_virt + iet_mem_size -PAGE_SIZE;
	BUG_ON((long)dcache_data_addr%PAGE_SIZE);
	
	while(dcache_data_addr >=dcache_struct_addr+dcache_page_size) {
		struct dcache_page *dcache_page;
		struct page *page;
		
		page = virt_to_page(dcache_data_addr);
		dcache_page=(struct dcache_page *)dcache_struct_addr;
		
		dcache_page->dcache = NULL;
		dcache_page->index= -1; 
		dcache_page->dirty_bitmap=dcache_page->valid_bitmap=0x00;
		dcache_page->page=page;
		page->mapping = (struct address_space *)dcache_page;
		ClearPageReferenced(page);
		ClearPageActive(page);
		
		dcache_page->flag=0;
		inactive_add_page(dcache_page);

		dcache_struct_addr += dcache_page_size;
		dcache_data_addr -= PAGE_SIZE;
		i++;
	}
	
	dcache_total_pages = i;
	cache_info("The cache includes %ld pages.\n", dcache_total_pages);
	
	if((err=wb_thread_init()) < 0)
		goto error;

	if((err=cache_procfs_init()) < 0)
		goto error;

	return err;
error:
	cache_alert("[Alert] Cache Initialize failed.\n");
	dcache_global_exit();
	return err;
}

module_init(dcache_global_init);
module_exit(dcache_global_exit);

MODULE_VERSION(CACHE_VERSION);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disk Cache");
MODULE_AUTHOR("Hongjun Dai <dahogn@sdu.edu.cn>");
MODULE_AUTHOR("Hearto <hearto1314@gmail.com>");
MODULE_AUTHOR("Bing Sun <b.y.sun.cn@gmail.com>");

