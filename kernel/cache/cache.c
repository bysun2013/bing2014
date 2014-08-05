/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
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

#include "cache.h"
#include "cache_wb.h"
#include "cache_lru.h"

#define SECTOR_SHIFT	9
#define SECTOR_SIZE	512
#define SECTORS_ONE_PAGE	8
#define SECTORS_ONE_PAGE_SHIFT 3

bool peer_is_good = true;

static int ctr_major_cache;
static char ctr_name_cache[] = "ietctl_cache";
extern struct file_operations ctr_fops_cache;


extern int cache_procfs_init(void);
extern void cache_procfs_exit(void);

/* param of reserved memory at boot */
extern unsigned int iet_mem_size;
extern char *iet_mem_virt;
/* preferred starting address of the region */
//extern unsigned long iscsi_mem_goal; 


unsigned long iscsi_cache_total_pages;
unsigned int iscsi_cache_total_volume;

struct kmem_cache *cache_request_cache;

/* list all of caches, which represent volumes. */
struct list_head iscsi_cache_list;
struct mutex iscsi_cache_list_lock;

static int add_page_to_radix(struct iscsi_cache *iscsi_cache, struct iscsi_cache_page *page, gfp_t gfp_mask)
{
	int error;

	error = radix_tree_preload(gfp_mask & ~__GFP_HIGHMEM);
	if (error == 0) {
		spin_lock_irq(&iscsi_cache->tree_lock);
		error = radix_tree_insert(&iscsi_cache->page_tree, page->index, page);
		spin_unlock_irq(&iscsi_cache->tree_lock);
		
		if (unlikely(error)) {
			cache_dbg("something is wrong when add page to cache, it's perhaps not fault.\n");
		}
		radix_tree_preload_end();
	}else
		cache_err("Error occurs when preload cache!\n");
	
	return error;
}

static void del_page_from_radix(struct iscsi_cache_page *page)
{
	struct  iscsi_cache *iscsi_cache = page->iscsi_cache;
	
	spin_lock_irq(&iscsi_cache->tree_lock);
	radix_tree_delete(&iscsi_cache->page_tree, page->index);
	page->iscsi_cache = NULL;
	spin_unlock_irq(&iscsi_cache->tree_lock);
}

/*
* find the exact page pointer, or return NULL 
*/
static struct iscsi_cache_page *find_page_from_radix(struct iscsi_cache *iscsi_cache, sector_t index)
{
	
	struct iscsi_cache_page * iscsi_page;
	void **pagep;
	
	cond_resched();
	
	rcu_read_lock();
repeat:
	iscsi_page = NULL;
	pagep = radix_tree_lookup_slot(&iscsi_cache->page_tree, index);
	if (pagep) {
		iscsi_page = radix_tree_deref_slot(pagep);
		if (unlikely(!iscsi_page))
			goto out;
		if (radix_tree_deref_retry(iscsi_page))
			goto repeat;
		if (unlikely(iscsi_page != *pagep)) {
			cache_warn("page has been moved.\n");
			goto repeat;
		}
	}
out:
	rcu_read_unlock();

	return iscsi_page;

}

static struct iscsi_cache_page* cache_get_free_page(struct iscsi_cache * iscsi_cache)
{
	struct iscsi_cache_page *iscsi_page=NULL;
	
again:
	check_list_status();
	iscsi_page = lru_alloc_page();
	if(iscsi_page){
		iscsi_page->valid_bitmap = 0x00;
		if(iscsi_page->iscsi_cache){
			atomic_dec(&iscsi_page->iscsi_cache->total_pages);
			del_page_from_radix(iscsi_page);
		}
		return iscsi_page;
	}else{
		cache_err("Cache is used up! Wait for write back...\n");
		wake_up_process(iscsi_wb_forker);
		if(iscsi_cache->owner)
			writeback_single(iscsi_cache, ISCSI_WB_SYNC_NONE, 1024);
		else{
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ/10);
			__set_current_state(TASK_RUNNING);
		}
		goto again;
	}
	
	return NULL;
}

/*
* copy data to wrote into cache
*/
static void copy_tio_to_cache(struct page* page, struct iscsi_cache_page *iscsi_page, 
	char bitmap, unsigned int skip_blk, unsigned int bytes)
{
	char *dest, *source;
	unsigned int i=0;
	
	BUG_ON(page == NULL);
	BUG_ON(iscsi_page == NULL);
	
	if(!bitmap)
		return;
	
	dest = page_address(iscsi_page->page);
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
static void copy_cache_to_tio(struct iscsi_cache_page *iscsi_page, struct page* page, 
	char bitmap, unsigned int skip_blk, unsigned int bytes)
{
	char *dest, *source;
	unsigned int i=0;
	
	BUG_ON(page  == NULL);
	BUG_ON(iscsi_page == NULL);
	
	if(!bitmap)
		return;
	
	dest = page_address(page);
	source = page_address(iscsi_page->page);
	
	dest+=(skip_blk<<SECTOR_SHIFT);
	
	for(i=0; i<SECTORS_ONE_PAGE; i++){
		if(bitmap & (0x01<<i)){
			memcpy(dest, source, SECTOR_SIZE);
			dest+=SECTOR_SIZE;
		}
		source+=SECTOR_SIZE;
	}

}

static int cache_add_page(struct iscsi_cache *iscsi_cache,  struct iscsi_cache_page* iscsi_page)
{
	int error;

	error = add_page_to_radix(iscsi_cache, iscsi_page, GFP_KERNEL);

	return error;
}

static struct iscsi_cache_page* cache_find_get_page(struct iscsi_cache *iscsi_cache, pgoff_t index)
{

	struct iscsi_cache_page * iscsi_page;

	iscsi_page = find_page_from_radix(iscsi_cache, index);
	
	return iscsi_page;
}

/* Lock strategy is not good, used to sync dirty pages. */
int cache_clean_page(struct iscsi_cache * iscsi_cache, pgoff_t index)
{
	struct iscsi_cache_page *iscsi_page;
again:
	iscsi_page = find_page_from_radix(iscsi_cache, index);
	if(!iscsi_page){
		cache_dbg("Write out one page, not found, index = %ld\n", index);
		return 0;
	}
	cache_dbg("Write out one page, index = %ld\n", index);
	lock_page(iscsi_page->page);
	if(iscsi_page->index !=index ||iscsi_page->iscsi_cache !=iscsi_cache){
		unlock_page(iscsi_page->page);
		goto again;
	}
	
	iscsi_page->dirty_bitmap = 0x00;
	lru_add_page(iscsi_page);
	atomic_dec(&iscsi_cache->dirty_pages);
	
	unlock_page(iscsi_page->page);

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

static int _iscsi_read_from_cache(void *iscsi_cachep, pgoff_t page_index, struct page* page, 
		char bitmap, unsigned int current_bytes, unsigned int skip_blk)
{
	struct iscsi_cache * iscsi_cache = (struct iscsi_cache *)iscsi_cachep;
	struct iscsi_cache_page *iet_page;
	int err=0;
	
again:
	iet_page= cache_find_get_page(iscsi_cache, page_index);

	if(iet_page) {	/* Read Hit */
		lock_page(iet_page->page);
		
		if(iet_page->iscsi_cache !=iscsi_cache || iet_page->index != page_index) {
			cache_dbg("read page have been changed.\n");
			unlock_page(iet_page->page);
			goto again;
		}
		/* if data to read is invalid, read from disk */
		if(unlikely((iet_page->valid_bitmap & bitmap) != bitmap)) {
			cache_dbg("data to read is invalid, Read from disk\n");
			
			err=cache_check_read_blocks(iet_page, iet_page->valid_bitmap, bitmap);
			if(unlikely(err)){
				cache_err("Error occurs when read missed blocks.\n");
				unlock_page(iet_page->page);
				return err;
			}
			iet_page->valid_bitmap = iet_page->valid_bitmap | bitmap;
		}
		
		copy_cache_to_tio(iet_page, page, bitmap, skip_blk, current_bytes);

		lru_read_hit_handle(iet_page);
		unlock_page(iet_page->page);
	}else{	/* Read Miss, no page */
		iet_page=cache_get_free_page(iscsi_cache);
		
		iet_page->iscsi_cache=iscsi_cache;
		iet_page->index=page_index;

		err=cache_add_page(iscsi_cache, iet_page);
		if(unlikely(err)){
			if(err==-EEXIST){
				cache_dbg("This page exists, try again!\n");
				iet_page->iscsi_cache= NULL;
				iet_page->index= -1;
				lru_set_page_back(iet_page);
				unlock_page(iet_page->page);
				goto again;
			}
			lru_set_page_back(iet_page);
			cache_err("Error occurs when read, but reason is not clear.\n");
			unlock_page(iet_page->page);
			return err;
		}

		cache_rw_page(iet_page, READ);
		
		copy_cache_to_tio(iet_page, page,  bitmap, skip_blk, current_bytes);
		iet_page->valid_bitmap =0xff;
		
		lru_read_miss_handle(iet_page);
		unlock_page(iet_page->page);
		
		atomic_inc(&iscsi_cache->total_pages);
	}
	return err;
}

static int  _iscsi_write_into_cache(void *iscsi_cachep, pgoff_t page_index, struct page* page, 
		char bitmap, unsigned int current_bytes, unsigned int skip_blk)
{
	struct iscsi_cache *iscsi_cache = (struct iscsi_cache *)iscsi_cachep;
	struct iscsi_cache_page *iet_page;
	int err=0;
		
again:
	iet_page= cache_find_get_page(iscsi_cache, page_index);

	if(iet_page == NULL){	/* Write Miss */
		iet_page=cache_get_free_page(iscsi_cache);
		
		iet_page->iscsi_cache=iscsi_cache;
		iet_page->index=page_index;

		err=cache_add_page(iscsi_cache, iet_page);
		if(unlikely(err)){
			if(err==-EEXIST){
				iet_page->iscsi_cache= NULL;
				iet_page->index= -1;
				lru_set_page_back(iet_page);
				unlock_page(iet_page->page);
				goto again;
			}
			lru_set_page_back(iet_page);
			cache_err("Error occurs when write, but reason is not clear.\n");
			unlock_page(iet_page->page);
			return err;
		}
		
		copy_tio_to_cache(page, iet_page, bitmap, skip_blk, current_bytes);

		iet_page->valid_bitmap |= bitmap;
		iet_page->dirty_bitmap |=bitmap;
		iet_page->dirtied_when = jiffies;
		
		iscsi_set_page_tag(iet_page, ISCSICACHE_TAG_DIRTY);

		atomic_inc(&iscsi_cache->total_pages);
		atomic_inc(&iscsi_cache->dirty_pages);

		lru_write_miss_handle(iet_page);
		unlock_page(iet_page->page);
		
		if(iscsi_cache->owner && over_bground_thresh(iscsi_cache))
			wakeup_cache_flusher(iscsi_cache);
		
		cache_dbg("WRITE MISS\n");
	}else{		/* Write Hit */

		lock_page(iet_page->page);
		
		if(unlikely(iet_page->iscsi_cache !=iscsi_cache || iet_page->index != page_index)){
			cache_dbg("write page have been changed.\n");
			unlock_page(iet_page->page);
			goto again;
		}
		
		wait_on_page_writeback(iet_page->page);
		BUG_ON(PageWriteback(iet_page->page));
		
		copy_tio_to_cache(page, iet_page, bitmap, skip_blk, current_bytes);

		iet_page->valid_bitmap |= bitmap;
		if(iet_page->dirty_bitmap == 0x00){
			iscsi_set_page_tag(iet_page, ISCSICACHE_TAG_DIRTY);
			atomic_inc(&iscsi_cache->dirty_pages);
			iet_page->dirtied_when = jiffies;
			if(iscsi_cache->owner && over_bground_thresh(iscsi_cache))
				wakeup_cache_flusher(iscsi_cache);
		}
		iet_page->dirty_bitmap |= bitmap;

		lru_write_hit_handle(iet_page);
		unlock_page(iet_page->page);
		cache_dbg("WRITE HIT\n");
	}
	return err;
}

static int _iscsi_read_cache(void *iscsi_cachep, struct page **pages, 
	u32 pg_cnt, u32 size, loff_t ppos, enum request_from from)
{
	struct iscsi_cache *iscsi_cache = (struct iscsi_cache *)iscsi_cachep;
	u32 tio_index = 0;
	u32 sector_num;
	int err = 0;
	char bitmap;

	sector_t lba, alba, lba_off;
	pgoff_t page_index;

	/* Main processing loop */
	while (size && tio_index < pg_cnt) {
			unsigned int current_bytes, bytes = PAGE_SIZE;
			unsigned int  skip_blk = 0;

			if (bytes > size)
				bytes = size;

			while(bytes>0){
				lba = ppos>>SECTOR_SHIFT;
				page_index = lba>>SECTORS_ONE_PAGE_SHIFT;
				alba = page_index<<SECTORS_ONE_PAGE_SHIFT;
				lba_off = lba-alba;
				
				cache_dbg("READ ppos=%lld, LBA=%lu, page num=%lu\n", 
					ppos, lba, (unsigned long)page_index);
				
				current_bytes = PAGE_SIZE-(lba_off<<SECTOR_SHIFT);
				if(current_bytes>bytes)
					current_bytes=bytes;
				sector_num = current_bytes>>SECTOR_SHIFT;
				bitmap = get_bitmap(lba_off, sector_num);

				_iscsi_read_from_cache(iscsi_cache, page_index, pages[tio_index],
					bitmap, current_bytes, skip_blk);
				
				bytes -= current_bytes;
				size -= current_bytes;
				skip_blk += sector_num;
				ppos += current_bytes;
			}
			
			tio_index++;
	}
	return err;
}

static int _iscsi_write_cache(void *iscsi_cachep, struct page **pages, 
	u32 pg_cnt, u32 size, loff_t ppos, enum request_from from)
{
	struct iscsi_cache *iscsi_cache = (struct iscsi_cache *)iscsi_cachep;
	struct cache_request * req;
	u32 tio_index = 0;
	u32 sector_num;
	int err = 0;
	char bitmap;
	u32 real_size = size, real_ppos = ppos;
	sector_t lba, alba, lba_off;
	pgoff_t page_index;
	
	/* Main processing loop */
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
				
				cache_dbg("WRITE ppos=%lld, LBA=%lu, page num=%lu\n", 
					ppos, lba, (unsigned long)page_index);
				
				current_bytes=PAGE_SIZE-(lba_off<<SECTOR_SHIFT);
				if(current_bytes>bytes)
					current_bytes=bytes;
				sector_num=current_bytes>>SECTOR_SHIFT;
				bitmap=get_bitmap(lba_off, sector_num);

				_iscsi_write_into_cache(iscsi_cache, page_index, pages[tio_index],
					bitmap, current_bytes, skip_blk);
				
				bytes-=current_bytes;
				size -=current_bytes;
				skip_blk+=sector_num;
				ppos+=current_bytes;
			}
			
			tio_index++;
	}
	/*
	if(iscsi_cache->owner && peer_is_good){
		int try = 5;
		cache_send_dblock(iscsi_cache->conn, pages, pg_cnt, real_size, real_ppos>>9, &req);
		cache_dbg("wait for data ack.\n");
		if(wait_for_completion_timeout(&req->done, HZ*10) == 0){
			cache_warn("timeout when wait for data ack.\n");
			cache_request_dequeue(req);
		}else
			kmem_cache_free(cache_request_cache, req);
		cache_dbg("ok, get data ack, go on!\n");
	}*/
	return err;
}

int iscsi_read_cache(void *iscsi_cachep, struct page **pages, u32 pg_cnt, u32 size, loff_t ppos)
{
	int err;
	
	err = _iscsi_read_cache(iscsi_cachep, pages, pg_cnt, size, ppos, REQUEST_FROM_OUT);

	return err;
}

int iscsi_write_cache(void *iscsi_cachep, struct page **pages, u32 pg_cnt, u32 size, loff_t ppos)
{
	int err;
	
	err = _iscsi_write_cache(iscsi_cachep, pages, pg_cnt, size, ppos, REQUEST_FROM_OUT);

	return err;
}

/*
* it's called when add one volume
*/
void* init_iscsi_cache(const char *path, int owner, int port)
{
	struct iscsi_cache *iscsi_cache;
	int vol_owner;
	
	iscsi_cache=kzalloc(sizeof(*iscsi_cache),GFP_KERNEL);
	if(!iscsi_cache)
		return NULL;

	memcpy(&iscsi_cache->path, path, strlen(path));

	iscsi_cache->bdev = blkdev_get_by_path(path, 
		(FMODE_READ |FMODE_WRITE), THIS_MODULE);
	if(IS_ERR(iscsi_cache->bdev)){
		iscsi_cache->bdev = NULL;
		cache_err("Error occurs when get block device.\n");
		kfree(iscsi_cache);
		return NULL;
	}
	
	spin_lock_init(&iscsi_cache->tree_lock);
	INIT_RADIX_TREE(&iscsi_cache->page_tree, GFP_ATOMIC);

	setup_timer(&iscsi_cache->wakeup_timer, cache_wakeup_timer_fn, (unsigned long)iscsi_cache);
	iscsi_cache->task = NULL;
	atomic_set(&iscsi_cache->dirty_pages, 0);
	atomic_set(&iscsi_cache->total_pages, 0);
	
	mutex_lock(&iscsi_cache_list_lock);
	list_add_tail(&iscsi_cache->list, &iscsi_cache_list);
	mutex_unlock(&iscsi_cache_list_lock);

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
				iscsi_cache->path, echo_host, echo_peer, port, (vol_owner ? "true" : "false"));

	memcpy(iscsi_cache->inet_addr, echo_host, strlen(echo_host));
	memcpy(iscsi_cache->inet_peer_addr, echo_peer, strlen(echo_peer));
	iscsi_cache->port = port;
	iscsi_cache->owner = vol_owner;
	iscsi_cache->origin_owner = vol_owner;

	//iscsi_cache->conn = cache_conn_init(iscsi_cache);

	iscsi_cache_total_volume++;
	
	return (void *)iscsi_cache;
}

/* 
* It's called when delete one volume
*
* FIXME 
* In case memory leak, it's necessary to delete all the pages in the radix tree.
*/
void del_iscsi_cache(void *iscsi_cachep)
{
	struct iscsi_cache *iscsi_cache=(struct iscsi_cache *)iscsi_cachep;
	if(!iscsi_cache)
		return;
	
	mutex_lock(&iscsi_cache_list_lock);
	list_del_init(&iscsi_cache->list);
	mutex_unlock(&iscsi_cache_list_lock);

	if(iscsi_cache->task){
		kthread_stop(iscsi_cache->task);
		wait_for_completion(&iscsi_cache->wb_completion);
	}
	
	writeback_single(iscsi_cache, ISCSI_WB_SYNC_ALL, ULONG_MAX);

	//cache_conn_exit(iscsi_cache);

	blkdev_put(iscsi_cache->bdev, (FMODE_READ |FMODE_WRITE));
	cache_dbg("Good, release block device %s.\n", iscsi_cache->path);

	iscsi_cache_total_volume--;

	kfree(iscsi_cache);
}

EXPORT_SYMBOL_GPL(iscsi_write_cache);
EXPORT_SYMBOL_GPL(iscsi_read_cache);
EXPORT_SYMBOL_GPL(del_iscsi_cache);
EXPORT_SYMBOL_GPL(init_iscsi_cache);

static int cache_request_init(void)
{
	cache_request_cache = KMEM_CACHE(cache_request, 0);
	return  cache_request_cache ? 0 : -ENOMEM;
}

static void iscsi_global_cache_exit(void)
{

	unregister_chrdev(ctr_major_cache, ctr_name_cache);
	
	cache_procfs_exit();

	lru_shrink_thread_exit();

	wb_thread_exit();

	if(cache_request_cache)
		kmem_cache_destroy(cache_request_cache);

	cio_exit();
	
	cache_info("Unload iSCSI Cache Module. All right \n");
}

static int iscsi_global_cache_init(void)
{
	int err = 0;
	unsigned int i = 0;
	phys_addr_t reserve_phys_addr;
	char *iscsi_struct_addr, *iscsi_data_addr;
	unsigned int iscsi_struct_size = sizeof(struct iscsi_cache_page);

	BUG_ON(PAGE_SIZE > 4096);
	BUG_ON(iet_mem_size%PAGE_SIZE);
	BUG_ON((long)iet_mem_virt%PAGE_SIZE);
//	BUG_ON(reserve_phys_addr != iscsi_mem_goal);

	reserve_phys_addr=virt_to_phys(iet_mem_virt);

	cache_info("iSCSI Cache Module  version %s \n", CACHE_VERSION);
	cache_info("reserved_virt_addr = 0x%lx reserved_phys_addr = 0x%lx size=%dMB \n", 
		(unsigned long)iet_mem_virt, (unsigned long)reserve_phys_addr, (iet_mem_size/1024/1024));
	
	cache_dbg("The size of struct iscsi_cache_page is %d.\n", iscsi_struct_size);

	if ((ctr_major_cache= register_chrdev(0, ctr_name_cache, &ctr_fops_cache)) < 0) {
		cache_alert("failed to register the control device %d\n", ctr_major_cache);
		err = ctr_major_cache;
		goto error;
	}
	
	if((err=cache_request_init())< 0)
		goto error;
	
	if((err=cio_init())< 0)
		goto error;

	if((err=lru_list_init()) < 0)
		goto error;
	
	INIT_LIST_HEAD(&iscsi_cache_list);
	mutex_init(&iscsi_cache_list_lock);

	iscsi_struct_addr = iet_mem_virt;
	iscsi_data_addr = iet_mem_virt + iet_mem_size -PAGE_SIZE;
	BUG_ON((long)iscsi_data_addr%PAGE_SIZE);
	
	while(iscsi_data_addr >=iscsi_struct_addr+iscsi_struct_size){
		struct iscsi_cache_page *iscsi_page;
		struct page *page;
		
		page = virt_to_page(iscsi_data_addr);
		iscsi_page=(struct iscsi_cache_page *)iscsi_struct_addr;
		
		iscsi_page->iscsi_cache = NULL;
		iscsi_page->index= -1; 
		iscsi_page->dirty_bitmap=iscsi_page->valid_bitmap=0x00;
		iscsi_page->page=page;
		page->mapping = (struct address_space *)iscsi_page;
		ClearPageReferenced(page);
		ClearPageActive(page);
		
		iscsi_page->flag=0;
		//list_add_tail(&iscsi_page->lru_list, &lru);
		inactive_add_page(iscsi_page);

		iscsi_struct_addr += iscsi_struct_size;
		iscsi_data_addr -= PAGE_SIZE;
		i++;
	}
	
	iscsi_cache_total_pages = i;
	cache_info("The cache includes %ld pages.\n", iscsi_cache_total_pages);
	
	if((err=wb_thread_init()) < 0)
		goto error;

	if((err=cache_procfs_init()) < 0)
		goto error;

	return err;
error:
	cache_alert("[Alert] Cache Initialize failed.\n");
	iscsi_global_cache_exit();
	return err;
}

module_init(iscsi_global_cache_init);
module_exit(iscsi_global_cache_exit);

MODULE_VERSION(CACHE_VERSION);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("iSCSI Cache");
MODULE_AUTHOR("Bing Sun <b.y.sun.cn@gmail.com>");
