/*
 * Copyright (C) 2013-2014 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <asm/atomic.h>
#include <linux/blkdev.h>
#include <asm/page.h>
#include <linux/list.h>


#include "iscsi_dbg.h"
#include "iscsi.h"
#include "iscsi_cache.h"



/* param of reserved memory at boot*/
extern unsigned int iet_mem_size;
extern char *iet_mem_virt;

static struct task_struct *iet_wb_thread;

static struct kmem_cache *iet_page_cache;

/*LRU link all of pages and devices*/
static struct list_head lru;
static struct list_head wb;

spinlock_t		lru_lock;
spinlock_t		wb_lock;


/* bitmap is 7-0, Notice the sequence of bitmap*/
char get_bitmap(sector_t lba, u32 num){
	char bitmap=0;
	sector_t alba, lba_off;
	int i;
	
	alba=(lba>>3)<<3;
	lba_off=lba-alba;
	assert(lba_off+num<=8);
	for(i=0;i<num;i++){
		bitmap= bitmap | (1<<(lba_off+i));
	}
	return bitmap;
}
static int add_page_to_radix(struct iet_volume *lun, struct iet_cache_page *page, 
		gfp_t gfp_mask)
{
	int error;

	error = radix_tree_preload(gfp_mask & ~__GFP_HIGHMEM);
	if (error == 0) {

		spin_lock_irq(&lun->tree_lock);
		error = radix_tree_insert(&lun->page_tree, page->index, page);
		if (likely(!error)) {
			spin_unlock_irq(&lun->tree_lock);
		} else {
			page->volume = NULL;
			spin_unlock_irq(&lun->tree_lock);
			printk(KERN_ALERT"add_to_iet_rdix error 1!\n");
		}
		radix_tree_preload_end();
	}else
		printk(KERN_ALERT"add_to_iet_radix error 2!\n");

	return error;
}

static void del_page_from_radix(struct iet_cache_page *page)
{
	struct  iet_volume *volume = page->volume;
	
	spin_lock_irq(&volume->tree_lock);
	radix_tree_delete(&volume->page_tree, page->index);
	page->volume = NULL;
	spin_unlock_irq(&volume->tree_lock);
}

/* find the exact page pointer, or return NULL */
static struct iet_cache_page *find_page_from_radix(struct iet_volume *volume, sector_t index)
{
	
	struct iet_cache_page * iet_page;
	void **pagep;

	rcu_read_lock();
repeat:
	iet_page = NULL;
	pagep = radix_tree_lookup_slot(&volume->page_tree, index);
	if (pagep) {
		iet_page = radix_tree_deref_slot(pagep);
		if (unlikely(!iet_page))
			goto out;
		if (radix_tree_deref_retry(iet_page))
			goto repeat;

		/*
		 * Has the page moved?
		 */
		if (unlikely(iet_page != *pagep)) {
			printk(KERN_ALERT"Has the page moved.\n");
			BUG();
		}
//		printk(KERN_ALERT"iet_cache_find: success find the exact page frame.\n");
	}
out:
	rcu_read_unlock();

	return iet_page;

}

void add_to_lru_list(struct list_head *list)
{
	spin_lock(&lru_lock);
	list_add_tail(list, &lru);
	spin_unlock(&lru_lock);
}
void update_lru_list(struct list_head *list)
{
	spin_lock(&lru_lock);
	list_del_init(list);
	list_add_tail(list, &lru);
	spin_unlock(&lru_lock);
}

void add_to_wb_list(struct list_head *list)
{
	spin_lock(&wb_lock);
	list_add_tail(list, &wb);
	spin_unlock(&wb_lock);
}

struct iet_cache_page* get_wb_page(void)
{
	struct list_head *list=NULL;
	spin_lock(&wb_lock);
	if(!list_empty(&wb)){
		list=wb.next;
		list_del_init(list);
		spin_unlock(&wb_lock);
		return (list_entry(list, struct iet_cache_page,  wb_list));
	}
	spin_unlock(&wb_lock);
	return NULL;
}

/* the free page is isolated, NOT list to LRU */
struct iet_cache_page* iet_get_free_page(void)
{
	struct list_head *list, *tmp;
	struct iet_cache_page *iet_page=NULL;
	spin_lock(&lru_lock);
	
	list_for_each_safe(list, tmp, &lru){
		iet_page=list_entry(list, struct iet_cache_page, lru_list);
		assert(iet_page != NULL);
		if((iet_page->dirty_bitmap & 0xff) == 0){
			list_del_init(list);
			iet_page->valid_bitmap=0x00;
//			printk(KERN_ALERT"iet_cache_add: find a free iet_cache_page for use.\n");
			break;
		}
		iet_page=NULL;
	}
	spin_unlock(&lru_lock);

	if(iet_page==NULL){
		printk(KERN_ERR"BUG at %s:%d : iet cache page is used up! \n", __FILE__, __LINE__);
		BUG();
	}
	if(iet_page->volume){
		del_page_from_radix(iet_page);
		iet_page->volume=NULL;
	}
	
	return iet_page;
}

int copy_tio_to_page(struct page* page, struct iet_cache_page *iet_page, 
	char bitmap, unsigned int skip_blk, unsigned int bytes)
{
	
	unsigned int blk_num;
	char *dest, *source;
	unsigned int i=0;
	
	dest = page_address(iet_page->page);
	source = page_address(page);
	
	dest+=(skip_blk<<9);
	blk_num=(bytes+512)>>9;
//	spin_lock(&iet_page->lock);
//	printk(KERN_ALERT"this is beginning. copy to cache from tio \n");
	for(i=0;i<blk_num;i++){
		memcpy(dest, source, 512);
	}
//	spin_unlock(&iet_page->lock);
//	printk(KERN_ALERT"this is done. copy to cache from tio \n");
	return 0;
}

int copy_page_to_tio(struct iet_cache_page *iet_page, struct page* page, 
	char bitmap, unsigned int skip_blk, unsigned int bytes)
{
	
	unsigned int blk_num;
	char *dest, *source;
	unsigned int i=0;
	
	source = page_address(iet_page->page);
	dest = page_address(page);
	
	dest+=(skip_blk<<9);
	blk_num=(bytes+512)>>9;
//	spin_lock(&iet_page->lock);
//	printk(KERN_ALERT"this is beginning. copy cache page to tio \n");
	for(i=0;i<blk_num;i++){
		memcpy(dest, source, 512);
	}
//	spin_unlock(&iet_page->lock);
//	printk(KERN_ALERT"this is done. copy cache page to tio \n");
	return 0;
}

int iet_add_page(struct iet_volume *volume,  struct iet_cache_page* iet_page)
{
	int error;

	error=add_page_to_radix(volume, iet_page, GFP_KERNEL);
	
	if(error <0){
		printk(KERN_ERR"iet_cache_add: error in adding to cache.\n");
	}
	return error;
}

struct iet_cache_page* iet_find_get_page(struct iet_volume *volume, sector_t index)
{

	struct iet_cache_page * iet_page;

	iet_page = find_page_from_radix(volume, index);
	
	return iet_page;
}

int iet_del_page(struct iet_cache_page *iet_page)
{
	spin_lock(&lru_lock);
	list_del_init(&iet_page->lru_list);
	list_add(&iet_page->lru_list, &lru);
	spin_unlock(&lru_lock);
	
	del_page_from_radix(iet_page);
	iet_page->volume=NULL;

	/*we assume only we use the page frame*/
//	atomic_set(&iet_page->count, 0);
	
	return 0;
}

int wakeup_writeback(void){
	wake_up_process(iet_wb_thread);
	return 0;
}
static int iet_page_init(void)
{
	iet_page_cache = KMEM_CACHE(iet_cache_page, 0);
	return  iet_page_cache ? 0 : -ENOMEM;
}

int iet_cache_init(void)
{
	int err = 0;
	unsigned int i;
	int iet_page_num;
	phys_addr_t reserve_phys_addr;
	char *tmp_addr;

	reserve_phys_addr=virt_to_phys(iet_mem_virt);
	printk(KERN_ALERT"reserve_virt_addr = 0x%lx reserve_phys_addr = 0x%lx \n", 
		(unsigned long)iet_mem_virt, (unsigned long)reserve_phys_addr);

	if((err=iet_page_init())< 0)
		return err;

	INIT_LIST_HEAD(&lru);
	INIT_LIST_HEAD(&wb);
	spin_lock_init(&lru_lock);
	spin_lock_init(&wb_lock);
	
	iet_page_num = (iet_mem_size)/PAGE_SIZE;
	
	tmp_addr = iet_mem_virt;
	for(i=0;i<iet_page_num;i++){
		struct iet_cache_page *iet_page;
		struct page *page;
		page = virt_to_page(tmp_addr);
		iet_page=kmem_cache_alloc(iet_page_cache, GFP_KERNEL);
		
		iet_page->page=page;
		iet_page->volume=NULL;
		iet_page->index=-1;
		iet_page->dirty_bitmap=iet_page->valid_bitmap=0x00;
		atomic_set(&iet_page->read_count, 0);
		spin_lock_init(&iet_page->lock);
		INIT_LIST_HEAD(&iet_page->wb_list);
		list_add_tail(&iet_page->lru_list, &lru);
		
		tmp_addr = tmp_addr+ PAGE_SIZE;
	}
	
	iet_wb_thread=kthread_run(writeback_thread, NULL, "iet_wb_thread");
	return err;
}

int iet_cache_exit(void)
{
		
	struct list_head *list, *tmp;
	struct iet_cache_page *iet_page;

	list_for_each_safe(list, tmp, &lru){
		iet_page = list_entry(list, struct iet_cache_page, lru_list);
		list_del_init(list);
		kmem_cache_free(iet_page_cache, iet_page);
	}
	kthread_stop(iet_wb_thread);
	kmem_cache_destroy(iet_page_cache);
	
/*	unmap reserved physical memory 
	if (iet_mem_virt)
		iounmap(iet_mem_virt);
*/

	return 0;
}
