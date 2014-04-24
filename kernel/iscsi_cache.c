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

static int  iet_mem_start = 930, iet_mem_size = 30;

module_param(iet_mem_start, int, S_IRUGO|S_IWUSR);
module_param(iet_mem_size, int, S_IRUGO|S_IWUSR);

static char *reserve_virt_addr;

static struct kmem_cache *iet_page_cache;

/*LRU link all of pages and devices*/
static struct list_head lru;

spinlock_t		lru_lock;

char get_bitmap(sector_t sector, loff_t off){
	char bitmap=0;
	
	int i;
	i = sector-(sector/SECTOR_PER_PAGE)*SECTOR_PER_PAGE;

	while(bytes>0){
		bitmap= bitmap & 1<<i;
		bytes-=SECTOR_SIZE;
		i++;
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

/*
	find the exact page pointer, or return NULL
*/
static struct iet_cache_page *find_page_from_radix(struct iet_volume *volume, pgoff_t index){
	
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
			
		}
		printk(KERN_ALERT"iet_cache_find: success find the exact page frame.\n");
	}
out:
	rcu_read_unlock();

	return iet_page;

}

static int copy_page_from_tio(struct page* page, struct iet_cache_page *iet_page, int size){
	unsigned int t;
	char *dist, *source;
	
	dist = page_address(iet_page->page);
	source = page_address(page);
	
	printk(KERN_ALERT"this is beginning. copy to cache from tio \n");
	for(t=0; t<size; t++){
		*dist= *source;
		dist++;
		source++;
	}
	printk(KERN_ALERT"this is done. copy to cache from tio \n");
	return 0;
}
static int copy_page_to_tio(struct iet_cache_page *iet_page, struct page* page, int size){
	unsigned int t;
	char *dist, *source;
	
	source = page_address(iet_page->page);
	dist= page_address(page);
	
	printk(KERN_ALERT"this is beginning. copy to tio \n");
	for(t=0; t<size; t++){
		*dist= *source;
		dist++;
		source++;
	}
	printk(KERN_ALERT"this is done. copy to tio \n");
	return 0;
}

/* 
** FIXME!!!
** find the correct page if exist, however HAVE NOT checked whether it's dirty	
*/
int iet_add_page_to_cache(struct iet_volume *volume,  struct page* page,  
		sector_t sector, int rw){

	
	struct list_head *list, *tmp;
	struct iet_cache_page *iet_page=NULL;
	
	int error;

	/* page is 4KB, and sector is 512Byte*/
	pgoff_t page_index= sector>>3;
	
	/* search for empty page from the head of list */
	list_for_each_safe(list, tmp, &lru){
		iet_page=list_entry(list, struct iet_cache_page, lru_list);
		assert(iet_page);
		if(atomic_read(&iet_page->count) == 0){
			list_del_init(list);
			printk(KERN_ALERT"iet_cache_add: find a free iet_cache_page for use.\n");
			break;
		}
	}
		
	printk(KERN_ALERT"iet_cache_add: here is a victory.\n");
	
	if(rw==READ){
		copy_page_to_tio(iet_page, page, PAGE_SIZE);
		
	}else if(rw==WRITE){
		copy_page_from_tio(page,  iet_page, PAGE_SIZE);
	}

	printk(KERN_ALERT"this is done. 3 \n");
	atomic_inc(&iet_page->count);
	iet_page->volume=volume;
	iet_page->index =page_index;

	error=add_page_to_radix(volume, iet_page, GFP_KERNEL);
	
	if(error <0){
		printk(KERN_ALERT"iet_cache_add: error in add_to_page_iet_cache.\n");
		goto err;
	}
	
	list_add_tail(list, &lru);
	printk(KERN_ALERT"iet_cache_add: success in add_to_page_iet_cache.\n");
	return 0;
err:
	list_add(list, &lru);
	return error;
	
}

int iet_update_page_to_cache(struct iet_cache_page iet_page, struct page * page){
	int err;
	err= copy_page_from_tio(page, iet_page, PAGE_SIZE);
	return err;
}

struct iet_cache_page* iet_find_page_from_cache(struct iet_volume *volume, sector_t sector){

	struct iet_cache_page * iet_page;
	int index = sector >>3;

	iet_page = find_page_from_radix(volume, index);
	
	return iet_page;
}

int iet_del_page_from_cache(struct iet_cache_page *iet_page){

	list_del_init(&iet_page->lru_list);
	list_add(&iet_page->lru_list, &lru);
		
	del_page_from_radix(iet_page);
	iet_page->volume=NULL;

	/*we assume only we use the page frame*/
	atomic_dec(&iet_page->count);
	
	return 0;
}

static int iet_page_init(void){
	iet_page_cache = KMEM_CACHE(iet_cache_page, 0);
	return  iet_page_cache ? 0 : -ENOMEM;
}

int iet_cache_init(void){
	int err = 0;
	unsigned int i;
	int iet_page_num;
	phys_addr_t reserve_phys_addr;
	char *tmp_addr;
	
	/*map reserved physical memory into kernel region*/
	if((reserve_virt_addr = ioremap(iet_mem_start *1024 * 1024, iet_mem_size *1024 * 1024)) == NULL)
		return -1;

	reserve_phys_addr=virt_to_phys(reserve_virt_addr);
	printk(KERN_ALERT"reserve_virt_addr = 0x%lx reserve_phys_addr = 0x%lx \n", 
		(unsigned long)reserve_virt_addr, (unsigned long)reserve_phys_addr);

	if((err=iet_page_init())< 0)
		return err;

	INIT_LIST_HEAD(&lru);

	iet_page_num = (iet_mem_size*1024*1024)/PAGE_SIZE;

	tmp_addr = reserve_virt_addr;
	for(i=0;i<iet_page_num;i++){
		struct iet_cache_page *iet_cache;
		struct page *cache_page;
		cache_page = virt_to_page(tmp_addr);
		iet_cache=kmem_cache_alloc(iet_page_cache, GFP_KERNEL);
		list_add(&iet_cache->lru_list, &lru);
		atomic_set(&iet_cache->count, 0);
		iet_cache->page=cache_page;
		tmp_addr = tmp_addr+ PAGE_SIZE;
	}
	return err;
}

int iet_cache_exit(void){
		
	struct list_head *list, *tmp;
	struct iet_cache_page *iet_page;

	list_for_each_safe(list, tmp, &lru){
		iet_page = list_entry(list, struct iet_cache_page, lru_list);
		list_del_init(list);
		kmem_cache_free(iet_page_cache, iet_page);
	}

	kmem_cache_destroy(iet_page_cache);
	
	/*unmap reserved physical memory */
	if (reserve_virt_addr)
		iounmap(reserve_virt_addr);
	
	return 0;
}
