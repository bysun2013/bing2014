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

#include "iscsi_dbg.h"
#include "iscsi.h"
#include "iscsi_cache.h"



/* param of reserved memory at boot*/

static int  iet_mem_start = 960, iet_mem_size = 10;

module_param(iet_mem_start, int, S_IRUGO|S_IWUSR);
module_param(iet_mem_size, int, S_IRUGO|S_IWUSR);

static char *reserve_virt_addr;

static struct kmem_cache *iet_page_cache;

/*LRU link all of pages and devices*/
struct list_head lru;
struct list_head iet_devices;
struct radix_tree_root page_tree;	/* radix tree of all pages */


static int iet_page_init(void){
	iet_page_cache = KMEM_CACHE(iet_cache_page, 0);
	return  iet_page_cache ? 0 : -ENOMEM;
}

static struct iet_device* iet_cache_find_device(dev_t dev){
	
	struct iet_device *device = NULL;
	if(!iet_devices.next){
		device=kmalloc(sizeof(struct iet_device), GFP_KERNEL);
		
		device->bdev=dev;
		address_space_init_once(&device->mapping);
		list_add(&device->list, &iet_devices);
//		printk(KERN_ALERT"iet_cache_find_device: A new device added to iet cache\n");
		return device;
	}

	for (device = list_entry((&iet_devices)->next, typeof(*device), list);	\
	     device->list.next != &iet_devices; 	\
	     device = list_entry((&iet_devices)->next, typeof(*device), list))
	{
		if(device->bdev==dev){
//			printk(KERN_ALERT"iet_cache_find_device: found device\n");
			return device;
		}
	}

	if(device->list.next==&iet_devices){
		device= kmalloc(sizeof(struct iet_device), GFP_KERNEL);

		device->bdev=dev;
		address_space_init_once(&device->mapping);
		list_add(&device->list, &iet_devices);
//		printk(KERN_ALERT"iet_cache_find_device: not found device, add a new device to iet cache\n");
		return device;
	}
	
	return device;
}

static int add_to_iet_radix(struct page *page, struct iet_volume *lun,
		pgoff_t offset, gfp_t gfp_mask)
{
	int error;

	error = radix_tree_preload(gfp_mask & ~__GFP_HIGHMEM);
	if (error == 0) {
		page->mapping = mapping;
		page->index = offset;

		spin_lock_irq(&mapping->tree_lock);
		error = radix_tree_insert(&mapping->page_tree, offset, page);
		if (likely(!error)) {
			mapping->nrpages++;
			spin_unlock_irq(&mapping->tree_lock);
		} else {
			page->mapping = NULL;
			spin_unlock_irq(&mapping->tree_lock);
			printk(KERN_ALERT"add_to_iet_rdix error 1!\n");
		}
		radix_tree_preload_end();
	}else
		printk(KERN_ALERT"add_to_iet_radix error 2!\n");
	
	return error;
}

static int copy_from_tio(){
	
}
static int copy_to_tio(){
	
}

static void delete_from_iet_radix(struct page *page)
{
	struct address_space *mapping = page->mapping;
	void (*freepage)(struct page *);

	freepage = mapping->a_ops->freepage;
	spin_lock_irq(&mapping->tree_lock);
	radix_tree_delete(&mapping->page_tree, page->index);
	page->mapping = NULL;
	mapping->nrpages--;
	spin_unlock_irq(&mapping->tree_lock);

	if (freepage)
		freepage(page);
}
static struct page *find_from_iet_radix(struct address_space *mapping, pgoff_t offset){
	
	struct page *page = NULL;
	void **pagep;
	
	rcu_read_lock();
repeat:
	pagep = radix_tree_lookup_slot(&mapping->page_tree, offset);
	if (pagep) {
		page = radix_tree_deref_slot(pagep);
		if (unlikely(!page))
			goto out;
		if (radix_tree_deref_retry(page))
			goto repeat;
	}
out:
	rcu_read_unlock();
	return page;
}

/*   we assume block is aligned in page ,page 4KB and block 512 Byte ,
			and there is not the exact page in cache
	@page_index  offset based on page size
*/ 
int iet_cache_add(dev_t dev, unsigned long page_index, struct page *page){
	
	struct iet_device *device = NULL;
	struct address_space * mapping = NULL;
	struct iet_cache_page *iet_page = NULL;
	
	struct list_head *list=lru.prev;
	
	char *dist, *source;
	int t;
	if(!list || !lru.next){
		printk(KERN_ALERT"iet_cache_add: lru is empty!\n");
		return -1;
	}
		
	device = iet_cache_find_device(dev);
	if(!device){
		printk(KERN_ALERT"iet_cache_add: failed find device\n");
		return -1;
	}

	if(!(mapping=&device->mapping)){
		printk(KERN_ALERT"iet_cache_add: can't find mapping, reason is unknown.\n");
		return -1;
	}
	
	/* 
	** FIXME!!!find the correct page if exist, however HAVE NOT checked whether it's dirty		
	*/
/*	
	if((found_page=find_get_page(mapping, page_index))!= NULL){
		printk(KERN_ALERT"iet_cache_add: the exact page is found. however dirty flag is not checked.\n");
		return 0;
	}
*/	


	/* search for empty page from the end of list */
	while(list->prev != &lru){
		iet_page=list_entry(list,struct iet_cache_page, lru_list);

		if(atomic_read(&iet_page->count) > 0){
			list=list->prev;
			continue;
		}
		list_del(list);
		list_add(list,&lru);
		printk(KERN_ALERT"iet_cache_add: find a free iet_cache_page for use.\n");
		break;
		
	}
	if(!iet_page){
		printk(KERN_ALERT"iet_cache_add: no free page for cache, it's a explicit error.\n");
		return -1;
	}
		

	printk(KERN_ALERT"iet_cache_add: here is a victory.\n");


	/* copy tio page info into the page structof iet cache */
	dist = page_address(iet_page->page);
	source = page_address(page);
	printk(KERN_ALERT"this is done. 2 \n");
	for(t=0; t<PAGE_SIZE; t++){
		
		*dist++ = *source++;
	}
	printk(KERN_ALERT"this is done. 3 \n");
	atomic_inc(&iet_page->count);

//	iet_page->device = device;
//	iet_page->bdev= dev;
	if(!add_to_iet_radix(iet_page->page, mapping, page_index, GFP_KERNEL)){
		iet_cache_release(iet_page);
		printk(KERN_ALERT"iet_cache_add: error in add_to_page_iet_cache.\n");
	}
	printk(KERN_ALERT"iet_cache_add: success in add_to_page_iet_cache.\n");
	return 0;
}

/*
	find the exact page pointer, or return NULL
	@dev  the device No.
	@offset   based on page, which is 4KB
*/
struct iet_cache_page* iet_cache_find(dev_t dev, unsigned long offset){
	
	struct page *page = NULL;
	struct iet_device* device;
	struct iet_cache_page* iet_page;
		
	if((device = iet_cache_find_device(dev)) != NULL)
		printk(KERN_ALERT"iet_cache_find: Success find the exact device.\n");
	else{
		printk(KERN_ALERT"iet_cache_find: Failed find the exact device.\n");
		return NULL;
	}


	if(!(page = find_from_iet_radix(&device->mapping, offset))){
		printk(KERN_ALERT"iet_cache_find: failed find the exact page frame.\n");
		return NULL;
	}
	
	iet_page = list_entry(&page, struct iet_cache_page, page);
	printk(KERN_ALERT"iet_cache_find: success find the exact page frame.\n");
	
	return iet_page;
}

int iet_cache_release(struct iet_cache_page *iet_page){

	/*we assume only we use the page frame*/
	atomic_dec(&iet_page->count);
	
	list_del(&iet_page->lru_list);
	list_add_tail(&iet_page->lru_list, &lru);

	delete_from_iet_radix(iet_page->page);
	return 0;
}



int iet_cache_init(void){
	int err = 0;
	unsigned int i;
	int iet_page_num;
	phys_addr_t reserve_phys_addr;
	char *tmp_addr;
	struct iet_cache_page *iet_cache;
	/*map reserved physical memory into kernel region*/
	if((reserve_virt_addr = ioremap(iet_mem_start *1024 * 1024, iet_mem_size *1024 * 1024)) == NULL)
		return -1;

	reserve_phys_addr=virt_to_phys(reserve_virt_addr);
	printk(KERN_ALERT"reserve_virt_addr = 0x%lx reserve_phys_addr = 0x%lx \n", 
		(unsigned long)reserve_virt_addr, (unsigned long)reserve_phys_addr);

	if((err=iet_page_init())< 0)
		return err;

	INIT_LIST_HEAD(&iet_devices);
	INIT_LIST_HEAD(&lru);

	iet_page_num = (iet_mem_size*1024*1024)/PAGE_SIZE;

	tmp_addr = reserve_virt_addr;
	for(i=0;i<iet_page_num;i++){
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
		
	struct list_head *list;
	
	while(lru.next!= &lru){
		struct iet_cache_page* iet_page;
		
		list=lru.next;
		list_del_init(list);
		
		iet_page = list_entry(list, struct iet_cache_page, lru_list);
		kmem_cache_free(iet_page_cache, iet_page);
	}
	
	while(iet_devices.next!= &iet_devices){
		struct iet_device *device;
		
		list=iet_devices.next;
		list_del(list);
		
		device = list_entry(list, struct iet_device, list);
		kfree(device);
	}

	
	kmem_cache_destroy(iet_page_cache);
	
	/*unmap reserved physical memory */
	if (reserve_virt_addr)
		iounmap(reserve_virt_addr);
	
	return 0;
}
