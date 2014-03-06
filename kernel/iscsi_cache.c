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
#include <linux/hash.h>
#include <scsi/scsi.h>


#include "iscsi_dbg.h"
#include "iotype.h"
#include "iscsi.h"
#include "iscsi_cache.h"



/* param of reserved memory at boot*/

static int  iet_mem_start = 910, iet_mem_size = 80;

module_param(iet_mem_start, int, S_IRUGO|S_IWUSR);
module_param(iet_mem_size, int, S_IRUGO|S_IWUSR);

static void *reserve_virt_addr;

static struct kmem_cache *iet_page_cache;

/*LRU link all of pages and devices*/
struct list_head lru;
struct list_head iet_devices;

int iet_page_num;

static int iet_page_init(void){
	iet_page_cache = KMEM_CACHE(iet_cache_page, 0);
	return  iet_page_cache ? 0 : -ENOMEM;
}

struct iet_device* iet_cache_find_device(dev_t dev){
	
	struct iet_device *device=NULL;
	if(!iet_devices.next){
		device=kmalloc(sizeof(struct iet_device), GFP_KERNEL);
		
		device->bdev=dev;
		address_space_init_once(&device->mapping);
		list_add(&device->list, &iet_devices);
		return device;
	}

	for (device = list_entry((&iet_devices)->next, typeof(*device), list);	\
	     device->list.next != &iet_devices; 	\
	     device = list_entry((&iet_devices)->next, typeof(*device), list))
	{
		if(device->bdev==dev){
			return device;
		}
	}

	if(device->list.next==&iet_devices){
		device= kmalloc(sizeof(struct iet_device), GFP_KERNEL);

		device->bdev=dev;
		address_space_init_once(&device->mapping);
		list_add(&device->list, &iet_devices);
	}
	
	return device;
}

int iet_cache_add(struct iet_volume *volume, struct tio *tio, int rw){
	
	struct blockio_data *bio_data = volume->private;
	struct iet_device *device = NULL;
	struct address_space * mapping = NULL;
	struct iet_cache_page *iet_page = NULL;

	/* search for empty page from the end of list */
	struct list_head *list=lru.prev;
	loff_t ppos = tio->offset;
	struct page *page;
	int i, index, count;
	rw=1;
	count=tio->pg_cnt;
	
	device = iet_cache_find_device(bio_data->bdev->bd_dev);
	if(!device){
		printk(KERN_ALERT"can't find device\n");
		return -1;
	}

	if(!(mapping=&device->mapping)){
		printk(KERN_ALERT"can't find device\n");
		return -1;
	}
	
	for(i=0,index=0;i<count;i++,index++){
		
		sector_t sector = ppos>>9;
		pgoff_t page_index = sector>>2;
		int t;
		char *dist, *source;

		/* 
		** find the correct page if exist, however HAVE NOT checked whether it's dirty
		** 		FIXME!!!
		*/
		if((page=find_get_page(mapping, page_index))!= NULL)
			return 0;
		while(list->prev != &lru){
			iet_page=list_entry(list,struct iet_cache_page, lru_list);

			if(atomic_read(&iet_page->page->_count)>0){
				list=list->prev;
				continue;
			}else
				break;
		}
		
		/* copy tio page info into the page structof iet cache */
		dist = page_to_phys(iet_page->page);
		source = page_to_phys(tio->pvec[index]);
		
		for(t=0; t<PAGE_SIZE; t++){
			*dist++ = *source++;
		}
		
		atomic_inc(&iet_page->page->_count);
		iet_page->page->mapping= &device->mapping;

		add_to_page_cache(iet_page->page, mapping, page_index, GFP_KERNEL);
		ppos+= PAGE_SIZE;
	}
	return 0;
}

int iet_cache_release(struct iet_cache_page *iet_page){
	
	list_del(&iet_page->lru_list);
	list_add_tail(&iet_page->lru_list, &lru);

	/*we assume only we use the page frame*/
	atomic_dec(&iet_page->page->_count);

	delete_from_page_cache(iet_page->page);
	return 0;
}

struct iet_cache_page* iet_cache_find(dev_t dev, pgoff_t offset){
	
	struct page *page;
	struct iet_device* device;
	struct iet_cache_page* iet_page;
	
	static long seq;
	
	device = iet_cache_find_device(dev);

	seq++;

	/* use the kernel function of page cache */
	if(!(page=find_get_page(&device->mapping, offset))){
		printk(KERN_ALERT"do not find the exact page frame.\n");
		return NULL;
	}
	iet_page = list_entry(&page, struct iet_cache_page, page);
	printk(KERN_ALERT"find the exact page frame.\n");
	
	return iet_page;
}

int iet_cache_init(void){
	int err = 0;
	unsigned int i;
	phys_addr_t reserve_phys_addr;
	struct page *cache_page;
	struct iet_cache_page *iet_cache;
	/*map reserved physical memory into kernel region*/
	if((reserve_virt_addr = ioremap(iet_mem_start *1024 * 1024, iet_mem_size *1024 * 1024)) < 0)
		return -1;
	printk("reserve_virt_addr = 0x%lx\n", (unsigned long)reserve_virt_addr);

	reserve_phys_addr=virt_to_phys(reserve_virt_addr);
	cache_page=virt_to_page(reserve_virt_addr);

	if((err=iet_page_init())< 0)
		return err;

	INIT_LIST_HEAD(&iet_devices);
	INIT_LIST_HEAD(&lru);

	iet_page_num = iet_mem_size/PAGE_SIZE;
	for(i=0;i<iet_page_num;i++){
		iet_cache=kmem_cache_alloc(iet_page_cache, GFP_KERNEL | __GFP_NOFAIL);
		list_add(&iet_cache->lru_list, &lru);
		/*I'm not sure it works...*/
		iet_cache->page=cache_page++;
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
	/*Need to destroy iet_device list, which i have no t done */
	
	kmem_cache_destroy(iet_page_cache);
	
	/*unmap reserved physical memory */
	if (reserve_virt_addr)
		iounmap(reserve_virt_addr);
	
	return 0;
}
