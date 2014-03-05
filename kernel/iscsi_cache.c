/*
 * Copyright (C) 2013-2014 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include "iscsi.h"
#include "iscsi_cache.h"

/*LRU link all of pages*/
struct list_head lru;


iet_page_num=iet_mem_size/PAGE_SIZE;


static int iet_page_init(){
	iet_page_cache = KMEM_CACHE(iet_cache_page, 0);
	return  iet_page_cache ? 0 : -ENOMEM;
}

struct iet_device* iet_cache_find_device(dev_t dev){
	
	struct iet_device *device=NULL;
	if(!iet_devices.next){
		device=kmalloc(sizeof(iet_device));
		
		device->bdev=dev;
		address_space_init_once(&device->mapping);
		list_add(device->list, iet_devices);
		return device;
	}

	list_for_each_entry(device, iet_devices, list){
		if(device->bdev==dev){
			return device;
		}
	}

	if(device->list==iet_devices){
		device=kmalloc(sizeof(iet_device));

		device->bdev=dev;
		address_space_init_once(&device->mapping);
		list_add(device->list, iet_devices);
	}
	
	return device;
}

int iet_cache_add(struct iet_volume *volume, struct tio *tio, int rw){
	
	struct blockio_data *bio_data = volume->private;
	struct iet_device *device=NULL;
	struct address_space * mapping=NULL;

	device=iet_cache_find_device(bio_data->bdev->bd_dev);
	mapping=&device->mapping;
	
	int index, count=tio->pg_cnt;
	struct iet_cache_page *iet_page;
	/*search for empty page from the end of list*/
	struct list_head *list=lru.prev;
	loff_t ppos = tio->offset;
	
	int i;
	for(i=0;i<count;i++){
		
		sector_t sector = ppos>>9;
		pgoff_t page_index = sector>>2;
		
		/*find the correct page if exist
		** use the kernel function, or complete it soon if you will 
		*/
		find_get_page(mapping, page_index);
again:
		iet_page=list_entry(list,struct iet_cache_page, lru_list);
		if(!iet_page){
			printk(KERN_ALERT"iet cache is empty.\n");
			return -NOMEM;
		}
		
		if(atomic_read(iet_page->page->_count)>0){
			list=list->prev;
			goto again;
		}
		
		/*copy tio page info into the page structof iet cache
		*
		*/
		atomic_inc(iet_page->page->_count);
		iet_page->page->mapping= &device->mapping;
		unsigned int bytes = PAGE_SIZE;
		ppos+=bytes;
	}
}

int iet_cache_release(struct iet_cache_page *iet_page){
	/*we assume only we use the page frame*/
	atomic_dec(iet_page->page->_count);
	
	list_del(iet_page->lru_list);
	list_add_tail(iet_page->lru_list, lru);

	delete_from_page_cache(iet_page->page);
	
}

struct iet_cache_page* iet_cache_find(struct iet_device *device, pgoff_t offset){
	/* use the kernel function */
	struct page *page;
	if(!(page=find_get_page(&device->mapping, offset)))
		return NULL;
	return list_entry(&page, struct iet_cache_page, page);
}


int iet_cache_init(){
	int err;
	unsigned int i=0;
	phys_addr_t reserve_phys_addr;
	struct page *cache_page;
	struct iet_cache_page *iet_cache;
	/*map reserved physical memory into kernel region*/
	if((reserve_virt_addr = ioremap(iet_mem_start *1024 * 1024, iet_mem_size *1024 * 1024))<0)
		goto err;
	printk("reserve_virt_addr = 0x%lx\n", (unsigned long)reserve_virt_addr);

	reserve_phys_addr=virt_to_phys(reserve_virt_addr);
	cache_page=virt_to_page(reserve_virt_addr);

	if((err=iet_page_init())< 0)
		return err;

	INIT_LIST_HEAD(iet_devices);
	INIT_LIST_HEAD(lru);
	
	for(;i<iet_page_num;i++){
		iet_cache=kmem_cache_alloc(iet_page_cache, GFP_KERNEL | __GFP_NOFAIL);
		list_add(iet_cache->lru_list, lru);
	}
	return 0;
}



int iet_cache_exit(){
		
	struct list_head list;
	list=lru.next;
	while(list != lru.pre){
		struct iet_cache_page page = list_entry(list, struct iet_cache_page, lru_list);
		kmem_cache_free(iet_page_cache, page);
	}
	
	kmem_cache_destroy(iet_page_cache);
	/*unmap reserved physical memory */
	if (reserve_virt_addr)
¡¡¡¡	iounmap(reserve_virt_addr);
	return 0;
}

