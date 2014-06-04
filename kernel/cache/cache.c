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

#include "cache.h"

#define CACHE_VERSION "0.2"

/* param of reserved memory at boot */
extern unsigned int iet_mem_size;
//extern unsigned long iscsi_mem_goal; /* preferred starting address of the region */
extern char *iet_mem_virt;

static struct kmem_cache *iscsi_page_cache;

/*LRU link all of pages and devices*/
static struct list_head lru;
static spinlock_t		lru_lock;

/* list all of volume, which use cache. */
struct list_head iscsi_cache_list;
struct mutex iscsi_cache_list_lock;

//struct cache_connection *cache_conn;

/* bitmap is 7-0, Notice the sequence of bitmap*/
unsigned char get_bitmap(sector_t lba_off, u32 num){
	unsigned char a, b;
	unsigned char bitmap = 0xff;

	BUG_ON(lba_off+num > 8);
	
	if((lba_off == 0 && num == 8))
		return bitmap;
	
	a = 0xff << lba_off;
	b = 0xff >>(8-(lba_off + num));
	bitmap = (a & b);
	return bitmap;

}
EXPORT_SYMBOL_GPL(get_bitmap);

static int add_page_to_radix(struct iscsi_cache *iscsi_cache, struct iscsi_cache_page *page, 
		gfp_t gfp_mask)
{
	int error;

	error = radix_tree_preload(gfp_mask & ~__GFP_HIGHMEM);
	if (error == 0) {
		spin_lock_irq(&iscsi_cache->tree_lock);
		error = radix_tree_insert(&iscsi_cache->page_tree, page->index, page);
		if (likely(!error)) {
			spin_unlock_irq(&iscsi_cache->tree_lock);
		} else {
			page->iscsi_cache = NULL;
			spin_unlock_irq(&iscsi_cache->tree_lock);
			cache_err("Error occurs when add page to cache!\n");
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

/* find the exact page pointer, or return NULL */
static struct iscsi_cache_page *find_page_from_radix(struct iscsi_cache *iscsi_cache, sector_t index)
{
	
	struct iscsi_cache_page * iscsi_page;
	void **pagep;

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

void add_to_lru_list(struct list_head *list)
{
	spin_lock(&lru_lock);
	list_add_tail(list, &lru);
	spin_unlock(&lru_lock);
}
void throw_to_lru_list(struct list_head *list)
{
	spin_lock(&lru_lock);
	list_add(list, &lru);
	spin_unlock(&lru_lock);
}

void update_lru_list(struct list_head *list)
{
	spin_lock(&lru_lock);
	list_del_init(list);
	list_add_tail(list, &lru);
	spin_unlock(&lru_lock);
}

/* the free page is isolated, NOT list to LRU */
struct iscsi_cache_page* iscsi_get_free_page(struct iscsi_cache * iscsi_cache)
{
	struct list_head *list, *tmp;
	struct iscsi_cache_page *iscsi_page=NULL;
	
again:
	spin_lock(&lru_lock);
	list_for_each_safe(list, tmp, &lru){
		iscsi_page=list_entry(list, struct iscsi_cache_page, lru_list);
		BUG_ON(iscsi_page == NULL);
		if((iscsi_page->dirty_bitmap & 0xff) == 0){
			list_del_init(list);
			iscsi_page->valid_bitmap=0x00;
			break;
		}
		iscsi_page=NULL;
	}
	spin_unlock(&lru_lock);
	
	if(over_bground_thresh(iscsi_cache))
		wakeup_cache_flusher(iscsi_cache);

	if(iscsi_page==NULL){
		cache_err("Cache is used up! Wait for write back...\n");
		wake_up_process(iscsi_wb_forker);
		writeback_single(iscsi_cache, ISCSI_WB_SYNC_NONE, 1024);
		goto again;
	}
	if(iscsi_page->iscsi_cache){
		del_page_from_radix(iscsi_page);
		iscsi_page->iscsi_cache=NULL;
	}
	
	return iscsi_page;
}

void copy_tio_to_cache(struct page* page, struct iscsi_cache_page *iscsi_page, 
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
	
	source+=(skip_blk<<9);
	
	for(i=0;i<8;i++){
		if(bitmap & (0x01<<i)){
			memcpy(dest, source, 512);
			source+=512;
		}
		dest+=512;
	}
	return;
}

void copy_cache_to_tio(struct iscsi_cache_page *iscsi_page, struct page* page, 
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
	
	dest+=(skip_blk<<9);
	
	for(i=0;i<8;i++){
		if(bitmap & (0x01<<i)){
			memcpy(dest, source, 512);
			dest+=512;
		}
		source+=512;
	}
	return;

}

int iscsi_add_page(struct iscsi_cache *iscsi_cache,  struct iscsi_cache_page* iscsi_page)
{
	int error;

	error=add_page_to_radix(iscsi_cache, iscsi_page, GFP_KERNEL);
	
	if(error <0){
		cache_err("iscsi_cache_add: error in adding to cache.\n");
	}
	return error;
}

struct iscsi_cache_page* iscsi_find_get_page(struct iscsi_cache *iscsi_cache, pgoff_t index)
{

	struct iscsi_cache_page * iscsi_page;

	iscsi_page = find_page_from_radix(iscsi_cache, index);
	
	return iscsi_page;
}

int iscsi_del_page(struct iscsi_cache_page *iscsi_page)
{
	spin_lock(&lru_lock);
	list_del_init(&iscsi_page->lru_list);
	list_add(&iscsi_page->lru_list, &lru);
	spin_unlock(&lru_lock);
	
	del_page_from_radix(iscsi_page);
	iscsi_page->iscsi_cache=NULL;
	
	return 0;
}

static int iscsi_page_init(void)
{
	iscsi_page_cache = KMEM_CACHE(iscsi_cache_page, 0);
	return  iscsi_page_cache ? 0 : -ENOMEM;
}

void* init_iscsi_cache(void)
{
	struct iscsi_cache *iscsi_cache;
	static int id = 0;
	iscsi_cache=kzalloc(sizeof(*iscsi_cache),GFP_KERNEL);
	if(!iscsi_cache)
		return NULL;

	snprintf(iscsi_cache->name, MAX_NAME_LEN, "%d", ++id);

	iscsi_cache->total_pages = iscsi_cache->dirty_pages = 0;
	iscsi_cache->last_active = iscsi_cache->last_old_flush =0;
	
	spin_lock_init(&iscsi_cache->tree_lock);
	INIT_RADIX_TREE(&iscsi_cache->page_tree, GFP_KERNEL);
	mutex_init(&iscsi_cache->mutex);
	
	mutex_lock(&iscsi_cache_list_lock);
	list_add_tail(&iscsi_cache->list, &iscsi_cache_list);
	mutex_unlock(&iscsi_cache_list_lock);
	
	return (void *)iscsi_cache;
}
EXPORT_SYMBOL_GPL(init_iscsi_cache);

void del_iscsi_cache(void *iscsi_cachep)
{
	struct iscsi_cache *iscsi_cache=(struct iscsi_cache *)iscsi_cachep;
	if(!iscsi_cache)
		return;
	
	mutex_lock(&iscsi_cache_list_lock);
	mutex_lock(&iscsi_cache->mutex);
	list_del_init(&iscsi_cache->list);
	mutex_unlock(&iscsi_cache->mutex);
	mutex_unlock(&iscsi_cache_list_lock);

	if(iscsi_cache->task)
		kthread_stop(iscsi_cache->task);

	writeback_single(iscsi_cache, ISCSI_WB_SYNC_ALL, ULONG_MAX);
	kfree(iscsi_cache);
}

EXPORT_SYMBOL_GPL(del_iscsi_cache);

static int iscsi_global_cache_init(void)
{
	int err = 0;
	unsigned int i;
	unsigned long iscsi_pages;
	phys_addr_t reserve_phys_addr;
	char *tmp_addr;

	BUG_ON(PAGE_SIZE > 4096);
	
	reserve_phys_addr=virt_to_phys(iet_mem_virt);
	iscsi_pages = (iet_mem_size)/PAGE_SIZE;
	
	tmp_addr = iet_mem_virt;

	cache_info("iSCSI Cache Module  version %s \n", CACHE_VERSION);
	cache_info("reserved_virt_addr = 0x%lx reserved_phys_addr = 0x%lx size=%dMB \n", 
		(unsigned long)iet_mem_virt, (unsigned long)reserve_phys_addr, (iet_mem_size/1024/1024));

//	BUG_ON(reserve_phys_addr != iscsi_mem_goal);
	
	if((err=iscsi_page_init())< 0)
		return err;

	INIT_LIST_HEAD(&lru);
	spin_lock_init(&lru_lock);
	
	
	INIT_LIST_HEAD(&iscsi_cache_list);
	mutex_init(&iscsi_cache_list_lock);

	for(i=0;i<iscsi_pages;i++){
		struct iscsi_cache_page *iscsi_page;
		struct page *page;
		page = virt_to_page(tmp_addr);
		iscsi_page=kmem_cache_alloc(iscsi_page_cache, GFP_KERNEL);
		
		iscsi_page->iscsi_cache=NULL;
		iscsi_page->bdev=NULL;
		iscsi_page->index=-1; 
		
		iscsi_page->dirty_bitmap=iscsi_page->valid_bitmap=0x00;
		
		iscsi_page->page=page;
		spin_lock_init(&iscsi_page->page_lock);
		iscsi_page->flag=0;
		mutex_init(&iscsi_page->write);
		list_add_tail(&iscsi_page->lru_list, &lru);
		
		tmp_addr = tmp_addr+ PAGE_SIZE;
	}
	
	if((err=wb_thread_init()) < 0)
		return err;

	//cache_conn = cache_conn_create("cache_conn");
	return err;
}

static void iscsi_global_cache_exit(void)
{
	
	struct list_head *list, *tmp;
	struct iscsi_cache_page *iscsi_page;

	wb_thread_exit();

	//cache_conn_destroy();
	
	list_for_each_safe(list, tmp, &lru){
		iscsi_page = list_entry(list, struct iscsi_cache_page, lru_list);
		list_del_init(list);
		kmem_cache_free(iscsi_page_cache, iscsi_page);
	}
	
	kmem_cache_destroy(iscsi_page_cache);
	cache_info("Unload iSCSI Cache Module. All right \n");
}

module_init(iscsi_global_cache_init);
module_exit(iscsi_global_cache_exit);

MODULE_VERSION(CACHE_VERSION);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("iSCSI Cache");
MODULE_AUTHOR("Bing Sun <b.y.sun.cn@gmail.com>");

