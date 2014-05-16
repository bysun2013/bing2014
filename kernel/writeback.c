#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>

#include "iscsi.h"
#include "iscsi_cache.h"

#define PVEC_SIZE		16

void iet_set_page_tag(struct iet_cache_page *iet_page, unsigned int tag)
{
	struct iet_volume *volume=iet_page->volume;
	if (volume) {	/* Race with truncate? */
		spin_lock_irq(&volume->tree_lock);
		radix_tree_tag_set(&volume->page_tree,
				iet_page->index, tag);
		spin_unlock_irq(&volume->tree_lock);
	}
}

void iet_clear_page_tag(struct iet_cache_page *iet_page, unsigned int tag)
{
	struct iet_volume *volume=iet_page->volume;
	
	if (volume) {	/* Race with truncate? */
		spin_lock_irq(&volume->tree_lock);
		radix_tree_tag_clear(&volume->page_tree,
				iet_page->index, tag);
		spin_unlock_irq(&volume->tree_lock);
	}
}

static void iet_tag_pages_for_writeback(struct iet_volume *volume,
			     pgoff_t start, pgoff_t end)
{
#define WRITEBACK_TAG_BATCH 4096
	unsigned long tagged;

	do {
		spin_lock_irq(&volume->tree_lock);
		tagged = radix_tree_range_tag_if_tagged(&volume->page_tree,
				&start, end, WRITEBACK_TAG_BATCH,
				IETCACHE_TAG_DIRTY, IETCACHE_TAG_TOWRITE);
		spin_unlock_irq(&volume->tree_lock);
		WARN_ON_ONCE(tagged > WRITEBACK_TAG_BATCH);
		cond_resched();
		/* We check 'start' to handle wrapping when end == ~0UL */
	} while (tagged >= WRITEBACK_TAG_BATCH && start);
}

static unsigned iet_find_get_pages_tag(struct iet_volume *volume, pgoff_t *index,
			int tag, unsigned int nr_pages, struct iet_cache_page **pages)
{
	unsigned int i;
	unsigned int ret;
	unsigned int nr_found;

	rcu_read_lock();
restart:
	nr_found = radix_tree_gang_lookup_tag_slot(&volume->page_tree,
				(void ***)pages, *index, nr_pages, tag);
	ret = 0;
	for (i = 0; i < nr_found; i++) {
		struct iet_cache_page *page;
repeat:
		page = radix_tree_deref_slot((void **)pages[i]);
		if (unlikely(!page))
			continue;

		/*
		 * This can only trigger when the entry at index 0 moves out
		 * of or back to the root: none yet gotten, safe to restart.
		 */
		if (radix_tree_deref_retry(page))
			goto restart;

		/* Has the page moved? */
		if (unlikely(page != *((void **)pages[i]))) {
			goto repeat;
		}

		pages[ret] = page;
		ret++;
	}

	/*
	 * If all entries were removed before we could secure them,
	 * try again, because callers stop trying once 0 is returned.
	 */
	if (unlikely(!ret && nr_found))
		goto restart;
	rcu_read_unlock();

	if (ret)
		*index = pages[ret - 1]->index + 1;

	return ret;
}

int writeback_lun(struct iet_volume *volume, unsigned int mode){
	int err=0;
	int done = 0;
	int nr_pages;
	struct iet_cache_page *pages[PVEC_SIZE];
	pgoff_t index=0;
	pgoff_t end=LONG_MAX;
	pgoff_t done_index;
	int tag;
	
	if (mode == WB_SYNC_ALL)
		tag = IETCACHE_TAG_TOWRITE;
	else
		tag = IETCACHE_TAG_DIRTY;

	if(!volume)
		return err;
	
	if (mode == WB_SYNC_ALL)
		iet_tag_pages_for_writeback(volume, index, end);
	done_index = index;
	while (!done && (index <= end)) {
		int i;
		nr_pages = iet_find_get_pages_tag(volume, &index, tag,
			      min(end - index, (pgoff_t)PVEC_SIZE-1) + 1, pages);
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct iet_cache_page *iet_page = pages[i];

			if (iet_page->index > end) {
				done = 1;
				break;
			}

			done_index = iet_page->index;

			lock_page(iet_page->page);

			if (unlikely(iet_page->volume != volume)) {
continue_unlock:
				unlock_page(iet_page->page);
				continue;
			}

			if (!(iet_page->dirty_bitmap & 0xff)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if (!mutex_trylock(&iet_page->write)) {
				if (mode == WB_SYNC_ALL)
					mutex_lock(&iet_page->write);
				else
					goto continue_unlock;
			}
			
			printk(KERN_ALERT"WRITE BACK one page. page index is %llu, dirty is %x.\n", 
				(unsigned long long)iet_page->index, iet_page->dirty_bitmap);

			err = blockio_start_rw_page_blocks(iet_page, WRITE);
			if (unlikely(err)) {
				printk(KERN_ALERT"writeback_lun: Error when submit blocks to device.\n");
				mutex_unlock(&iet_page->write);
				goto continue_unlock;
			}
			iet_page->dirty_bitmap=0x00;

			mutex_unlock(&iet_page->write);
			
			iet_clear_page_tag(iet_page, tag);
			
			unlock_page(iet_page->page);
		}
		cond_resched();
	}
	return err;
}

int writeback_target(struct iscsi_target *target, unsigned int mode){
	int err=0;
	struct iet_volume *volume;
	struct list_head *head=&target->volumes;
	
	list_for_each_entry(volume, head, list){
again:
		err=writeback_lun(volume, mode);
		if(unlikely(err)){
			printk(KERN_ALERT"Error when writeback target.\n");
			goto again;
		}
	}
	return err;
}
#ifdef WRITEBACK_LIST
/* this writeback way is based on list, and is abandoned */
int writeback_all(void)
{
	int err=0;
	struct iet_cache_page *iet_page=NULL;

	while((iet_page=get_wb_page())){
		lock_page(iet_page->page);
		
		if (!mutex_trylock(&iet_page->write)) {
			/* move to tail, CPU may be spinning here. */
			add_to_wb_list(&iet_page->wb_list); 
			printk(KERN_ALERT"WRITE BACK conflict with write to cache.\n");
			continue;
		}

		printk(KERN_ALERT"WRITE BACK one page. page index is %llu, dirty is %x.\n", 
			(unsigned long long)iet_page->index, iet_page->dirty_bitmap);
		
		err=blockio_start_rw_page_blocks(iet_page, WRITE);
		
		iet_page->dirty_bitmap = 0x00;

		mutex_unlock(&iet_page->write);
		unlock_page(iet_page->page);
	}
	return err;
}
#endif

extern struct list_head target_list;
extern struct mutex target_list_mutex;
int writeback_all_target(void){
	struct iscsi_target *target;
	list_for_each_entry(target, &target_list, t_list){
		writeback_target(target,  WB_SYNC_NONE);
	}
	return 0;
}

int writeback_thread(void *args){
	do{
#ifdef WRITEBACK_LIST
		writeback_all();
#else
		writeback_all_target();
#endif
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ/4);
	}while(!kthread_should_stop());
	
	return 0;
}

