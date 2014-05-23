#include "iscsi_cache.h"

#define PVEC_SIZE		16

enum writeback_sync_modes {
	ISCSI_WB_SYNC_NONE,	/* Don't wait on anything */
	ISCSI_WB_SYNC_ALL,	/* Wait on every mapping */
};

void iscsi_set_page_tag(struct iscsi_cache_page *iscsi_page, unsigned int tag)
{
	struct iscsi_cache *iscsi_cache=iscsi_page->iscsi_cache;
	if (iscsi_cache) {	/* Race with truncate? */
		spin_lock_irq(&iscsi_cache->tree_lock);
		radix_tree_tag_set(&iscsi_cache->page_tree,
				iscsi_page->index, tag);
		spin_unlock_irq(&iscsi_cache->tree_lock);
	}
}

void iscsi_clear_page_tag(struct iscsi_cache_page *iscsi_page, unsigned int tag)
{
	struct iscsi_cache *iscsi_cache=iscsi_page->iscsi_cache;
	
	if (iscsi_cache) {	/* Race with truncate? */
		spin_lock_irq(&iscsi_cache->tree_lock);
		radix_tree_tag_clear(&iscsi_cache->page_tree,
				iscsi_page->index, tag);
		spin_unlock_irq(&iscsi_cache->tree_lock);
	}
}

static void iscsi_tag_pages_for_writeback(struct iscsi_cache *iscsi_cache,
			     pgoff_t start, pgoff_t end)
{
#define WRITEBACK_TAG_BATCH 4096
	unsigned long tagged;

	do {
		spin_lock_irq(&iscsi_cache->tree_lock);
		tagged = radix_tree_range_tag_if_tagged(&iscsi_cache->page_tree,
				&start, end, WRITEBACK_TAG_BATCH,
				ISCSICACHE_TAG_DIRTY, ISCSICACHE_TAG_TOWRITE);
		spin_unlock_irq(&iscsi_cache->tree_lock);
		WARN_ON_ONCE(tagged > WRITEBACK_TAG_BATCH);
		cond_resched();
		/* We check 'start' to handle wrapping when end == ~0UL */
	} while (tagged >= WRITEBACK_TAG_BATCH && start);
}

static unsigned iscsi_find_get_pages_tag(struct iscsi_cache *iscsi_cache, pgoff_t *index,
			int tag, unsigned int nr_pages, struct iscsi_cache_page **pages)
{
	unsigned int i;
	unsigned int ret;
	unsigned int nr_found;

	rcu_read_lock();
restart:
	nr_found = radix_tree_gang_lookup_tag_slot(&iscsi_cache->page_tree,
				(void ***)pages, *index, nr_pages, tag);
	ret = 0;
	for (i = 0; i < nr_found; i++) {
		struct iscsi_cache_page *page;
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

int writeback_single(struct iscsi_cache *iscsi_cache, unsigned int mode){
	int err=0;
	int done = 0;
	int nr_pages;
	struct iscsi_cache_page *pages[PVEC_SIZE];
	pgoff_t index=0;
	pgoff_t end=LONG_MAX;
	pgoff_t done_index;
	int tag;
	
	if (mode == ISCSI_WB_SYNC_ALL)
		tag = ISCSICACHE_TAG_TOWRITE;
	else
		tag = ISCSICACHE_TAG_DIRTY;

	if(!iscsi_cache)
		return err;
	
	if (mode == ISCSI_WB_SYNC_ALL)
		iscsi_tag_pages_for_writeback(iscsi_cache, index, end);
	done_index = index;
	while (!done && (index <= end)) {
		int i;
		nr_pages = iscsi_find_get_pages_tag(iscsi_cache, &index, tag,
			      min(end - index, (pgoff_t)PVEC_SIZE-1) + 1, pages);
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct iscsi_cache_page *iscsi_page = pages[i];

			if (iscsi_page->index > end) {
				done = 1;
				break;
			}

			done_index = iscsi_page->index;

			lock_page(iscsi_page->page);

			if (unlikely(iscsi_page->iscsi_cache != iscsi_cache)) {
continue_unlock:
				unlock_page(iscsi_page->page);
				continue;
			}

			if (!(iscsi_page->dirty_bitmap & 0xff)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if (!mutex_trylock(&iscsi_page->write)) {
				if (mode == ISCSI_WB_SYNC_ALL)
					mutex_lock(&iscsi_page->write);
				else
					goto continue_unlock;
			}
			
			printk(KERN_ALERT"WRITE BACK one page. page index is %llu, dirty is %x.\n", 
				(unsigned long long)iscsi_page->index, iscsi_page->dirty_bitmap);

			err = blockio_start_rw_page_blocks(iscsi_page, WRITE);
			if (unlikely(err)) {
				printk(KERN_ALERT"writeback_lun: Error when submit blocks to device.\n");
				mutex_unlock(&iscsi_page->write);
				goto continue_unlock;
			}
			iscsi_page->dirty_bitmap=0x00;

			mutex_unlock(&iscsi_page->write);
			
			iscsi_clear_page_tag(iscsi_page, tag);
			
			unlock_page(iscsi_page->page);
		}
		cond_resched();
	}
	return err;
}

int writeback_all(void){
	struct iscsi_cache *iscsi_cache;
	mutex_lock(&iscsi_cache_list_mutex);
	list_for_each_entry(iscsi_cache, &iscsi_cache_list, list){
		writeback_single(iscsi_cache,  ISCSI_WB_SYNC_NONE);
	}
	mutex_lock(&iscsi_cache_list_mutex);
	return 0;
}

int writeback_thread(void *args){
	do{
		writeback_all();
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ/4);
	}while(!kthread_should_stop());
	
	return 0;
}

