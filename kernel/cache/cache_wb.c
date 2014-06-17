/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */
#include <linux/freezer.h>
#include "cache.h"
#include "cache_wb.h"

struct task_struct *iscsi_wb_forker;
/*
 * Start background writeback (via writeback threads) at this percentage
 */
unsigned long cache_dirty_background_ratio = 10;
/*
 * The interval between `kupdate'-style writebacks
 */
unsigned int cache_dirty_writeback_interval = 5 * 100; /* centiseconds */
/*
 * The longest time for which data is allowed to remain dirty
 */
unsigned int cache_dirty_expire_interval = 30 * 100; /* centiseconds */


/*
 * why some writeback work was initiated
 */
enum cache_wb_reason {
	ISCSI_WB_REASON_BACKGROUND,
	ISCSI_WB_REASON_SYNC,
	ISCSI_WB_REASON_PERIODIC,
	ISCSI_WB_REASON_FORKER_THREAD,

	ISCSI_WB_REASON_MAX,
};

/*
 * Passed into cache_wb_writeback(), essentially a subset of writeback_control
 */
struct cache_writeback_work {
	long nr_pages;
	struct iscsi_cache *cache;
	unsigned long *older_than_this;   /* may be used in the future */
	enum iscsi_wb_sync_modes sync_mode;
	unsigned int tagged_writepages:1;
	unsigned int for_kupdate:1;
	unsigned int range_cyclic:1;
	unsigned int for_background:1;
	enum cache_wb_reason reason;		/* why was writeback initiated? */

	struct list_head list;		/* pending work list */
	struct completion *done;	/* set if the caller waits */
};

#define PVEC_SIZE		16

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

/* return nr of wrote pages */
int writeback_single(struct iscsi_cache *iscsi_cache, unsigned int mode, unsigned long pages_to_write)
{
	int err = 0;
	int done = 0;
	unsigned long nr_pages, wrote = 0;
	struct iscsi_cache_page *pages[PVEC_SIZE];
	pgoff_t index=0;
	pgoff_t end=ULONG_MAX;
	pgoff_t done_index;
	int tag;
	
	if (mode == ISCSI_WB_SYNC_ALL)
		tag = ISCSICACHE_TAG_TOWRITE;
	else
		tag = ISCSICACHE_TAG_DIRTY;

	if(!iscsi_cache)
		return 0;
	
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
			
			cache_dbg("WRITEBACK one page. Index is %llu, dirty bitmap is %#x.\n", 
				(unsigned long long)iscsi_page->index, iscsi_page->dirty_bitmap);

			err = cache_write_page_blocks(iscsi_page);
			if (unlikely(err)) {
				cache_err("Error when writeback blocks to device.\n");
				mutex_unlock(&iscsi_page->write);
				goto continue_unlock;
			}
			iscsi_page->dirty_bitmap=0x00;
			mutex_unlock(&iscsi_page->write);
			
			iscsi_clear_page_tag(iscsi_page, tag);
			if(mode == ISCSI_WB_SYNC_ALL)
				iscsi_clear_page_tag(iscsi_page, ISCSICACHE_TAG_TOWRITE);

			wrote++;
			iscsi_cache->dirty_pages--;
			if(--pages_to_write < 1){
				done=1;
				unlock_page(iscsi_page->page);
				break;
			}
			unlock_page(iscsi_page->page);
		}
		cond_resched();
	}
	return wrote;
}

int writeback_all(void){
	struct iscsi_cache *iscsi_cache;
	
	mutex_lock(&iscsi_cache_list_lock);
	list_for_each_entry(iscsi_cache, &iscsi_cache_list, list){
		mutex_unlock(&iscsi_cache_list_lock);
		writeback_single(iscsi_cache,  ISCSI_WB_SYNC_ALL, ULONG_MAX);
		mutex_lock(&iscsi_cache_list_lock);
	}
	mutex_unlock(&iscsi_cache_list_lock);
	
	return 0;
}

bool over_bground_thresh(struct iscsi_cache *iscsi_cache){
	unsigned long ratio;
	unsigned long dirty_pages = iscsi_cache->dirty_pages;
	if(dirty_pages < 256)
		return false;
	
	ratio = dirty_pages * 100/iscsi_cache_total_pages;
	if(ratio > cache_dirty_background_ratio)
		return true;
	return false;
}

/* Wakeup flusher thread or forker thread to fork it. */
void wakeup_cache_flusher(struct iscsi_cache *iscsi_cache)
{
	if (iscsi_cache->task) {
		wake_up_process(iscsi_cache->task);
	} else {
		wake_up_process(iscsi_wb_forker);
	}
}

void cache_wakeup_timer_fn(unsigned long data)
{
	struct iscsi_cache *iscsi_cache = (struct iscsi_cache *)data;

	if (iscsi_cache->task) {
		wake_up_process(iscsi_cache->task);
	} else{
		wake_up_process(iscsi_wb_forker);
	}
}

static void cache_wakeup_thread_delayed(struct iscsi_cache *iscsi_cache)
{
	unsigned long timeout;

	timeout = msecs_to_jiffies(cache_dirty_writeback_interval * 10);
	mod_timer(&iscsi_cache->wakeup_timer, jiffies + timeout);
}

/*
 * Calculate the longest interval (jiffies) wb threads allowed to be
 * inactive.
 */
static unsigned long cache_longest_inactive(void)
{
	unsigned long interval;

	interval = msecs_to_jiffies(cache_dirty_writeback_interval * 10);
	return max(5UL * 60 * HZ, interval);
}

static long cache_writeback(struct iscsi_cache *wb, struct cache_writeback_work *work)
{
	long nr_pages = work->nr_pages;
	unsigned long oldest_jif;
	long progress;

	oldest_jif = jiffies;
	work->older_than_this = &oldest_jif;

	for (;;) {
		if (work->nr_pages <= 0)
			break;

		if (work->for_background && !over_bground_thresh(wb))
			break;

		if (work->for_kupdate) {
			oldest_jif = jiffies -msecs_to_jiffies(cache_dirty_expire_interval * 10);
		} else if (work->for_background)
			oldest_jif = jiffies;

		progress = writeback_single(wb, work->sync_mode, nr_pages);
		
		work->nr_pages-=progress;

		if(!progress)
			break;
	}

	return nr_pages - work->nr_pages;
}

/* when dirty ratio is over thresh, it's executed */
static long cache_wb_background_flush(struct iscsi_cache *wb)
{
	if (over_bground_thresh(wb)) {
		struct cache_writeback_work work = {
			.nr_pages	= LONG_MAX,
			.sync_mode	= ISCSI_WB_SYNC_NONE,
			.for_background	= 1,
			.range_cyclic	= 1,
			.reason		= ISCSI_WB_REASON_BACKGROUND,
		};
		return cache_writeback(wb, &work);
	}
	return 0;
}

/* wakes up periodically and does kupdated style flushing. */
static long cache_wb_old_data_flush(struct iscsi_cache *wb)
{
	unsigned long expired;
	struct cache_writeback_work work = {
		.nr_pages	= wb->dirty_pages,
		.sync_mode	= ISCSI_WB_SYNC_NONE,
		.for_kupdate	= 1,
		.range_cyclic	= 1,
		.reason		= ISCSI_WB_REASON_PERIODIC,
	};

	/*
	 * When set to zero, disable periodic writeback
	 */
	if (!cache_dirty_writeback_interval)
		return 0;

	expired = wb->last_old_flush +
			msecs_to_jiffies(cache_dirty_writeback_interval * 10);
	if (time_before(jiffies, expired))
		return 0;

	wb->last_old_flush = jiffies;
	cache_wakeup_thread_delayed(wb);

	return cache_writeback(wb, &work);
}

/*
 * Retrieve work items and do the writeback they describe
 */
static long cache_do_writeback(struct iscsi_cache *wb)
{
	long wrote = 0;

	set_bit(CACHE_writeback_running, &wb->state);
	
	wrote += cache_wb_old_data_flush(wb);
	wrote += cache_wb_background_flush(wb);
	
	clear_bit(CACHE_writeback_running, &wb->state);

	return wrote;
}

/*
 * Handle writeback of dirty data for the volume. Also
 * wakes up periodically and does kupdated style flushing.
 */
int cache_writeback_thread(void *data)
{
	struct iscsi_cache *wb = (struct iscsi_cache *)data;
	long pages_written;
	
	set_user_nice(current, 0);
	
	wb->last_active = jiffies; 
	
	cache_dbg("WB Thread starts, id= %u", wb->id);
	while (!kthread_should_stop()) {
		/*
		 * Remove own delayed wake-up timer, since we are already awake
		 * and we'll take care of the periodic write-back.
		 */
		del_timer(&wb->wakeup_timer);

		pages_written = cache_do_writeback(wb);

		if (pages_written)
			wb->last_active = jiffies;

		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			continue;
		}
		
		schedule_timeout(msecs_to_jiffies(cache_dirty_writeback_interval * 10));
	}
	cache_dbg("WB Thread ends, id= %u", wb->id);
	
	/* Flush any work that raced with us exiting */
	writeback_single(wb, ISCSI_WB_SYNC_NONE,  ULONG_MAX);
	
	return 0;
}

static int cache_forker_thread(void * args)
{
	struct task_struct *task = NULL;
	struct iscsi_cache *iscsi_cache;
	bool have_dirty_io = false;
	
	set_freezable();
	
	set_user_nice(current, 0);

	while(!kthread_should_stop()){

		enum {
			NO_ACTION,   /* Nothing to do */
			FORK_THREAD, /* Fork thread */
			KILL_THREAD, /* Kill inactive thread */
		} action = NO_ACTION;

		mutex_lock(&iscsi_cache_list_lock);

		set_current_state(TASK_INTERRUPTIBLE);

		list_for_each_entry(iscsi_cache, &iscsi_cache_list, list) {

			have_dirty_io = over_bground_thresh(iscsi_cache);

			if (!iscsi_cache->task && have_dirty_io) {
				set_bit(CACHE_pending, &iscsi_cache->state);
				action = FORK_THREAD;
				break;
			}

			if (iscsi_cache->task && !have_dirty_io &&
			    time_after(jiffies, iscsi_cache->last_active +
						cache_longest_inactive())) {
				task = iscsi_cache->task;
				 iscsi_cache->task = NULL;
				set_bit(CACHE_pending, &iscsi_cache->state);
				action = KILL_THREAD;
				break;
			}
		}
		mutex_unlock(&iscsi_cache_list_lock);

		switch (action) {
		case FORK_THREAD:
			__set_current_state(TASK_RUNNING);
			task = kthread_create(cache_writeback_thread, iscsi_cache,
					      "icache-flush-%d", iscsi_cache->id);
			if (IS_ERR(task)) {
				writeback_single(iscsi_cache, ISCSI_WB_SYNC_NONE, 1024);
			} else {
				iscsi_cache->task = task;
				wake_up_process(task);
			}
			clear_bit(CACHE_pending, &iscsi_cache->state);
			break;

		case KILL_THREAD:
			__set_current_state(TASK_RUNNING);
			kthread_stop(task);
			clear_bit(CACHE_pending, &iscsi_cache->state);
			break;

		case NO_ACTION:
			if(have_dirty_io)
				schedule_timeout(msecs_to_jiffies(cache_dirty_writeback_interval * 10));
			else
				schedule_timeout(cache_longest_inactive());
			try_to_freeze();
			break;
		}
	}

	mutex_lock(&iscsi_cache_list_lock);
	list_for_each_entry(iscsi_cache, &iscsi_cache_list, list) {
		task = iscsi_cache->task;
		iscsi_cache->task = NULL;
		if(task)
			kthread_stop(task);
	}
	mutex_unlock(&iscsi_cache_list_lock);
	
	return 0;
}

int wb_thread_init(void){
	unsigned int err = 0;
	iscsi_wb_forker=kthread_run(cache_forker_thread, NULL, "cache_wb_forker");
	return err;
}

void wb_thread_exit(void){
	if(iscsi_wb_forker)
		kthread_stop(iscsi_wb_forker);
	
	writeback_all();
}
