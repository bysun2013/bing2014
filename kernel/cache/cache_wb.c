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
* check whether ratio dirty pages is over the thresh
*/
bool over_bground_thresh(struct iscsi_cache *iscsi_cache)
{
	unsigned long dirty;
	unsigned long dirty_pages = atomic_read(&iscsi_cache->dirty_pages);

	if(dirty_pages < 256)
		return false;
	
	dirty = dirty_pages * 100 * iscsi_cache_total_volume;
	if(dirty > cache_dirty_background_ratio * iscsi_cache_total_pages)
		return true;
	return false;
}

/*
* Wakeup flusher thread or forker thread to fork it. 
*/
void wakeup_cache_flusher(struct iscsi_cache *iscsi_cache)
{
	if (iscsi_cache->task) {
		wake_up_process(iscsi_cache->task);
	} else {
		wake_up_process(iscsi_wb_forker);
	}
}

/*
* called by timer at short intervals
*/
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
	mod_timer(&iscsi_cache->wakeup_timer, jiffies + timeout); /* modify timer */
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

static long cache_writeback(struct iscsi_cache *iscsi_cache, struct cache_writeback_work *work)
{
	long nr_pages = work->nr_pages;
	unsigned long oldest_jif;
	long progress;

	oldest_jif = jiffies;
	work->older_than_this = &oldest_jif;

	for (;;) {
		if (work->nr_pages <= 0)
			break;

		if (work->for_background && !over_bground_thresh(iscsi_cache))
			break;

		if (work->for_kupdate) {
			oldest_jif = jiffies -msecs_to_jiffies(cache_dirty_expire_interval * 10);
		} else if (work->for_background)
			oldest_jif = jiffies;

		progress = writeback_single(iscsi_cache, work->sync_mode, nr_pages);
		
		work->nr_pages -= progress;

		if(!progress)
			break;
	}

	return nr_pages - work->nr_pages;
}

/*
* when dirty ratio is over thresh, it's executed 
*/
static long cache_wb_background_flush(struct iscsi_cache *iscsi_cache)
{
	if (over_bground_thresh(iscsi_cache)) {
		struct cache_writeback_work work = {
			.nr_pages	= ULONG_MAX,
			.sync_mode	= ISCSI_WB_SYNC_NONE,
			.for_background	= 1,
			.range_cyclic	= 1,
			.reason		= ISCSI_WB_REASON_BACKGROUND,
		};
		return cache_writeback(iscsi_cache, &work);
	}
	return 0;
}

/*
* wakes up periodically and does kupdated style flushing. 
*/
static long cache_wb_old_data_flush(struct iscsi_cache *iscsi_cache)
{
	unsigned long expired;

	expired = iscsi_cache->last_old_flush +
			msecs_to_jiffies(cache_dirty_writeback_interval * 10);
	if (time_before(jiffies, expired))
		return 0;
	
	iscsi_cache->last_old_flush = jiffies;
	cache_wakeup_thread_delayed(iscsi_cache);

	if(atomic_read(&iscsi_cache->dirty_pages)){
		struct cache_writeback_work work = {
			.nr_pages	= atomic_read(&iscsi_cache->dirty_pages),
			.sync_mode	= ISCSI_WB_SYNC_NONE,
			.for_kupdate	= 1,
			.range_cyclic	= 1,
			.reason		= ISCSI_WB_REASON_PERIODIC,
		};
		return cache_writeback(iscsi_cache, &work);
	}
	
	return 0;
}

/*
 * Retrieve work items and do the writeback they describe
 */
static long cache_do_writeback(struct iscsi_cache *iscsi_cache)
{
	long wrote = 0;
	
	wrote += cache_wb_old_data_flush(iscsi_cache);
	wrote += cache_wb_background_flush(iscsi_cache);

	return wrote;
}

/*
 * Handle writeback of dirty data for the volume. Also
 * wakes up periodically and does kupdated style flushing.
 */
int cache_writeback_thread(void *data)
{
	struct iscsi_cache *iscsi_cache = (struct iscsi_cache *)data;
	long pages_written;
	
	set_user_nice(current, 0);
	
	iscsi_cache->last_active = jiffies; 
	iscsi_cache->last_old_flush = jiffies; 
	
	cache_dbg("WB Thread starts, path= %s\n", iscsi_cache->path);
	while (!kthread_should_stop()) {
		/*
		 * Remove own delayed wake-up timer, since we are already awake
		 * and we'll take care of the periodic write-back.
		 */
		del_timer(&iscsi_cache->wakeup_timer);

		pages_written = cache_do_writeback(iscsi_cache);
		
		if (pages_written)
			iscsi_cache->last_active = jiffies;

		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			continue;
		}
		
		schedule_timeout(msecs_to_jiffies(cache_dirty_writeback_interval * 10));
	}
	cache_dbg("WB Thread ends, path= %s\n", iscsi_cache->path);

	del_timer(&iscsi_cache->wakeup_timer);
	/* Flush any work that raced with us exiting */
	writeback_single(iscsi_cache, ISCSI_WB_SYNC_ALL,  ULONG_MAX);
	
	complete_all(&iscsi_cache->wb_completion);
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
				/* if this machine don't own the volume, ignore it */
				if(iscsi_cache->owner){
					action = FORK_THREAD;
					break;
				}
			}

			if (iscsi_cache->task && !have_dirty_io &&
			    time_after(jiffies, iscsi_cache->last_active +
						cache_longest_inactive())) {
				task = iscsi_cache->task;
				 iscsi_cache->task = NULL;
				action = KILL_THREAD;
				break;
			}
		}
		mutex_unlock(&iscsi_cache_list_lock);

		switch (action) {
		case FORK_THREAD:			
			__set_current_state(TASK_RUNNING);
			task = kthread_create(cache_writeback_thread, iscsi_cache,
					      "wb_%s", &iscsi_cache->path[5]);
			init_completion(&iscsi_cache->wb_completion);
			if (IS_ERR(task)) {
				writeback_single(iscsi_cache, ISCSI_WB_SYNC_NONE, 1024);
			} else {
				iscsi_cache->task = task;
				wake_up_process(task);
			}
			break;

		case KILL_THREAD:
			__set_current_state(TASK_RUNNING);
			kthread_stop(task);
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

/*
* flush all the volume of cache, wait for page if it's locked.
*/
static int writeback_all(void)
{
	struct iscsi_cache *iscsi_cache;
	
	mutex_lock(&iscsi_cache_list_lock);
	list_for_each_entry(iscsi_cache, &iscsi_cache_list, list) {
		mutex_unlock(&iscsi_cache_list_lock);
		writeback_single(iscsi_cache,  ISCSI_WB_SYNC_ALL, ULONG_MAX);
		mutex_lock(&iscsi_cache_list_lock);
	}
	mutex_unlock(&iscsi_cache_list_lock);
	
	return 0;
}

int wb_thread_init(void)
{
	unsigned int err = 0;
	iscsi_wb_forker=kthread_run(cache_forker_thread, NULL, "cache_wb_forker");
	return err;
}

void wb_thread_exit(void)
{
	if(iscsi_wb_forker)
		kthread_stop(iscsi_wb_forker);
	
	writeback_all();
}
