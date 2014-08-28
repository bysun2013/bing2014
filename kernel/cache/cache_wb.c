/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */
 
#include <linux/freezer.h>

#include "cache.h"
#include "cache_wb.h"

struct task_struct *dcache_wb_forker;

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
bool over_bground_thresh(struct dcache *dcache)
{
	unsigned long dirty;
	unsigned long dirty_pages = atomic_read(&dcache->dirty_pages);

	if(dirty_pages < 256)
		return false;
	
	dirty = dirty_pages * 100 * dcache_total_volume;
	if(dirty > cache_dirty_background_ratio * dcache_total_pages)
		return true;
	return false;
}

/*
* Wakeup flusher thread or forker thread to fork it. 
*/
void wakeup_cache_flusher(struct dcache *dcache)
{
	if (dcache->task) {
		wake_up_process(dcache->task);
	} else {
		wake_up_process(dcache_wb_forker);
	}
}

/*
* called by timer at short intervals
*/
void cache_wakeup_timer_fn(unsigned long data)
{
	struct dcache *dcache = (struct dcache *)data;

	if (dcache->task) {
		wake_up_process(dcache->task);
	} else{
		wake_up_process(dcache_wb_forker);
	}
}

static void cache_wakeup_thread_delayed(struct dcache *dcache)
{
	unsigned long timeout;

	timeout = msecs_to_jiffies(cache_dirty_writeback_interval * 10);
	mod_timer(&dcache->wakeup_timer, jiffies + timeout); /* modify timer */
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

static long cache_writeback(struct dcache *dcache, struct cache_writeback_work *work)
{
	long nr_pages = work->nr_pages;
	unsigned long oldest_jif;
	long progress;

	oldest_jif = jiffies;
	work->older_than_this = &oldest_jif;

	for (;;) {
		if (work->nr_pages <= 0)
			break;

		if (work->for_background && !over_bground_thresh(dcache))
			break;

		if (work->for_kupdate) {
			oldest_jif = jiffies -msecs_to_jiffies(cache_dirty_expire_interval * 10);
		} else if (work->for_background){
			oldest_jif = jiffies;
		}
		
		progress = writeback_single(dcache, work->sync_mode, nr_pages, work->range_cyclic);
		
		work->nr_pages -= progress;

		if(!progress)
			break;
	}

	return nr_pages - work->nr_pages;
}

/*
* when dirty ratio is over thresh, it's executed 
*/
static long cache_wb_background_flush(struct dcache *dcache)
{
	if (over_bground_thresh(dcache)) {
		struct cache_writeback_work work = {
			.nr_pages	= atomic_read(&dcache->dirty_pages),
			.sync_mode	= DCACHE_WB_SYNC_NONE,
			.for_background	= 1,
			.range_cyclic	= 1,
			.reason		= DCACHE_WB_REASON_BACKGROUND,
		};
		return cache_writeback(dcache, &work);
	}
	return 0;
}

/*
* wakes up periodically and does kupdated style flushing. 
*/
static long cache_wb_old_data_flush(struct dcache *dcache)
{
	unsigned long expired;

	expired = dcache->last_old_flush +
			msecs_to_jiffies(cache_dirty_writeback_interval * 10);
	if (time_before(jiffies, expired))
		return 0;
	
	dcache->last_old_flush = jiffies;
	cache_wakeup_thread_delayed(dcache);

	if(atomic_read(&dcache->dirty_pages)){
		struct cache_writeback_work work = {
			.nr_pages	= atomic_read(&dcache->dirty_pages),
			.sync_mode	= DCACHE_WB_SYNC_NONE,
			.for_kupdate	= 1,
			.range_cyclic	= 1,
			.reason		= DCACHE_WB_REASON_PERIODIC,
		};
		return cache_writeback(dcache, &work);
	}
	
	return 0;
}

/*
 * Retrieve work items and do the writeback they describe
 */
static long cache_do_writeback(struct dcache *dcache)
{
	long wrote = 0;
	
	wrote += cache_wb_old_data_flush(dcache);
	wrote += cache_wb_background_flush(dcache);

	return wrote;
}

/*
 * Handle writeback of dirty data for the volume. Also
 * wakes up periodically and does kupdated style flushing.
 */
int cache_writeback_thread(void *data)
{
	struct dcache *dcache = (struct dcache *)data;
	long pages_written;
	
	set_user_nice(current, 0);
	
	dcache->last_active = jiffies; 
	dcache->last_old_flush = jiffies; 
	
	cache_dbg("WB Thread starts, path= %s\n", dcache->path);
	while (!kthread_should_stop()) {
		/*
		 * Remove own delayed wake-up timer, since we are already awake
		 * and we'll take care of the periodic write-back.
		 */
		del_timer(&dcache->wakeup_timer);

		pages_written = cache_do_writeback(dcache);
		
		if (pages_written)
			dcache->last_active = jiffies;

		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			continue;
		}
		
		schedule_timeout(msecs_to_jiffies(cache_dirty_writeback_interval * 10));
	}
	cache_dbg("WB Thread ends, path= %s\n", dcache->path);

	del_timer(&dcache->wakeup_timer);
	/* Flush any work that raced with us exiting */
	writeback_single(dcache, DCACHE_WB_SYNC_ALL,  LONG_MAX, false);
	
	complete_all(&dcache->wb_completion);
	return 0;
}

/*
* when dirty pages of volume is over backgroud thresh at the first time, 
* start writeback thread; and when writeback thread don't work for enough
* long time, forker_thread is responsible to kill it.
*/
static int cache_forker_thread(void * args)
{
	struct task_struct *task = NULL;
	struct dcache *dcache;
	bool have_dirty_io = false;
	
	set_freezable();
	
	set_user_nice(current, 0);

	while(!kthread_should_stop()){

		enum {
			NO_ACTION,   /* Nothing to do */
			FORK_THREAD, /* Fork thread */
			KILL_THREAD, /* Kill inactive thread */
		} action = NO_ACTION;

		mutex_lock(&dcache_list_lock);

		set_current_state(TASK_INTERRUPTIBLE);

		list_for_each_entry(dcache, &dcache_list, list) {

			have_dirty_io = over_bground_thresh(dcache);

			if (!dcache->task && have_dirty_io) {
				/* if this machine don't own the volume, ignore it */
				if(dcache->owner){
					action = FORK_THREAD;
					break;
				}
			}

			if (dcache->task && !have_dirty_io &&
			    time_after(jiffies, dcache->last_active +
						cache_longest_inactive())) {
				task = dcache->task;
				 dcache->task = NULL;
				action = KILL_THREAD;
				break;
			}
		}
		mutex_unlock(&dcache_list_lock);

		switch (action) {
		case FORK_THREAD:			
			__set_current_state(TASK_RUNNING);
			task = kthread_create(cache_writeback_thread, dcache,
					      "wb_%s", &dcache->path[5]);
			init_completion(&dcache->wb_completion);
			if (IS_ERR(task)) {
				writeback_single(dcache, DCACHE_WB_SYNC_NONE, 1024, true);
			} else {
				dcache->task = task;
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

	mutex_lock(&dcache_list_lock);
	list_for_each_entry(dcache, &dcache_list, list) {
		task = dcache->task;
		dcache->task = NULL;
		if(task)
			kthread_stop(task);
	}
	mutex_unlock(&dcache_list_lock);
	
	return 0;
}

/*
* flush all the volume of cache, wait for page if it's locked.
*/
static int writeback_all(void)
{
	struct dcache *dcache;
	
	mutex_lock(&dcache_list_lock);
	list_for_each_entry(dcache, &dcache_list, list) {
		mutex_unlock(&dcache_list_lock);
		writeback_single(dcache,  DCACHE_WB_SYNC_ALL, LONG_MAX, false);
		mutex_lock(&dcache_list_lock);
	}
	mutex_unlock(&dcache_list_lock);
	
	return 0;
}

int wb_thread_init(void)
{
	unsigned int err = 0;
	dcache_wb_forker=kthread_run(cache_forker_thread, NULL, "cache_wb_forker");
	return err;
}

void wb_thread_exit(void)
{
	if(dcache_wb_forker)
		kthread_stop(dcache_wb_forker);
	
	writeback_all();
}
