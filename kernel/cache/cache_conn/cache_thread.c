
#define WORKER_MIN_THREADS	1
#define WORKER_MAX_THREADS	8

static LIST_HEAD(worker_list);
static DEFINE_SPINLOCK(worker_lock);

static int nr_worker_threads = 0;
static unsigned long last_empty_jifs = 0;

struct cache_worker_thread_info{
	struct task_struct *who;
	void (*fn)(unsigned long arg);
	unsigned long arg;
	struct list_head list;
	unsigned long when_i_went_to_sleep;
};

static void start_one_worker_thread(void);

static int __cache_thread_worker(struct cache_worker_thread_info *my_info)
{
	set_freezable();
	my_info->fn = NULL;
	my_info->who = current;
	INIT_LIST_HEAD(&my_info->list);

	spin_lock_irq(&worker_lock);
	nr_worker_threads++;

	for(;;){
		struct cache_worker_thread_info *info;
		set_current_state(TASK_INTERRUPTIBLE);
		list_move(&my_info->list, &worker_list);
		my_info->when_i_went_to_sleep = jiffies;
		spin_unlock_irq(&worker_lock);
		schedule();
		try_to_freeze();

		spin_lock_irq(&worker_lock);
		if(!list_empty(&my_info->list)){
			my_info->fn = NULL;
			continue;
		}

		if(my_info->fn ==NULL){
			cache_warn("cache worker: bogus wakeup.\n");
			continue;
		}
		spin_unlock_irq(&worker_lock);

		(*my_info->fn)(my_info->arg);

		if(jiffies - last_empty_jifs > 1*HZ){
			if(list_empty(&worker_list))
				if(nr_worker_threads < WORKER_MAX_THREADS)
					start_one_worker_thread();
		}

		spin_lock_irq(&worker_lock);
		my_info->fn = NULL;

		if(list_empty(&worker_list))
			continue;
		if(nr_worker_threads < WORKER_MIN_THREADS)
			continue;

		info = list_entry(worker_list.pre, struct cache_worker_thread_info, list);

		if(jiffies - info->when_i_went_to_sleep > 1*HZ){
			info->when_i_went_to_sleep = jiffies;
			break;
		}
	}

	nr_worker_threads --;
	spin_unlock_irq(&worker_lock);

	return 0;
}

int cache_worker_operation(void (*fn)(unsigned long), unsigned long arg)
{
	unsigned long flags;
	int ret = 0;

	BUG_ON(fn == NULL); 

	spin_lock_irqsave(&worker_lock, flags);

	if (list_empty(&worker_list)) {
		spin_lock_restore(&worker_lock, flags);
		ret = -1;
	}else{
		struct cache_worker_thread_info *info;

		info = list_entry(worker_list.next, struct cache_worker_thread_info, list);
		list_del(&info->list);
		info->fn = fn;
		info->arg = arg;
		if(list_empty(&worker_list)){
			last_empty_jifs = jiffies;
		}

		wake_up_process(info->who);
		spin_lock_restore(&worker_lock, flags);
	}

	return ret;
}

static void cache_thread_worker(void * dummy)
{
	struct cache_worker_thread_info my_info;

	set_user_nice(current, 0);
	
	return __cache_thread_worker(&my_info);
}

static void start_one_worker_thread(void)
{
	kthread_run(cache_thread_worker, NULL, "cache_worker"); 
}

int cache_worker_thread_init(void)
{
	int i;
	for(i=0;  i < WORKER_MIN_THREADS; i++)
		start_one_worker_thread();

	return 0;
}

