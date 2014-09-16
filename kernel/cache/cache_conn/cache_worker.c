/*
 * cache_conn/cache_worker.c
 *
 * handle data or meta received(ack, wrote index), using thread pool
 *
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include "cache_conn.h"

static inline void
cache_queue_work(struct cache_work_queue *q, struct cache_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock, flags);
	list_add_tail(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	wake_up(&q->q_wait);
}

bool dequeue_work_batch(struct cache_work_queue *queue, struct list_head *work_list)
{
	spin_lock_irq(&queue->q_lock);
	list_splice_init(&queue->q, work_list);
	spin_unlock_irq(&queue->q_lock);
	return !list_empty(work_list);
}

bool dequeue_work_item(struct cache_work_queue *queue, struct list_head *work_list)
{
	spin_lock_irq(&queue->q_lock);
	if (!list_empty(&queue->q))
		list_move(queue->q.next, work_list);
	spin_unlock_irq(&queue->q_lock);
	return !list_empty(work_list);
}

void wait_for_work(struct cache_connection *connection, struct list_head *work_list)
{
	DEFINE_WAIT(wait);

	dequeue_work_item(&connection->sender_work, work_list);
	if (!list_empty(work_list))
		return;

	for (;;) {
		int send_barrier;
		prepare_to_wait(&connection->sender_work.q_wait, &wait, TASK_INTERRUPTIBLE);
		spin_lock(&connection->sender_work.q_lock);	/* FIXME get rid of this one? */
		/* dequeue single item only,
		 * we still use cache_queue_work_front() in some places */
		if (!list_empty(&connection->sender_work.q))
			list_move(connection->sender_work.q.next, work_list);
		spin_unlock(&connection->sender_work.q_lock);	/* FIXME get rid of this one? */
		if (!list_empty(work_list) || signal_pending(current)) {
			break;
		}

		schedule();
	}
	
	finish_wait(&connection->sender_work.q_wait, &wait);

	mutex_unlock(&connection->data.mutex);
}


int cache_worker(struct cache_thread *thi)
{
	struct cache_connection *connection = thi->connection;
	struct cache_work *w = NULL;
	LIST_HEAD(work_list);
	int vnr;

	while (get_t_state(thi) == RUNNING) {

		/* as long as we use cache_queue_work_front(),
		 * we may only dequeue single work items here, not batches. */
		if (list_empty(&work_list))
			wait_for_work(connection, &work_list);

		if (signal_pending(current)) {
			flush_signals(current);
			if (get_t_state(thi) == RUNNING) {
				cache_warn("Worker got an unexpected signal\n");
				continue;
			}
			break;
		}

		if (get_t_state(thi) != RUNNING)
			break;

		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct cache_work, list);
			list_del_init(&w->list);
			if (w->cb(w) == 0)
				continue;
		}
	}

	do {
		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct cache_work, list);
			list_del_init(&w->list);
			w->cb(w);
		}
		dequeue_work_batch(&connection->sender_work, &work_list);
	} while (!list_empty(&work_list));

	return 0;
}

