/*
 * cache_conn/cache_worker.h
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

#ifndef CACHE_WORKER_H
#define CACHE_WORKER_H

#include "cache_conn.h"

static inline void cache_queue_work(struct cache_work_queue *q, struct cache_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock, flags);
	list_add_tail(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	wake_up(&q->q_wait);
}

static inline void cache_queue_work_front(struct cache_work_queue *q, struct cache_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock, flags);
	list_add(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	wake_up(&q->q_wait);
}

#endif
