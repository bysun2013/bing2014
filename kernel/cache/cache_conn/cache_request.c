/*
 * cache_conn/cache_request.c
 *
 * list all the sync requests, wait for ack 
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

extern struct kmem_cache *cache_request_cache;

struct cache_request * cache_request_alloc(struct cache_connection *conn, u32 seq_num)
{
	struct cache_request *req;
	if(!conn)
		return NULL;
	
	req = kmem_cache_alloc(cache_request_cache, GFP_KERNEL | __GFP_NOFAIL);
	req->seq_num = seq_num;
	//init_timer(&req->nop_timer);  //it need a timer in case thread blocked forever
	req->connection = conn;
	init_completion(&req->done);
	
	return req;
}

struct cache_request * get_ready_request(struct cache_connection *conn, u32 seq_num)
{
	struct cache_request *req, *tmp;

	spin_lock(&conn->request_lock);
	list_for_each_entry_safe(req, tmp, &conn->request_list, list){
		if (req->seq_num == seq_num) {
			list_del_init(&req->list);
			BUG_ON(req->connection != conn);
			atomic_dec(&conn->nr_cmnds);
			break;
		}
	}
	if(&req->list == &conn->request_list){
		cache_err("Error, right request can't be found.\n");
		spin_unlock(&conn->request_lock);
		return NULL;
	}
	spin_unlock(&conn->request_lock);

	return req;
}

void cache_request_enqueue(struct cache_request *req)
{
	struct cache_connection * conn;
	conn = req->connection;
	
	spin_lock(&conn->request_lock);
	list_add_tail(&req->list, &conn->request_list);
	spin_unlock(&conn->request_lock);

	atomic_inc(&conn->nr_cmnds);
	cache_dbg("enqueue one request.\n");
}

void cache_request_dequeue(struct cache_request *req)
{
	struct cache_connection * conn;
	conn = req->connection;
	
	spin_lock(&conn->request_lock);
	if(!req){
		spin_unlock(&conn->request_lock);
		return;
	}
	list_del_init(&req->list);
	spin_unlock(&conn->request_lock);

	atomic_dec(&conn->nr_cmnds);
	cache_dbg("dequeue one request.\n");

	kmem_cache_free(cache_request_cache, req);
}

