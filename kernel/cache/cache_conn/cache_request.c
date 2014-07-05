/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
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
			BUG_ON(!req->conn);
			atomic_dec(&conn->nr_cmnds);
		}
	}
	spin_unlock(&conn->request_lock);
	if(req->list.next == &conn->request_list){
		cache_err("Error, right request can't be found.\n");
		return NULL;
	}
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
