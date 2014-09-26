/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 *
 * WARNNING
 * 	This file is not used now
 */

#include "cache_conn.h"

/* quoting tcp(7):
 *   On individual connections, the socket buffer size must be set prior to the
 *   listen(2) or connect(2) calls in order to have it take effect.
 * This is our wrapper to do so.
 */
static void cache_setbufsize(struct socket *sock, unsigned int snd,
		unsigned int rcv)
{
	/* open coded SO_SNDBUF, SO_RCVBUF */
	if (snd) {
		sock->sk->sk_sndbuf = snd;
		sock->sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
	}
	if (rcv) {
		sock->sk->sk_rcvbuf = rcv;
		sock->sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
	}
}

static void cache_incoming_connection(struct sock *sk)
{
	struct accept_wait_data *ad = sk->sk_user_data;
	void (*state_change)(struct sock *sk);

	state_change = ad->original_sk_state_change;
	if (sk->sk_state == TCP_ESTABLISHED)
		complete(&ad->door_bell);
	state_change(sk);
}

static void unregister_state_change(struct sock *sk, struct accept_wait_data *ad)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_state_change = ad->original_sk_state_change;
	sk->sk_user_data = NULL;
	write_unlock_bh(&sk->sk_callback_lock);
}

int cache_worker(struct cache_thread *thi)
{
	struct cache_connection *connection = thi->connection;
	struct cache_work *w = NULL;
	struct cache_peer_device *peer_device;
	LIST_HEAD(work_list);
	int vnr;

	while (get_t_state(thi) == RUNNING) {
		cache_thread_current_set_cpu(thi);

		/* as long as we use cache_queue_work_front(),
		 * we may only dequeue single work items here, not batches. */
		if (list_empty(&work_list))
			wait_for_work(connection, &work_list);

		if (signal_pending(current)) {
			flush_signals(current);
			if (get_t_state(thi) == RUNNING) {
				cache_warn(connection, "Worker got an unexpected signal\n");
				continue;
			}
			break;
		}

		if (get_t_state(thi) != RUNNING)
			break;

		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct cache_work, list);
			list_del_init(&w->list);
			if (w->cb(w, connection->cstate < C_WF_REPORT_PARAMS) == 0)
				continue;
			if (connection->cstate >= C_WF_REPORT_PARAMS)
				conn_request_state(connection, NS(conn, C_NETWORK_FAILURE), CS_HARD);
		}
	}

	do {
		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct cache_work, list);
			list_del_init(&w->list);
			w->cb(w, 1);
		}
		dequeue_work_batch(&connection->sender_work, &work_list);
	} while (!list_empty(&work_list));

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct cache_device *device = peer_device->device;
		D_ASSERT(device, device->state.disk == D_DISKLESS && device->state.conn == C_STANDALONE);
		kobject_get(&device->kobj);
		rcu_read_unlock();
		cache_device_cleanup(device);
		kobject_put(&device->kobj);
		rcu_read_lock();
	}
	rcu_read_unlock();

	return 0;
}

/**
 * cache_send_ack() - Sends an ack packet
 * @device:	cache device
 * @cmd:	packet command code
 * @peer_req:	peer request
 */
int cache_send_ack(struct cache_peer_device *peer_device, enum cache_packet cmd,
		  struct cache_peer_request *peer_req)
{
	return _cache_send_ack(peer_device, cmd,
			      cpu_to_be64(peer_req->i.sector),
			      cpu_to_be32(peer_req->i.size),
			      peer_req->block_id);
}

/**
 * _cache_send_ack() - Sends an ack packet
 * @device:	cache device.
 * @cmd:	Packet command code.
 * @sector:	sector, needs to be in big endian byte order
 * @blksize:	size in byte, needs to be in big endian byte order
 * @block_id:	Id, big endian byte order
 */
static int _cache_send_ack(struct cache_peer_device *peer_device, enum cache_packet cmd,
			  u64 sector, u32 blksize, u64 block_id)
{
	struct cache_socket *sock;
	struct p_block_ack *p;

	if (peer_device->device->state.conn < C_CONNECTED)
		return -EIO;

	sock = &peer_device->connection->meta;
	p = cache_prepare_command(peer_device, sock);
	if (!p)
		return -EIO;
	p->sector = sector;
	p->block_id = block_id;
	p->blksize = blksize;
	p->seq_num = cpu_to_be32(atomic_inc_return(&peer_device->device->packet_seq));
	return cache_send_command(peer_device, sock, cmd, sizeof(*p), NULL, 0);
}

static int _cache_no_send_page(struct cache_connection*conn, struct page *page,
			      int offset, size_t size, unsigned msg_flags)
{
	struct socket *socket;
	void *addr;
	int err;

	socket = conn->data.socket;
	addr = kmap(page) + offset;
	err = cache_send_all(conn, socket, addr, size, msg_flags);
	kunmap(page);
	if(err){
		cache_err("Error occurs when send data.\n");
	}
	return err;
}


static int _cache_send_pages(struct cache_connection *conn, struct page **pages, 
				int count, size_t size, sector_t sector)
{
	int i;
	int len;
	/* hint all but last page with MSG_MORE */
	for (i = 0; i < count; i++){
		int err;
		len = min_t(int, PAGE_SIZE, size);
		err = _cache_no_send_page(conn, pages[i],
					 0, len,
					 i == count - 1 ? 0 : MSG_MORE);
		if (err)
			return err;
		size -=len;
	}
	return 0;
}


