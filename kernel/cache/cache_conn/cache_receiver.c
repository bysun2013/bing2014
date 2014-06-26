/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include "cache_conn.h"

static int decode_header(struct cache_connection *tconn, void *header, struct packet_info *pi)
{
	unsigned int header_size = cache_header_size(tconn);

	if (header_size == sizeof(struct p_header80) &&
		   *(__be16 *)header == cpu_to_be16(CACHE_MAGIC)) {
		struct p_header80 *h = header;
		pi->cmd = be16_to_cpu(h->command);
		pi->size = be32_to_cpu(h->length);
		pi->vnr = 0;
	} else {
		cache_err("Wrong magic value 0x%08x in \n",
			 be16_to_cpu(*(__be16 *)header));
		return -EINVAL;
	}
	pi->data = header + header_size;
	return 0;
}


static int cache_recv_short(struct socket *sock, void *buf, size_t size, int flags)
{
	mm_segment_t oldfs;
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr msg = {
		.msg_iovlen = 1,
		.msg_iov = (struct iovec *)&iov,
		.msg_flags = (flags ? flags : MSG_WAITALL | MSG_NOSIGNAL)
	};
	int rv;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	rv = sock_recvmsg(sock, &msg, size, msg.msg_flags);
	set_fs(oldfs);

	return rv;
}

static int cache_recv(struct cache_connection *connection, void *buf, size_t size)
{
	int rv;

	rv = cache_recv_short(connection->data.socket, buf, size, 0);

	if (rv < 0) {
		if (rv == -ECONNRESET)
			cache_info("sock was reset by peer\n");
		else if (rv != -ERESTARTSYS)
			cache_err( "sock_recvmsg returned %d\n", rv);
	} else if (rv == 0) {
	/*
		if (test_bit(DISCONNECT_SENT, &connection->flags)) {
			long t;
			rcu_read_lock();
			t = rcu_dereference(connection->net_conf)->ping_timeo * HZ/10;
			rcu_read_unlock();

			t = wait_event_timeout(connection->ping_wait, connection->cstate < C_WF_REPORT_PARAMS, t);

			if (t)
				goto out;
		}
	*/
		cache_info("sock was shut down by peer\n");
	}
	
	return rv;
}

static int cache_recv_all(struct cache_connection *connection, void *buf, size_t size)
{
	int err;

	err = cache_recv(connection, buf, size);
	if (err != size) {
		if (err >= 0)
			err = -EIO;
	} else
		err = 0;
	return err;
}

static int cache_recv_all_warn(struct cache_connection *connection, void *buf, size_t size)
{
	int err;

	err = cache_recv_all(connection, buf, size);
	if (err && !signal_pending(current))
		cache_warn("short read (expected size %d)\n", (int)size);
	return err;
}

int cache_recv_header(struct cache_connection *connection, struct packet_info *pi)
{
	void *buffer = connection->data.rbuf;
	int err;

	err = cache_recv_all_warn(connection, buffer, cache_header_size(connection));
	if (err)
		return err;

	err = decode_header(connection, buffer, pi);
	connection->last_received = jiffies;

	return err;
}

int receive_first_packet(struct cache_connection *connection, struct socket *sock)
{
	unsigned int header_size = cache_header_size(connection);
	struct packet_info pi;
	int err;

	err = cache_recv_short(sock, connection->data.rbuf, header_size, 0);
	if (err != header_size) {
		if (err >= 0)
			err = -EIO;
		return err;
	}
	err = decode_header(connection, connection->data.rbuf, &pi);
	if (err)
		return err;
	return pi.cmd;
}

/* used from receive_Data */
static struct cio *
read_in_block(struct cache_connection *connection, sector_t sector,
	      struct packet_info *pi)
{
	static struct cio * req;
	struct page *page;
	int ds, err;
	int data_size = pi->size;
	int i, nr_pages = (data_size + PAGE_SIZE - 1)>>PAGE_SHIFT;
	unsigned long *data;

	if (!(IS_ALIGNED(data_size, 512))){
		cache_err("size is not aligned to 512.\n");
		return NULL;
	}
	req = cio_alloc(nr_pages);
	if (!req)
		return NULL;
	req->offset = sector << 9;
	req->size = data_size;
	
	ds = data_size;
	
//	WARN_ON(ds%PAGE_SIZE != 0);
	
	for(i=0;i<nr_pages; i++){
		unsigned len = min_t(int, ds, PAGE_SIZE);
		//WARN_ON(len%PAGE_SIZE != 0);
		page = req->pvec[i];
		data = kmap(page);
		err = cache_recv_all_warn(connection, data, len);
		kunmap(page);
		if (err) {
			cio_put(req);
			cache_err("Error occurs when receive data from net.\n");
			return NULL;
		}
		ds -= len;
	}

	return req;
}

int receive_data(struct cache_connection * connection, struct packet_info * pi)
{
	struct iscsi_cache *iscsi_cache = connection->iscsi_cache;
	struct cio * req;
	struct p_data *p = pi->data;
//	u32 peer_seq = be32_to_cpu(p->seq_num);
	sector_t sector = be64_to_cpu(p->sector);

	cache_dbg("begin to receive data.\n");
	
	req = read_in_block(connection, sector, pi);
	if (!req) {
		cache_err("Error occurs when receive data.\n");
		return -EIO;
	}
	cache_dbg("To write received data.\n");

	iscsi_write_cache((void *)iscsi_cache, req->pvec, req->pg_cnt, req->size, req->offset);
	
	cache_dbg("write received data into cache.\n");
	return 0;
};

int receive_data_reply(struct cache_connection *connection, struct packet_info *pi){
	cache_dbg("receive data reply.\n");
	return 0;
};

int receive_data_wrote(struct cache_connection *connection, struct packet_info *pi)
{
	struct iscsi_cache *iscsi_cache = connection->iscsi_cache;
	struct p_block_wrote *p = pi->data;
	unsigned int size = pi->size;
	unsigned long *data;
	struct page *page;
	u32 peer_seq = be32_to_cpu(p->seq_num);
	int err, i;
	int count = size/sizeof(pgoff_t);
	pgoff_t *pages_index;
	
	cache_dbg("begin to receive wrote data.\n");
	page = alloc_page(GFP_KERNEL);
	
	data = kmap(page);
	err = cache_recv_all_warn(connection, data, size);
	kunmap(page);
	if (err) {
		cache_err("Error occurs when receive wrote data...\n");
		return err;
	}
	
	cache_dbg("To write out received pages index.\n");
	pages_index = (pgoff_t *)data;
	for(i=0; i<count; i++){
		pgoff_t  index = pages_index[i];
		if(index < 0)
			return -EINVAL;
		cache_del_page(iscsi_cache, index);
	}
	
	cache_dbg("delete wrote data from cache.\n");
	return err;
};

int got_block_ack(struct cache_connection *connection, struct packet_info *pi){
	cache_dbg("receive data ack.\n");
	return 0;
};

static const char *cmdname(enum cache_packet cmd)
{
	/* THINK may need to become several global tables
	 * when we want to support more than
	 * one PRO_VERSION */
	static const char *cmdnames[] = {
		[P_DATA]	        = "Data",
		[P_DATA_REPLY]	        = "DataReply",
		[P_DATA_WRITTEN]	= "DataWritten",
		[P_WRITE_ACK]	        = "WriteAck",
	};

	if (cmd == P_INITIAL_META)
		return "InitialMeta";
	if (cmd == P_INITIAL_DATA)
		return "InitialData";
	if (cmd >= ARRAY_SIZE(cmdnames))
		return "Unknown";
	return cmdnames[cmd];
}

static struct data_cmd cache_cmd_handler[] = {
	[P_DATA]	    = { 1, sizeof(struct p_data), receive_data },
	[P_DATA_REPLY]	    = { 1, sizeof(struct p_data), receive_data_reply },
	[P_DATA_WRITTEN]    = { 1, sizeof(struct p_block_wrote), receive_data_wrote},
	[P_WRITE_ACK]	    = {0,  sizeof(struct p_block_ack), got_block_ack },
};

void cached(struct cache_connection *connection)
{
	struct packet_info pi;
	size_t shs; /* sub header size */
	int err;

	while (get_t_state(&connection->receiver) == RUNNING) {
		struct data_cmd *cmd;

		if (cache_recv_header(connection, &pi))
			goto err_out;
		
		cmd = &cache_cmd_handler[pi.cmd];
		if (unlikely(pi.cmd >= ARRAY_SIZE(cache_cmd_handler) || !cmd->fn)) {
			cache_err("Unexpected data packet %s (0x%04x)\n",
				 cmdname(pi.cmd), pi.cmd);
			goto err_out;
		}

		shs = cmd->pkt_size;
		if (pi.size > shs && !cmd->expect_payload) {
			cache_err("No payload expected %s l:%d\n",
				 cmdname(pi.cmd), pi.size);
			goto err_out;
		}
cache_dbg("Cache cmd is %s.\n", cmdname(pi.cmd));
		if (shs) {
			err = cache_recv_all_warn(connection, pi.data, shs);
			if (err)
				goto err_out;
			pi.size -= shs;
		}

		err = cmd->fn(connection, &pi);
		if (err) {
			cache_err("error receiving %s, e: %d l: %d!\n",
				 cmdname(pi.cmd), err, pi.size);
			goto err_out;
		}
	}
	
	return;
	
err_out:
	cache_err("Error occurs when cached.\n");
	return;
}


