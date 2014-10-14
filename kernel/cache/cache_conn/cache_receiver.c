/*
 * cache_conn/cache_receiver.c
 *
 * according to cmd, execute corresponding callback(receive different data)
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


#include "../cache_def.h"
#include "../cache.h"
#include "cache_conn.h"
#include "../cache_config.h"

static int decode_header(struct cache_connection *conn, void *header, struct packet_info *pi)
{
	unsigned int header_size = cache_header_size(conn);

	if (header_size == sizeof(struct p_header80) &&
		   *(__be16 *)header == cpu_to_be16(CACHE_MAGIC)) {
		struct p_header80 *h = header;
		pi->cmd = be16_to_cpu(h->command);
		pi->size = be32_to_cpu(h->length);
		pi->vnr = 0;
	} else {
		cache_err("Wrong magic value 0x%08x.\n",
			 be16_to_cpu(*(__be16 *)header));
		return -EINVAL;
	}
	pi->data = header + header_size;
	return 0;
}

int cache_recv_short(struct socket *sock, void *buf, size_t size, int flags)
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

static int cache_recv(struct cache_socket *cache_socket, void *buf, size_t size)
{
	int rv;

	rv = cache_recv_short(cache_socket->socket, buf, size, 0);

	if (rv < 0) {
		cache_err( "sock_recvmsg returned %d\n", rv);
		if (rv == -ECONNRESET)
			cache_info("sock was reset by peer\n");
	} else if (rv == 0) {
		cache_info("sock was shut down by peer\n");
		hb_change_state();
	}
	
	return rv;
}

static int cache_recv_all(struct cache_socket *cache_socket, void *buf, size_t size)
{
	int err;

	err = cache_recv(cache_socket, buf, size);
	if (err != size) {
		if (err >= 0)
			err = -EIO;
	} else
		err = 0;
	return err;
}

static int cache_recv_all_warn(struct cache_socket *cache_socket, void *buf, size_t size)
{
	int err;

	err = cache_recv_all(cache_socket, buf, size);
	if (err && err != -EAGAIN && !signal_pending(current))
		cache_warn("short read (expected size %d)\n", (int)size);
	return err;
}

int cache_recv_header(struct cache_connection *connection, struct cache_socket *cache_socket, 
	struct packet_info *pi)
{

	void *buffer = cache_socket->rbuf;
	int err;

	err = cache_recv_all_warn(cache_socket, buffer, cache_header_size(connection));
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

/* used from receive_Data, with data sock */
static struct cio* read_in_block(struct cache_connection *connection, sector_t sector,
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
	
	for(i=0;i<nr_pages; i++){
		unsigned len = min_t(int, ds, PAGE_SIZE);
		page = req->pvec[i];
		data = kmap(page);
		err = cache_recv_all_warn(&connection->data, data, len);
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

static int receive_data(struct cache_connection * connection, struct packet_info * pi)
{
	struct dcache *dcache = connection->dcache;
	struct cio * req;
	struct p_data *p = pi->data;
	u32 peer_seq = be32_to_cpu(p->seq_num);
	sector_t sector = be64_to_cpu(p->sector);

	cache_dbg("begin to receive data.\n");
	
	req = read_in_block(connection, sector, pi);
	if (!req) {
		cache_err("Error occurs when receive data.\n");
		return -EIO;
	}
	
	cache_dbg("To write received data.\n");
	_dcache_write((void *)dcache, req->pvec, req->pg_cnt, req->size, req->offset, REQUEST_FROM_PEER);

	cache_send_data_ack(connection,peer_seq, sector);

	cio_put(req);
	
	cache_dbg("write received data into cache.\n");
	return 0;
}

/* 
* use msock to receive writeback index 
*/
static int receive_wrote(struct cache_connection *connection, struct packet_info *pi)
{
	struct dcache *dcache = connection->dcache;
	struct p_block_wrote *p = pi->data;
	unsigned int size = pi->size;
	int count = size/sizeof(pgoff_t);
	pgoff_t *data;
	pgoff_t *pages_index;
	u32 peer_seq = be32_to_cpu(p->seq_num);
	int err, i;

	data = (pgoff_t *)kzalloc(size, GFP_KERNEL);
	if (!data){
		cache_err("Out of memory!\n");
		return -ENOMEM;
	}

	cache_dbg("begin to receive wrote data.\n");
	
	err = cache_recv_all_warn(&connection->meta, data, size);
	if (err) {
		cache_err("Error occurs when receive wrote data...\n");
		return err;
	}
	
	pages_index = data;
	for(i=0; i < count; i++) {
		pgoff_t  index = pages_index[i];
		if(index == -1)
			break;
		if(index < 0){
			cache_err("Error occurs, index is %ld.\n", index);
			return -EINVAL;
		}
		dcache_clean_page(dcache, index);
	}

	cache_send_wrote_ack(connection,peer_seq);

	cache_dbg("delete wrote data from cache.\n");

	kfree(data);
	return err;
}

static int got_block_ack(struct cache_connection *connection, struct packet_info *pi)
{
	struct cache_request * req;
	struct p_block_ack *p = pi->data;
	u32 seq_num = be32_to_cpu(p->seq_num);

	req = get_ready_request(connection, seq_num);
	if(!req)
		return 0;

	complete(&req->done);

	cache_dbg("receive data ack.\n");
	return 0;
}

static int got_wrote_ack(struct cache_connection *connection, struct packet_info *pi)
{
	struct cache_request * req;
	struct p_wrote_ack *p = pi->data;
	u32 seq_num = be32_to_cpu(p->seq_num);

	req = get_ready_request(connection, seq_num);
	if(!req)
		return 0;

	complete(&req->done);

	cache_dbg("receive wrote ack.\n");
	return 0;
}

static const char *cmdname(enum cache_packet cmd)
{
	/* THINK may need to become several global tables
	 * when we want to support more than
	 * one PRO_VERSION */
	static const char *cmdnames[] = {
		[P_DATA]	        = "Data",
		[P_DATA_WRITTEN]	= "DataWritten",
		[P_DATA_ACK]	        = "DataAck",
		[P_WRITTEN_ACK]	        = "WrittenAck",
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
	[P_DATA_WRITTEN]    = { 1, sizeof(struct p_block_wrote), receive_wrote},
	[P_DATA_ACK]	    = {0,  sizeof(struct p_block_ack), got_block_ack },
	[P_WRITTEN_ACK]	    = {0,  sizeof(struct p_wrote_ack), got_wrote_ack },
};

void cache_socket_receive(struct cache_connection *connection)
{
	struct packet_info pi;
	size_t shs; /* sub header size */
	int err;

	while (get_t_state(&connection->receiver) == RUNNING) {
		struct data_cmd *cmd;

		err = cache_recv_header(connection, &connection->data, &pi);
		if(err < 0){
			if (err == -EAGAIN && peer_is_good)
				continue;
			goto err_out;
		}
		WARN_ON(pi.cmd != P_DATA);
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
			err = cache_recv_all_warn(&connection->data, pi.data, shs);
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
	
err_out:
	return;
}

/*
* it deal with sync of writeback index and all ack 
*/
int cache_msocket_receive(struct cache_connection *connection)
{
	struct packet_info pi;
	size_t shs; /* sub header size */
	int err = 0;

	while (get_t_state(&connection->asender) == RUNNING) {
		struct data_cmd *cmd;

		err = cache_recv_header(connection, &connection->meta, &pi);
		if(err < 0){
			if (likely(err == -EAGAIN))
				continue;
			goto err_out;
		}

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
			err = cache_recv_all_warn(&connection->meta, pi.data, shs);
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
	
	return err;
	
err_out:
	cache_err("Error occurs when receive on msocket.\n");
	return err;
}

