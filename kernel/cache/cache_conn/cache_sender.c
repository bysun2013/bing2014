/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include "cache_conn.h"

/**
 * cache_header_size  -  size of a packet header
 *
 * The header size is a multiple of 8, so any payload following the header is
 * word aligned on 64-bit architectures.  (The bitmap send and receive code
 * relies on this.)
 */
unsigned int cache_header_size(struct cache_connection *conn)
{
	return sizeof(struct p_header80);
}

static void *conn_prepare_command(struct cache_connection *conn, struct cache_socket *sock)
{
	void *p;

	mutex_lock(&sock->mutex);
	if (!sock->socket){
		p = NULL;
		mutex_unlock(&sock->mutex);
	}else
		p = sock->sbuf + cache_header_size(conn);	

	return p;
}

static unsigned int prepare_header80(struct p_header80 *h, enum cache_packet cmd, int size)
{
	h->magic   = cpu_to_be16(CACHE_MAGIC);
	h->command = cpu_to_be16(cmd);
	h->length  = cpu_to_be32(size);
	return sizeof(struct p_header80);
}

static unsigned int prepare_header(struct cache_connection *conn, 
							void *buffer, enum cache_packet cmd, int size)
{
		return prepare_header80(buffer, cmd, size);
}

/*
 * you must have down()ed the appropriate [m]sock_mutex elsewhere!
 */
static int cache_send(struct cache_connection *connection, struct socket *sock,
	      void *buf, size_t size, unsigned msg_flags)
{
	struct kvec iov;
	struct msghdr msg;
	int rv, sent = 0;

	if (!sock)
		return -EBADR;

	/* THINK  if (signal_pending) return ... ? */

	iov.iov_base = buf;
	iov.iov_len  = size;

	msg.msg_name       = NULL;
	msg.msg_namelen    = 0;
	msg.msg_control    = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags      = msg_flags | MSG_NOSIGNAL;

	do {
		/* STRANGE
		 * tcp_sendmsg does _not_ use its size parameter at all ?
		 *
		 * -EAGAIN on timeout, -EINTR on signal.
		 */
/* THINK
 * do we need to block cache_SIG if sock == &meta.socket ??
 * otherwise wake_asender() might interrupt some send_*Ack !
 */

		rv = kernel_sendmsg(sock, &msg, &iov, 1, size);
		if (rv == -EAGAIN) {
			cache_warn("Send data fail, try again.\n");
			continue;
		}
		if (rv == -EINTR) {
			flush_signals(current);
			rv = 0;
		}
		if (rv < 0)
			break;
		sent += rv;
		iov.iov_base += rv;
		iov.iov_len  -= rv;
	} while (sent < size);
/*
	if (sock == connection->data.socket)
		clear_bit(NET_CONGESTED, &connection->flags);
*/
	if (rv <= 0) {
		if (rv != -EAGAIN) {
			cache_err("%s_sendmsg returned %d\n",
				 sock == connection->meta.socket ? "msock" : "sock",
				 rv);
//			conn_request_state(connection, NS(conn, C_BROKEN_PIPE), CS_HARD);
		} //else
			//conn_request_state(connection, NS(conn, C_TIMEOUT), CS_HARD);*/
	}

	return sent;
}

/**
 * cache_send_all  -  Send an entire buffer
 *
 * Returns 0 upon success and a negative error value otherwise.
 */
static int cache_send_all(struct cache_connection *connection, struct socket *sock, void *buffer,
		  size_t size, unsigned msg_flags)
{
	int err;

	err = cache_send(connection, sock, buffer, size, msg_flags);
	if (err < 0)
		return err;
	if (err != size)
		return -EIO;
	return 0;
}

/**
*	@size: total cache data 
*/
static int __send_command(struct cache_connection *conn,
			  struct cache_socket *sock, enum cache_packet cmd,
			  unsigned int header_size, void *data,
			  unsigned int size)
{
	int msg_flags;
	int err;

	/*
	 * Called with @data == NULL and the size of the data blocks in @size
	 * for commands that send data blocks.  For those commands, omit the
	 * MSG_MORE flag: this will increase the likelihood that data blocks
	 * which are page aligned on the sender will end up page aligned on the
	 * receiver.
	 */
	msg_flags = data ? MSG_MORE : 0;

	header_size += prepare_header(conn, sock->sbuf, cmd,
				      header_size + size);
	err = cache_send_all(conn, sock->socket, sock->sbuf, header_size,
			    msg_flags);
	if (data && !err)
		err = cache_send_all(conn, sock->socket, data, size, 0);
	return err;
}

static int conn_send_command(struct cache_connection *tconn, struct cache_socket *sock,
		      enum cache_packet cmd, unsigned int header_size,
		      void *data, unsigned int size)
{
	int err;

	err = __send_command(tconn, sock, cmd, header_size, data, size);
	mutex_unlock(&sock->mutex);
	return err;
}


int send_first_packet(struct cache_connection *connection, struct cache_socket *sock,
			     enum cache_packet cmd)
{
	if (!conn_prepare_command(connection, sock))
		return -EIO;
	return conn_send_command(connection, sock, cmd, 0, NULL, 0);
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

static int _cache_send_page(struct cache_connection*conn, struct page *page,
		    int offset, size_t size, unsigned msg_flags)
{
	struct socket *socket = conn->data.socket;
	mm_segment_t oldfs = get_fs();
	int len = size;
	int err = -EIO;

	if ((page_count(page) < 1) || PageSlab(page))
		return _cache_no_send_page(conn, page, offset, size, msg_flags);

	msg_flags |= MSG_NOSIGNAL;

	set_fs(KERNEL_DS);
	do {
		int sent;

		sent = socket->ops->sendpage(socket, page, offset, len, msg_flags);
		if (sent <= 0) {
			if (sent == -EAGAIN) {
				cache_warn("send page fail, try again.\n");
				continue;
			}
			if (sent < 0)
				err = sent;
			break;
		}
		len    -= sent;
		offset += sent;
	} while (len > 0);
	set_fs(oldfs);

	if (len == 0)
		err = 0;
	
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

static int _cache_send_zc_pages(struct cache_connection *conn, struct page **pages, 
				int count, size_t size, sector_t sector)
{
	int i;
	/* hint all but last page with MSG_MORE */
	for (i = 0; i < count; i++){
		int err, write;
		write = min_t(int, PAGE_SIZE, size);
		err = _cache_send_page(conn, pages[i],
					 0, write,
					 i == count - 1 ? 0 : MSG_MORE);
		if (err)
			return err;
	}
	return 0;
}

int cache_send_dblock(struct cache_connection *connection, struct page **pages, 
				int count, u32 size, sector_t sector, struct cache_request ** req)
{
	struct cache_socket *sock;
	struct p_data *p;
	u32 seq_num;
	int err;

	sock = &connection->data;
	
	p = conn_prepare_command(connection, sock);
	if (!p)
		return -EIO;
	
	seq_num= atomic_inc_return(&connection->packet_seq);
	p->sector = cpu_to_be64(sector);
	p->block_id = (unsigned long)pages;
	p->seq_num = cpu_to_be32(seq_num);
	
	cache_dbg("begin to send cmd.\n");
	err = __send_command(connection, sock, P_DATA, sizeof(*p), NULL, size); /* size of total data written to device */
	
	cache_dbg("finish sending cmd, begin to send data.\n");
	if (!err) {
		err = _cache_send_zc_pages(connection, pages, count, size, sector);
	}
	cache_dbg("finish sending data.\n");
	
	mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */

	*req = cache_request_alloc(connection, seq_num);
	cache_request_enqueue(*req);

	return err;
}

int cache_send_wrote(struct cache_connection *connection, pgoff_t *pages_index, int count)
{
	struct cache_socket *sock;
	struct p_block_wrote *p;
	struct socket * socket;
	int err;
	int size = sizeof(pgoff_t)*count;
	
	sock = &connection->meta;
	socket = sock->socket;
	
	p = conn_prepare_command(connection, sock);
	if (!p)
		return -EIO;

	p->seq_num = cpu_to_be32(atomic_inc_return(&connection->packet_seq));

	cache_dbg("begin to send wrote data.\n");
	err = __send_command(connection, sock, P_DATA_WRITTEN, sizeof(*p), NULL, size);
	if (!err) {
		err = cache_send(connection, socket, pages_index, size, 0);
	}
	cache_dbg("finish sending wrote data.\n");
	
	mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */	
	
	return err;
}

int cache_send_data_ack(struct cache_connection *connection,  u32 seq_num, u64 sector)
{
	struct cache_socket *sock;
	struct p_block_ack *p;
	struct socket * socket;
	int err;
	
	sock = &connection->meta;
	socket = sock->socket;
	
	p = conn_prepare_command(connection, sock);
	if (!p)
		return -EIO;

	p->seq_num = cpu_to_be32(seq_num);
	p->sector = cpu_to_be64(sector);

	cache_dbg("begin to send data ack.\n");
	err = __send_command(connection, sock, P_WRITE_ACK, sizeof(*p), NULL, 0);

	cache_dbg("finish sending data ack.\n");
	
	mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */	
	
	return err;
}

