/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include "cache_conn.h"

static unsigned int inet_addr(const char* ip)
{
	int a, b, c, d;
	char addr[4];
	sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d);
	addr[0] = a;
	addr[1] = b;
	addr[2] = c;
	addr[3] = d;
	return *(unsigned int *)addr;
}
static char *inet_ntoa(struct in_addr *in)
{
	char* str_ip = NULL;
	u_int32_t int_ip = 0;	
	str_ip = kmalloc(16 * sizeof(char), GFP_KERNEL);
	if (!str_ip)
		return NULL;
	else
		memset(str_ip, 0, 16);
	int_ip = in->s_addr;
	sprintf(str_ip, "%d.%d.%d.%d",  (int_ip) & 0xFF,
		(int_ip >> 8) & 0xFF, (int_ip >> 16) & 0xFF,
		(int_ip >> 24) & 0xFF);	
	return str_ip;
}

static int sock_close(struct socket *sk)
{
	int ret;

	ret = sk->ops->release(sk);

	if (sk)
		sock_release(sk);

	return ret;
}

static int cache_alloc_socket(struct cache_socket *socket)
{
	socket->rbuf = (void *) __get_free_page(GFP_KERNEL);
	if (!socket->rbuf)
		return -ENOMEM;
	socket->sbuf = (void *) __get_free_page(GFP_KERNEL);
	if (!socket->sbuf)
		return -ENOMEM;
	return 0;
}

static void cache_free_socket(struct cache_socket *socket)
{
	free_page((unsigned long) socket->sbuf);
	free_page((unsigned long) socket->rbuf);
}

void cache_free_sock(struct cache_connection *connection)
{
	if (connection->data.socket) {
		mutex_lock(&connection->data.mutex);
		kernel_sock_shutdown(connection->data.socket, SHUT_RDWR);
		sock_close(connection->data.socket);
		connection->data.socket = NULL;
		mutex_unlock(&connection->data.mutex);
	}
	if (connection->meta.socket) {
		mutex_lock(&connection->meta.mutex);
		kernel_sock_shutdown(connection->meta.socket, SHUT_RDWR);
		sock_close(connection->meta.socket);
		connection->meta.socket = NULL;
		mutex_unlock(&connection->meta.mutex);
	}
}

static void cache_init_workqueue(struct cache_work_queue* wq)
{
	spin_lock_init(&wq->q_lock);
	INIT_LIST_HEAD(&wq->q);
	init_waitqueue_head(&wq->q_wait);
}

static void cache_thread_init(struct cache_thread *thi,
			     int (*func) (struct cache_thread *), const char *name)
{
	spin_lock_init(&thi->t_lock);
	thi->task    = NULL;
	thi->t_state = NONE;
	thi->function = func;
	thi->connection = NULL;
	thi->name = name;
}

static int cache_thread_setup(void *arg)
{
	struct cache_thread *thi = (struct cache_thread *) arg;
	unsigned long flags;
	int retval;

restart:
	retval = thi->function(thi);

	spin_lock_irqsave(&thi->t_lock, flags);

	if (thi->t_state == RESTARTING) {
		cache_info("Restarting %s thread\n", thi->name);
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		goto restart;
	}

	thi->task = NULL;
	thi->t_state = NONE;
	smp_mb();
	complete_all(&thi->stop);
	spin_unlock_irqrestore(&thi->t_lock, flags);

	//module_put(THIS_MODULE);
	cache_info("Terminating\n");

	return retval;
}

int cache_thread_start(struct cache_thread *thi)
{
	struct task_struct *nt;
	unsigned long flags;

	/* is used from state engine doing cache_thread_stop_nowait,
	 * while holding the req lock irqsave */
	spin_lock_irqsave(&thi->t_lock, flags);

	switch (thi->t_state) {
	case NONE:
		cache_info("Starting %s thread\n", thi->name);

		/* Get ref on module for thread - this is released when thread exits 
		if (!try_module_get(THIS_MODULE)) {
			cache_err("Failed to get module reference in cache_thread_start\n");
			spin_unlock_irqrestore(&thi->t_lock, flags);
			return false;
		}
		

		if (thi->connection)
			kref_get(&thi->connection->kref);
		
*/
		init_completion(&thi->stop);
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		flush_signals(current);  //otherw. may get -ERESTARTNOINTR

		nt = kthread_create(cache_thread_setup, (void *) thi,
				    "cache_%s", thi->name);

		if (IS_ERR(nt)) {
			cache_err("Couldn't start thread\n");
/*
			if (thi->connection)
				kref_put(&thi->connection->kref, cache_destroy_connection);
*/
			//module_put(THIS_MODULE);
			return false;
		}
		spin_lock_irqsave(&thi->t_lock, flags);
		thi->task = nt;
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		wake_up_process(nt);
		break;
	case EXITING:
		thi->t_state = RESTARTING;
		cache_info("Restarting %s thread ([%d])\n", thi->name, current->pid);
		/* fall through */
	case RUNNING:
	case RESTARTING:
	default:
		spin_unlock_irqrestore(&thi->t_lock, flags);
		break;
	}

	return true;
}

void _cache_thread_stop(struct cache_thread *thi, int restart, int wait)
{
	unsigned long flags;

	enum cache_thread_state ns = restart ? RESTARTING : EXITING;
	cache_alert("begin to kill thread %s\n", thi->name);
	/* may be called from state engine, holding the req lock irqsave */
	spin_lock_irqsave(&thi->t_lock, flags);

	if (thi->t_state == NONE) {
		spin_unlock_irqrestore(&thi->t_lock, flags);
		if (restart)
			cache_thread_start(thi);
		return;
	}

	if (thi->t_state != ns) {
		if (thi->task == NULL) {
			spin_unlock_irqrestore(&thi->t_lock, flags);
			return;
		}

		thi->t_state = ns;
		smp_mb();
		init_completion(&thi->stop);
	}
	spin_unlock_irqrestore(&thi->t_lock, flags);

	if (wait)
		wait_for_completion(&thi->stop);
	cache_alert("Thread %s exit.\n", thi->name);
}

static struct socket *cache_wait_for_connect(struct cache_connection *connection, struct accept_wait_data *ad)
{
	int err = 0;
	struct socket *s_estab = NULL;
/*
	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return NULL;
	}
	connect_int = nc->connect_int;
	rcu_read_unlock();

	timeo = connect_int * HZ;
	timeo += (prandom_u32() & 1) ? timeo / 7 : -timeo / 7; 

	err = wait_for_completion_interruptible_timeout(&ad->door_bell, timeo);
	if (err <= 0)
		return NULL;
*/
	cache_err("Server waits for accept.\n");
	err = kernel_accept(ad->s_listen, &s_estab, 0);
	if (err < 0) {
		if (err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS) {
			cache_err("accept failed, err = %d\n", err);
		}
	}
/*
	if (s_estab)
		unregister_state_change(s_estab->sk, ad);
*/	
	cache_err("Server finish accept.\n");
	return s_estab;
}

static struct socket *cache_try_connect(struct cache_connection *connection)
{
	const char *what;
	struct socket *sock;
	struct sockaddr_in6 src_in6;
	struct sockaddr_in6 peer_in6;

	int err, peer_addr_len, my_addr_len;
	int sndbuf_size, rcvbuf_size, connect_int = 5;
	int disconnect_on_error = 1;
/*
	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return NULL;
	}
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	connect_int = nc->connect_int;
	rcu_read_unlock();
*/
	my_addr_len = min_t(int, connection->my_addr_len, sizeof(src_in6));
	memcpy(&src_in6, &connection->my_addr, my_addr_len);

	if (((struct sockaddr *)&connection->my_addr)->sa_family == AF_INET6)
		src_in6.sin6_port = 0;
	else
		((struct sockaddr_in *)&src_in6)->sin_port = 0; /* AF_INET & AF_SCI */

	peer_addr_len = min_t(int, connection->peer_addr_len, sizeof(src_in6));
	memcpy(&peer_in6, &connection->peer_addr, peer_addr_len);

	what = "sock_create_kern";
	err = sock_create_kern(((struct sockaddr *)&src_in6)->sa_family,
			       SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0) {
		sock = NULL;
		goto out;
	}

//	sock->sk->sk_rcvtimeo =
//	sock->sk->sk_sndtimeo = connect_int * HZ;
//cache_setbufsize(sock, sndbuf_size, rcvbuf_size);

       /* explicitly bind to the configured IP as source IP
	*  for the outgoing connections.
	*  This is needed for multihomed hosts and to be
	*  able to use lo: interfaces for cache.
	* Make sure to use 0 as port number, so linux selects
	*  a free one dynamically.
	*/
	what = "bind before connect";
	err = sock->ops->bind(sock, (struct sockaddr *) &src_in6, my_addr_len);
	if (err < 0)
		goto out;

	/* connect may fail, peer not yet available.
	 * stay C_WF_CONNECTION, don't go Disconnecting! */
	disconnect_on_error = 0;
	what = "connect";
	err = sock->ops->connect(sock, (struct sockaddr *) &peer_in6, peer_addr_len, 0);

out:
	if (err < 0) {
		if (sock) {
			sock_release(sock);
			sock = NULL;
		}
		switch (-err) {
			/* timeout, busy, signal pending */
		case ETIMEDOUT: case EAGAIN: case EINPROGRESS:
		case EINTR: case ERESTARTSYS:
			/* peer not (yet) available, network problem */
		case ECONNREFUSED: case ENETUNREACH:
		case EHOSTDOWN:    case EHOSTUNREACH:
			disconnect_on_error = 0;
			break;
		default:
			cache_err("connect peer: %s failed, err = %d\n", what, err);
			break;
		}
	}

	return sock;
}

static int prepare_listen_socket(struct cache_connection *connection, struct accept_wait_data *ad)
{
	int err, my_addr_len;
//	int sndbuf_size, rcvbuf_size,
	struct sockaddr_in6 my_addr;
	struct socket *s_listen;
	const char *what;
/*
	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EIO;
	}
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	rcu_read_unlock();
*/
	my_addr_len = min_t(int, connection->my_addr_len, sizeof(struct sockaddr_in6));
	memcpy(&my_addr, &connection->my_addr, my_addr_len);

	what = "sock_create_kern";
	err = sock_create_kern(((struct sockaddr *)&my_addr)->sa_family,
			       SOCK_STREAM, IPPROTO_TCP, &s_listen);
	if (err) {
		s_listen = NULL;
		goto out;
	}

	s_listen->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	//cache_setbufsize(s_listen, sndbuf_size, rcvbuf_size);

	what = "bind before listen";
	err = s_listen->ops->bind(s_listen, (struct sockaddr *)&my_addr, my_addr_len);
	if (err < 0)
		goto out;

	ad->s_listen = s_listen;
/*
	write_lock_bh(&s_listen->sk->sk_callback_lock);
	ad->original_sk_state_change = s_listen->sk->sk_state_change;
	s_listen->sk->sk_state_change = cache_incoming_connection;
	s_listen->sk->sk_user_data = ad;
	write_unlock_bh(&s_listen->sk->sk_callback_lock);
*/
	what = "listen";
	err = s_listen->ops->listen(s_listen, 5);
	if (err < 0)
		goto out;

	return 0;
out:
	if (s_listen){
		sock_close(s_listen);
	}
	if (err < 0) {
		if (err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS) {
			cache_err("server: %s failed, err = %d\n", what, err);
		}
	}
	return -EIO;
}

/*
 * return values:
 *   1 yes, we have a valid connection
 *   0 oops, did not work out, please try again
 *  -1 peer talks different language,
 *     no point in trying again, please go standalone.
 *  -2 We do not have a network config...
 */
static int conn_connect(struct cache_connection *connection)
{
	struct cache_socket sock, msock;

//	struct net_conf *nc;
//	int timeout, h, ok;
	int ping_timeo = 20;

	int h=0, count=0;

	struct accept_wait_data ad = {
		.connection = connection,
		.door_bell = COMPLETION_INITIALIZER_ONSTACK(ad.door_bell),
	};

	mutex_init(&sock.mutex);
	sock.sbuf = connection->data.sbuf;
	sock.rbuf = connection->data.rbuf;
	sock.socket = NULL;
	mutex_init(&msock.mutex);
	msock.sbuf = connection->meta.sbuf;
	msock.rbuf = connection->meta.rbuf;
	msock.socket = NULL;

	if (prepare_listen_socket(connection, &ad))
		return -1;

	do {
		struct socket *s;

		s = cache_try_connect(connection);
		if (s) {
			if (!sock.socket) {
				sock.socket = s;
				send_first_packet(connection, &sock, P_INITIAL_DATA);
			} else if (!msock.socket) {
				msock.socket = s;
				send_first_packet(connection, &msock, P_INITIAL_META);
			} else {
				cache_err("Logic error in conn_connect()\n");
				goto out_release_sockets;
			}
		}
		if (sock.socket && msock.socket) {
			break;
		}
/*
		if (sock.socket && msock.socket) {
			
			rcu_read_lock();
			nc = rcu_dereference(connection->net_conf);
			timeout = nc->ping_timeo * HZ / 10;
			rcu_read_unlock();
			schedule_timeout_interruptible(timeout);
			ok = cache_socket_okay(&sock.socket);
			ok = cache_socket_okay(&msock.socket) && ok;
			if (ok)
				break;
		}
*/
retry:	
		s = cache_wait_for_connect(connection, &ad);

		if (s) {
			int fp = receive_first_packet(connection, s);
			//cache_socket_okay(&sock.socket);
			//cache_socket_okay(&msock.socket);
			switch (fp) {
			case P_INITIAL_DATA:
				if (sock.socket) {
					cache_alert("initial packet S crossed\n");
					sock_release(sock.socket);
					sock.socket = s;
					goto randomize;
				}
				sock.socket = s;
				cache_alert("receiving initial data packet\n");
				break;
			case P_INITIAL_META:
				if (msock.socket) {
					cache_alert( "initial packet M crossed\n");
					sock_release(msock.socket);
					msock.socket = s;
					goto randomize;
				}
				msock.socket = s;
				cache_alert("receiving initial meta packet\n");
				break;
			default:
				cache_alert("Error receiving initial packet\n");
				sock_release(s);
randomize:
				if (prandom_u32() & 1)
					goto retry;
			}
		}
		
		if (sock.socket && msock.socket) {
			break;
		}
/*
		if (connection->cstate <= C_DISCONNECTING)
			goto out_release_sockets;
		if (signal_pending(current)) {
			flush_signals(current);
			smp_rmb();
			if (get_t_state(&connection->receiver) == EXITING)
				goto out_release_sockets;
		}

		ok = cache_socket_okay(&sock.socket);
		ok = cache_socket_okay(&msock.socket) && ok;
	} while (!ok);
*/	
	count++;
	cache_warn("Try to establish connection, count = %d\n", count);
	}while(count < 5);
	
	if (ad.s_listen){
		sock_close(ad.s_listen);
	}

	sock.socket->sk->sk_reuse = SK_CAN_REUSE;
	msock.socket->sk->sk_reuse = SK_CAN_REUSE;

	sock.socket->sk->sk_allocation = GFP_NOIO;
	msock.socket->sk->sk_allocation = GFP_NOIO;

//	sock.socket->sk->sk_priority = TC_PRIO_INTERACTIVE_BULK;
//	msock.socket->sk->sk_priority = TC_PRIO_INTERACTIVE;
	
	sock.socket->sk->sk_sndtimeo =
	sock.socket->sk->sk_rcvtimeo = ping_timeo*HZ;

	/* NOT YET ...
	 * sock.socket->sk->sk_sndtimeo = connection->net_conf->timeout*HZ/10;
	 * sock.socket->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;
	 * first set it to the P_CONNECTION_FEATURES timeout,
	 * which we set to 4x the configured ping_timeout. */
/*
	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);

	sock.socket->sk->sk_sndtimeo =
	sock.socket->sk->sk_rcvtimeo = nc->ping_timeo*4*HZ/10;

	msock.socket->sk->sk_rcvtimeo = nc->ping_int*HZ;
	timeout = nc->timeout * HZ / 10;
	discard_my_data = nc->discard_my_data;
	rcu_read_unlock();

	msock.socket->sk->sk_sndtimeo = timeout;
*/
	/* we don't want delays.
	 * we use TCP_CORK where appropriate, though */
	cache_tcp_nodelay(sock.socket);
	cache_tcp_nodelay(msock.socket);

	connection->data.socket = sock.socket;
	connection->meta.socket = msock.socket;
	connection->last_received = jiffies;

//	connection->data.socket->sk->sk_sndtimeo = timeout;
//	connection->data.socket->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;

//	cache_thread_start(&connection->asender);

	return h;

out_release_sockets:
	if (ad.s_listen)
		sock_close(ad.s_listen);
	if (sock.socket)
		sock_close(sock.socket);
	if (msock.socket)
		sock_close(msock.socket);
	return -1;
}

static void conn_disconnect(struct cache_connection *connection)
{
	//if (connection->cstate == C_STANDALONE)
	//	return;

	cache_free_sock(connection);
	cache_alert("Connection closed\n");
}

int cache_receiver(struct cache_thread *thi)
{
	struct cache_connection *connection = thi->connection;
	int h;
	int count = 10;
	cache_info("receiver (re)started\n");

	do {
		cache_dbg("Try to establish connection.\n");
		h = conn_connect(connection);
	} while (h == -1 && count --);
	
	if (h == 0){
		cache_dbg("Good, it works.\n");
		cache_thread_start(&connection->asender);
		cached(connection);
	}
	
	conn_disconnect(connection);
	cache_info("receiver terminated\n");
	
	return 0;
}

static struct cache_connection *cache_conn_create(struct iscsi_cache *iscsi_cache)
{
	struct cache_connection *connection;
	struct sockaddr_in my_addr, peer_addr;

	connection = kzalloc(sizeof(struct cache_connection), GFP_KERNEL);
	if (!connection)
		return NULL;
	
	connection->iscsi_cache = iscsi_cache;

	if (cache_alloc_socket(&connection->data))
		goto fail;
	if (cache_alloc_socket(&connection->meta))
		goto fail;
/*
	connection->current_epoch = kzalloc(sizeof(struct cache_epoch), GFP_KERNEL);
	if (!connection->current_epoch)
		goto fail;

	INIT_LIST_HEAD(&connection->current_epoch->list);
	connection->epochs = 1;
	spin_lock_init(&connection->epoch_lock);
*/
	
	connection->cstate = C_STANDALONE;
	mutex_init(&connection->cstate_mutex);
	init_waitqueue_head(&connection->ping_wait);
	kref_init(&connection->kref);

	cache_init_workqueue(&connection->sender_work);
	mutex_init(&connection->data.mutex);
	mutex_init(&connection->meta.mutex);

	memset(&my_addr, 0, sizeof(my_addr));
	memset(&peer_addr, 0, sizeof(peer_addr));
	connection->my_addr_len = sizeof(my_addr);
	connection->peer_addr_len = sizeof(peer_addr);
	atomic_set(&connection->packet_seq, 0);
	
	spin_lock_init(&connection->request_list_lock);
	atomic_set(&connection->nr_cmnds, 0);
	INIT_LIST_HEAD(&connection->request_list);
	
	my_addr.sin_family=AF_INET;
	my_addr.sin_addr.s_addr=inet_addr(iscsi_cache->inet_addr);
	my_addr.sin_port=htons(iscsi_cache->port);
	memcpy(&connection->my_addr, &my_addr, sizeof(my_addr));
	
	peer_addr.sin_family=AF_INET;
	peer_addr.sin_addr.s_addr=inet_addr(iscsi_cache->inet_peer_addr);
	peer_addr.sin_port=htons(iscsi_cache->port);
	memcpy(&connection->peer_addr, &peer_addr, sizeof(peer_addr));

	cache_thread_init(&connection->receiver, cache_receiver, "dreceiver");
	connection->receiver.connection = connection;
	cache_thread_init(&connection->asender, cache_wb_receiver, "wreceiver");
	connection->asender.connection = connection;

	cache_thread_start(&connection->receiver);
	
	return connection;

fail:
	kfree(connection->current_epoch);
	cache_free_socket(&connection->meta);
	cache_free_socket(&connection->data);
	kfree(connection);
	return NULL;
}


static void cache_conn_destroy(struct iscsi_cache *iscsi_cache)
{
	struct cache_connection *cache_conn;
/*
	if (atomic_read(&cache_conn->current_epoch->epoch_size) !=  0)
		cache_err("epoch_size:%d\n", atomic_read(&cache_conn->current_epoch->epoch_size));
	kfree(cache_conn->current_epoch);
*/
	if(!iscsi_cache)
		return;
	
	if(!(cache_conn = iscsi_cache->conn))
		return;

	/* FIXME thread crash when exit */
	cache_thread_stop_nowait(&cache_conn->asender);
	cache_thread_stop_nowait(&cache_conn->receiver);
	
	conn_disconnect(cache_conn);
	cache_free_socket(&cache_conn->meta);
	cache_free_socket(&cache_conn->data);
	kfree(cache_conn);
	iscsi_cache->conn = NULL;
}

struct cache_connection *cache_conn_init(struct iscsi_cache *iscsi_cache)
{
	struct cache_connection * conn;
	
	cache_alert("Start connection between caches!\n");
	
	conn = cache_conn_create(iscsi_cache);
	
	return conn;
}

int cache_conn_exit(struct iscsi_cache *iscsi_cache)
{
	cache_conn_destroy(iscsi_cache);
	
	cache_alert("Destroy connection between caches!\n");
	return 0;
}

