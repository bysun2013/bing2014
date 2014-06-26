/*
 * Event notification code.
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 *
 * Some functions are based on open-iscsi code
 * written by Dmitry Yusupov, Alex Aizman.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <asm/types.h>
#include <sys/socket.h>

#include "iet_cache.h"

static struct sockaddr_nl src_addr_ietd, dest_addr_ietd;

int nl_write_ietd(int fd, void *data, int len)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct nlmsghdr nlh = {0};

	iov[0].iov_base = &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = data;
	iov[1].iov_len = NLMSG_SPACE(len) - sizeof(nlh);

	nlh.nlmsg_len = NLMSG_SPACE(len);
	nlh.nlmsg_pid = getpid();
	nlh.nlmsg_flags = 0;
	nlh.nlmsg_type = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&dest_addr_ietd;
	msg.msg_namelen = sizeof(dest_addr_ietd);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	return sendmsg(fd, &msg, 0);
}

int nl_read_ietd(int fd, void *data, int len)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct nlmsghdr nlh;

	iov[0].iov_base = &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = data;
	iov[1].iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr_ietd;
	msg.msg_namelen = sizeof(src_addr_ietd);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	return recvmsg(fd, &msg, MSG_DONTWAIT);
}

int nl_open_ietd(void)
{
	int nl_fd, res;

	nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);//NETLINK_IET_CACHE
	if (nl_fd == -1) {
		log_error("%s %d\n", __FUNCTION__, errno);
		return -1;
	}

	memset(&src_addr_ietd, 0, sizeof(src_addr_ietd));
	src_addr_ietd.nl_family = AF_NETLINK;
	src_addr_ietd.nl_pid = getpid();
	src_addr_ietd.nl_groups = 1; /* unicast 1*/

	memset(&dest_addr_ietd, 0, sizeof(dest_addr_ietd));
	dest_addr_ietd.nl_family = AF_NETLINK;
	dest_addr_ietd.nl_pid = 0;
	dest_addr_ietd.nl_groups = 1; /* unicast 1*/
	
	res =  bind(nl_fd, (struct sockaddr*)&dest_addr_ietd, sizeof(dest_addr_ietd)); 
	if (res < 0) {
		log_error("%s %d\n", __FUNCTION__, res);
		return res;
	}
	return nl_fd;
}




