/*
 * ietadm_cache.c - ietd cache management program
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "iet_cache.h"

static char program_name[] = "ietadm_cache";

static struct sockaddr_nl src_addr_adm, dest_addr_adm;

static struct option const long_options[] =
{
	{"op", required_argument, NULL, 'o'},
	{"version", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
iSCSI CACHE Administration daemon.\n\
  --op update        \n\
				update cache state\n\
  --version		display version and exit\n\
  --help			display this help and exit\n\
");
	}
	exit(1);
}

static int str_to_op_cache(char *str)
{
	int op;

	if (!strcmp("update", str))
		op = CACHE_UPDATE;
	else
		op = -1;

	return op;
}

static int ietd_cache_request_send(int fd, struct ietadm_cache_req *req, int len)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct nlmsghdr nlh = {0};

	iov[0].iov_base = &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = req;
	iov[1].iov_len = NLMSG_SPACE(len) - sizeof(nlh);

	nlh.nlmsg_len = NLMSG_SPACE(len);
	nlh.nlmsg_pid = getpid();
	nlh.nlmsg_flags = 0;
	nlh.nlmsg_type = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&dest_addr_adm;
	msg.msg_namelen = sizeof(dest_addr_adm);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	return sendmsg(fd, &msg, 0);}

static int ietd_cache_response_recv(int fd, struct ietadm_cache_req *req, int len)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct nlmsghdr nlh;

	iov[0].iov_base = &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = req;
	iov[1].iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr_adm;
	msg.msg_namelen = sizeof(src_addr_adm);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	return recvmsg(fd, &msg, MSG_WAITALL);//MSG_DONTWAIT);
}

static int ietd_cache_connect(void)
{
	int nl_fd, res=0;

	nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);//NETLINK_GENERIC
	if (nl_fd == -1) {
		printf("%s %d\n", __FUNCTION__, errno);
		return -1;
	}
	
	memset(&src_addr_adm, 0, sizeof(src_addr_adm));
	src_addr_adm.nl_family = AF_NETLINK;
	src_addr_adm.nl_pid = getpid();
	src_addr_adm.nl_groups = 1; 

	memset(&dest_addr_adm, 0, sizeof(dest_addr_adm));
	dest_addr_adm.nl_family = AF_NETLINK;
	dest_addr_adm.nl_pid = 0; 
	dest_addr_adm.nl_groups = 1; 

      res = bind(nl_fd, (struct sockaddr*)&dest_addr_adm, sizeof(dest_addr_adm)); 
        
	if (res < 0) {
		printf("%s %d\n", __FUNCTION__, res);
		return res;
	}

	return nl_fd;


}

static int ietd_cache_request(struct ietadm_cache_req *req, void *rsp_data,
			size_t rsp_data_sz)
{
	int fd = -1, err = -EIO;
	
	if ((fd = ietd_cache_connect()) < 0) {
		err = fd;
		goto out;
	}

	if ((err = ietd_cache_request_send(fd, req, sizeof(struct ietadm_cache_req))) < 0)
		goto out;

retry:
	if ((err = ietd_cache_response_recv(fd, req, sizeof(struct ietadm_cache_req))) < 0) {
		if (errno == EAGAIN)
			goto out;
		if (errno == EINTR)
			goto retry;
	}
	
	printf("ietdadm receive :  req.name= %s  req.rcmnd = %d req.response =%d  req.tid = %d\n", 
		   req->name, req->rcmnd,req->response ,req->lun);
out:
	if (fd > 0)
		close(fd);

	if (err < 0)
		fprintf(stderr, "%s %s.\n", __FUNCTION__, strerror(-err));

	return err;
}

static int ietdadm_cache_sys_handle(int op, char *params)
{
	int err = -EINVAL;
	struct ietadm_cache_req req;

	memset(&req, 0, sizeof(req));

	switch (op) {
	case CACHE_UPDATE:
		req.rcmnd = CACHE_UPDATE;
		req.response = 0;
		req.lun = 0;
		strcpy(req.name , "inspur");
		break;
	default:
		break;
	}
	err = ietd_cache_request(&req, NULL, 0);

	return err;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int err = -EINVAL, op = -1;
	char *params = NULL;

	while ((ch = getopt_long(argc, argv, "o:vh",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'o':
			op = str_to_op_cache(optarg);
			break;
		case 'v':
			printf("%s version %s\n", program_name, IET_CACHE_VERSION);
			exit(0);
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(-1);
		}
	}

	if (op < 0) {
		fprintf(stderr, "You must specify the operation type\n");
		goto out;
	}

	if (optind < argc) {
		fprintf(stderr, "unrecognized: ");
		while (optind < argc)
			fprintf(stderr, "%s", argv[optind++]);
		fprintf(stderr, "\n");
		usage(-1);
	}

	err = ietdadm_cache_sys_handle(op,  params);
	
out:
	return err;
}
