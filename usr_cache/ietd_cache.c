/*
 * ietd_cache.c - ietd cache management program
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "iet_cache.h"

static char program_name[] = "ietd_cache";

struct pollfd poll_array[POLL_MAX];

int ctrl_fd_cache, nl_fd_ietd;

static struct option const long_options[] =
{
	{"config", required_argument, 0, 'c'},
	{"foreground", no_argument, 0, 'f'},
	{"debug", required_argument, 0, 'd'},
	{"uid", required_argument, 0, 'u'},
	{"gid", required_argument, 0, 'g'},
	{"address", required_argument, 0, 'a'},
	{"port", required_argument, 0, 'p'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

/* This will be configurable by command line options */
extern struct config_operations cache_plain_ops;
struct config_operations *cache_cops = &cache_plain_ops;

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
iSCSI CACHE daemon.\n\
	-c, --config=[path]		Execute in the config file.\n \
	-f, --foreground		make the program run in the foreground\n \
	-v, --version			display the program version \n \
	-h, --help			display this help and exit\n \
");
	}
	exit(1);
}

static int check_version(void)
{
	struct cache_module_info info;
	int err;

	memset(&info, 0x0, sizeof(info));

	err = cache_ki->module_info(&info);
	if (err)
		return 0;

	return !strncmp(info.version, IET_CACHE_VERSION, sizeof(info.version));
}

void event_loop_cache(int timeout)
{
	int res;

	poll_array[POLL_ADM].fd = nl_fd_ietd;
	poll_array[POLL_ADM].events = POLLIN;

	while (1) {
		res = poll(poll_array, POLL_MAX, timeout);
		if (res < 0) {
			if (res < 0 && errno != EINTR) {
				perror("poll()");
				exit(1);
			}
			continue;
		}

	if (poll_array[POLL_ADM].revents)
		ietadm_cache_request_handle(nl_fd_ietd);
	}
}

int main(int argc, char **argv)
{
	int ch, longindex, timeout = -1;
	char *config = NULL, pid_buf[64];
	uid_t uid = 0;
	gid_t gid = 0;
	int pid_fd;

	/* otherwise we would die in some later write() during the event_loop
	 * instead of getting EPIPE! */
	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt_long(argc, argv, "c:fvh", long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'c':
			config = optarg;
			break;
		case 'f':
			log_daemon = 0;
			break;
	
		case 'v':
			printf("%s version %s\n", program_name, IET_CACHE_VERSION);
			exit(0);
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}


	if (log_daemon) {
		pid_t pid;

		log_init();

		pid = fork();
		if (pid < 0) {
			log_error("error starting daemon: %m");
			exit(-1);
		} else if (pid)
			exit(0);

		close(0);
		open("/dev/null", O_RDWR);
		dup2(0, 1);
		dup2(0, 2);

		setsid();


		if (chdir("/") < 0) {
			log_error("failed to set working dir to /: %m");
			exit(-1);
		}
	}

	pid_fd = open("/var/run/ietd_cache.pid", O_WRONLY|O_CREAT, 0644);
	if (pid_fd < 0) {
		log_error("unable to create pid file: %m");
		exit(-1);
	}

	if (lockf(pid_fd, F_TLOCK, 0) < 0) {
		log_error("unable to lock pid file: %m");
		exit(-1);
	}

	if (ftruncate(pid_fd, 0) < 0) {
		log_error("failed to ftruncate the PID file: %m");
		exit(-1);
	}

	sprintf(pid_buf, "%d\n", getpid());
	if (write(pid_fd, pid_buf, strlen(pid_buf)) < strlen(pid_buf)) {
		log_error("failed to write PID to PID file: %m");
		exit(-1);
	}

	if ((ctrl_fd_cache = cache_ki->ctldev_open()) < 0) {
		log_error("unable to open ctldev fd: %m");
		exit(-1);
	}

	if (!check_version()) {
		log_error("kernel module version mismatch!");
		exit(-1);
	}

	if ((nl_fd_ietd = nl_open_ietd()) < 0) {
		log_error("unable to open netlink fd: %m");
		exit(-1);
	}

	if (gid && setgid(gid) < 0) {
		log_error("unable to setgid: %m");
		exit(-1);
	}

	if (uid && setuid(uid) < 0) {
		log_error("unable to setuid: %m");
		exit(-1);
	}

	cache_cops->init(config, &timeout);

	event_loop_cache(timeout);

	return 0;
}
