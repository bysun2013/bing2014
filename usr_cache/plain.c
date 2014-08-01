/*
 * plain.c - ietd plain file-based configuration
 *
 * Copyright (C) 2004-2005 FUJITA Tomonori <tomof at acm dot org>
 * Copyright (C) 2004-2010 VMware, Inc. All Rights Reserved.
 * Copyright (C) 2007-2010 Ross Walker <rswwalker at gmail dot com>
 *
 * This file is part of iSCSI Enterprise Target software.
 *
 * Released under the terms of the GNU GPL v2.0.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "iet_cache.h"

#define BUFSIZE		4096
#define CONFIG_FILE	"cache.conf"
#define CONFIG_DIR	"/etc/iet/"

/*
 * Account configuration code
 */


int is_addr_valid(char *addr)
{
	struct in_addr ia;
	struct in6_addr ia6;
	char tmp[NI_MAXHOST + 1], *p = tmp, *q;

	snprintf(tmp, sizeof(tmp), "%s", addr);

	if (inet_pton(AF_INET, p, &ia) == 1)
		return 1;

	if (*p == '[') {
		p++;
		q = p + strlen(p) - 1;
		if (*q != ']')
			return 0;
		*q = '\0';
	}

	if (inet_pton(AF_INET6, p, &ia6) == 1)
		return 1;

	return 0;
}

/* this is the orignal Ardis code. */
static char *cache_sep_string(char **pp)
{
	char *p = *pp;
	char *q;

	for (p = *pp; isspace(*p); p++)
		;
	for (q = p; *q && !isspace(*q); q++)
		;
	if (*q)
		*q++ = 0;
	else
		p = NULL;
	*pp = q;
	return p;
}

static void cache_param_init(FILE *fp)
{
	char buf[BUFSIZE];
	char *p, *q;

	u32 tid = 0;


	while (fgets(buf, BUFSIZE, fp)) {
		q = buf;
		p = cache_sep_string(&q);
		if (!p || *p == '#')
			continue;
		if (!strcasecmp(p, "Machine")) {
			tid = 0;
			if (!(p = cache_sep_string(&q)))
				continue;
			cache_ki->machine_init(&tid, p, 0);
		}else if (!strcasecmp(p, "MA")) {
			tid = 0;
			if (!(p = cache_sep_string(&q)))
				continue;
			cache_ki->ip_init(&tid, p, MA);
		}else if (!strcasecmp(p, "MB")) {
			tid = 1;
			if (!(p = cache_sep_string(&q)))
				continue;
			cache_ki->ip_init(&tid, p, MB);
		}else if (!strcasecmp(p, "Port")) {
			if (!(p = cache_sep_string(&q)))
				continue;
		}




		
	}

	return;
}

static void cache_plain_init(char *params, int *timeout)
{
	FILE *fp;
	char file1[PATH_MAX], file2[PATH_MAX];

	snprintf(file1, sizeof(file1), "%s%s", CONFIG_DIR, CONFIG_FILE);
	snprintf(file2, sizeof(file2), "/etc/%s", CONFIG_FILE);

	if (!(fp = fopen(params ? params : file1, "r"))) {
		if ((fp = fopen(file2, "r")))
			log_warning("%s's location is depreciated and will be moved in the next release to %s", file2, file1);
		else {
			log_warning("%s not found, configure through ietadm", CONFIG_FILE);
			return;
		}
	}

	cache_param_init(fp);

	fclose(fp);

	return;
}

static int cache_plain_update(struct ietadm_cache_req *req)
{
	int err;

	err = cache_ki->cache_update(req);

	return err;
}

struct config_operations cache_plain_ops = {
	.init			= cache_plain_init,
	.update		= cache_plain_update,
};
