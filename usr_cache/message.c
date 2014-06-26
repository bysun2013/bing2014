/*
 * message.c - ietd inter-process communication
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "iet_cache.h"

extern struct config_operations *cache_cops;

static void ietadm_cache_request_exec(struct ietadm_cache_req *req)
{
	int err = 0;

	switch (req->rcmnd) {
	case CACHE_UPDATE:
		err = cache_cops->update(req);
		break;
	default:
		break;
	}

	if (err < 0 )
		log_error("ietadm_cache_request_exec : error\n"); 
	else 
		log_warning("ietadm_cache_request_exec  send : req.name= %s  req.rcmnd = %d req.response =%d  req.tid = %d\n", 
					req->name, req->rcmnd,req->response ,req->lun);
}

void ietadm_cache_request_handle(int fd)
{
	struct ietadm_cache_req req;
	int res;

retry:
	if ((res = nl_read_ietd(fd, &req, sizeof(req))) < 0) {
		if (errno == EAGAIN)
			return;
		if (errno == EINTR)
			goto retry;
		log_error("%s(%d) \n", __FUNCTION__, __LINE__);
	}

	switch (req.rcmnd) {
	case CACHE_UPDATE:
		ietadm_cache_request_exec(&req);

		break;
	default:
		log_error("%s(%d) \n", __FUNCTION__, __LINE__);
		res = -1;
		break;
	}

	if (res < 0)
	{
		log_error("%s(%d) \n", __FUNCTION__, __LINE__);
	}

	res = nl_write_ietd(fd, &req, sizeof(struct ietadm_cache_req));
	if (res < 0)
	{
		log_error("%s(%d) \n", __FUNCTION__, __LINE__);
	}

	
}
