/*
 * Copyright (C) 2013-2014 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */


/* param of reserved memory at boot*/
MODULE_PARM(iet_mem_start, "i");
MODULE_PARM(iet_mem_size, "i");

static int iet_mem_start = 910, iet_mem_size = 80;

typedef char iet_page_t[PAGE_SIZE];

extern iet_page_t iet_cache[];

extern int iet_page_num;


struct iet_cache_page{
	iet_page_t * data;
	struct iet_cache_page *next, *prev;
	
};



