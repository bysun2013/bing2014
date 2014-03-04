/*
 * Copyright (C) 2013-2014 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include "iscsi.h"
#include "iscsi_cache.h"

iet_page_t iet_cache[];

iet_page_num=iet_mem_size/PAGE_SIZE;

int iscsi_cache_init(){
	unsigned int i=0;
	/*map reserved physical memory into kernel region*/
	if((reserve_virt_addr = ioremap(iet_mem_start *1024 * 1024, iet_mem_size *1024 * 1024))<0)
		goto err;
	printk("reserve_virt_addr = 0x%lx\n", (unsigned long)reserve_virt_addr);

	iet_cache=(iet_page_t *)reserve_virt_addr;
	
	for(;i<iet_page_num;i++){
		/*FIXME*/
		iet_cache[i]=0;
	}
	return 0;
}

int iscsi_cache_exit(){
		
	/*unmap reserved physical memory */
	if (reserve_virt_addr)
¡¡¡¡	iounmap(reserve_virt_addr);
	iet_cache=NULL;
	return 0;
}

int iscsi_cache_add(struct tio *tio){
	struct page **iet_page;
	int count=tio->count;
	iet_page=tio->pvec;
	int i;
	for(i=0;i<count;i++){
		
	}
}
