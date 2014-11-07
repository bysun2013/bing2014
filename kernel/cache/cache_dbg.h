/*
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


#ifndef CACHE_DBG_H
#define CACHE_DBG_H

/**
  * comment it, if you don't want to output much log.
*/
#if 0
#define CACHE_DEBUG_ENABLE_FLAGS
#endif

#define PFX "[Disk_Cache] "

#define eprintk_detail(level, fmt, args...)	\
	do {								\
		printk(level PFX "%s(%d) " fmt,	\
		       __FUNCTION__,				\
		       __LINE__,					\
		       ##args);					\
	} while (0)

#define eprintk(level, fmt, args...)			\
	do {								\
		printk(level PFX fmt,			\
		       ##args);					\
	} while (0)

#ifdef CACHE_DEBUG_ENABLE_FLAGS
#define dprintk_detail(level, fmt, args...)					\
	do { 							   \
			printk(level PFX "%s(%d) " fmt,	   \
				__FUNCTION__, 			   \
				__LINE__, 			   \
				##args);					\
	} while (0)
			   
#define dprintk(level, fmt, args...)					\
	do { 							   \
		   	printk(level PFX fmt,	   \
				##args);					\
	} while (0)

#else
#define dprintk_detail(level, fmt, args...)	do{	}while(0)
#define dprintk(level, fmt, args...)		do{	}while(0)
#endif

#define cache_ignore(fmt, args...)		do{	}while(0)
#define cache_dbg(fmt, args...) \
	dprintk_detail(KERN_ALERT, fmt, ##args)
#define cache_info(fmt, args...) \
	eprintk(KERN_INFO, fmt, ##args)
#define cache_warn(fmt, args...) \
	eprintk_detail(KERN_WARNING, fmt,##args)
#define cache_err(fmt, args...) \
	eprintk_detail(KERN_ERR, fmt, ##args)
#define cache_alert(fmt, args...) \
	eprintk_detail(KERN_ALERT, fmt, ##args)
#define cache_emerg(fmt, args...) \
	eprintk_detail(KERN_EMERG, fmt, ##args)


#endif
