/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef CACHE_DBG_H
#define CACHE_DBG_H

/**
  * set flag to zero, if you don't want to output much log.
*/
#define CACHE_DEBUG_ENABLE_FLAGS 0

#define PFX "[iSCSI_Cache] "

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

#define dprintk_detail(level, fmt, args...)					\
	do { 							   \
		if (CACHE_DEBUG_ENABLE_FLAGS) {		   \
			printk(level PFX "%s(%d) " fmt,	   \
				__FUNCTION__, 			   \
				__LINE__, 			   \
				##args);					\
		}						   \
	} while (0)
			   
#define dprintk(level, fmt, args...)					\
	do { 							   \
		if (CACHE_DEBUG_ENABLE_FLAGS) {		   \
		   	printk(level PFX fmt,	   \
				##args);					\
	  	}						   \
	} while (0)

#define cache_dbg(fmt, args...) \
	dprintk(KERN_DEBUG, fmt, ##args)
#define cache_info(fmt, args...) \
	eprintk(KERN_INFO, fmt, ##args)
#define cache_warn(fmt, args...) \
	eprintk(KERN_WARNING, fmt,##args)
#define cache_err(fmt, args...) \
	eprintk_detail(KERN_ERR, fmt, ##args)
#define cache_alert(fmt, args...) \
	eprintk(KERN_ALERT, fmt, ##args)
#define cache_emerg(fmt, args...) \
	eprintk(KERN_EMERG, fmt, ##args)


#endif