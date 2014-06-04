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
#define CACHE_DEBUG_ENABLE_FLAGS 1

#define PFX "[iSCSI_Cache] "

#define dprintk_detail(level, fmt, args...)					\
	do {								\
		if (CACHE_DEBUG_ENABLE_FLAGS) {			\
			printk(level PFX "%s(%d) " fmt,		\
			       __FUNCTION__,				\
			       __LINE__,				\
			       ##args);					\
		}							\
	} while (0)

#define dprintk(level, fmt, args...)					\
	do {								\
		if (CACHE_DEBUG_ENABLE_FLAGS) {			\
			printk(level PFX fmt,		\
			       ##args);					\
		}							\
	} while (0)

#define cache_err(fmt, args...) \
	dprintk(KERN_ERR, fmt, ##args)
#define cache_alert(fmt, args...) \
	dprintk(KERN_ALERT, fmt, ##args)
#define cache_emerg(fmt, args...) \
	dprintk(KERN_EMERG, fmt, ##args)

#ifndef CACHE_DEBUG_ENABLE_FLAGS
#undef dprintk_detail(level, fmt, args...)
#define dprintk_detail(level, fmt, args...)

#undef dprintk(level, fmt, args...)
#define dprintk(level, fmt, args...)
#endif

#define cache_dbg(fmt, args...) \
	dprintk(KERN_DEBUG, fmt, ##args)
#define cache_info(fmt, args...) \
	dprintk(KERN_INFO, fmt, ##args)
#define cache_warn(fmt, args...) \
	dprintk(KERN_WARNING, fmt,##args)

#endif
