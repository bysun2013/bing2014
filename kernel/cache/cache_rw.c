/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/completion.h>

#include "cache.h"

struct tio_work {
	atomic_t error;
	atomic_t bios_remaining;
	struct completion tio_complete;
};

static void cache_page_endio(struct bio *bio, int error)
{
	struct tio_work *tio_work = bio->bi_private;

	error = test_bit(BIO_UPTODATE, &bio->bi_flags) ? error : -EIO;

	if (error)
		atomic_set(&tio_work->error, error);

	/* If last bio signal completion */
	if (atomic_dec_and_test(&tio_work->bios_remaining))
		complete(&tio_work->tio_complete);

	bio_put(bio);
}

/**
	submit single page segment to the block device, 
	one segment includes several continuous blocks.
*/
static int cache_rw_segment(struct iscsi_cache_page *iet_page,
	unsigned int start, unsigned int blocks, int rw)
{
	struct block_device *bdev = iet_page->iscsi_cache->bdev;
	struct tio_work *tio_work;
	struct bio *bio = NULL;
	struct blk_plug plug;
	
	unsigned int bytes = blocks*512;
	unsigned int offset = start*512;
	int max_pages = 1;
	int err = 0;

	if(blocks==0)
		return err;
	
	cache_dbg("submit blocks to device, start=%d, sizes=%d\n", start, blocks);
	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work){
		err = -ENOMEM;
		goto out;
	}
	
	atomic_set(&tio_work->error, 0);
	atomic_set(&tio_work->bios_remaining, 0);
	init_completion(&tio_work->tio_complete);
	
	/* Main processing loop, allocate and fill all bios */
	bio = bio_alloc(GFP_KERNEL, max_pages);
	if (!bio) {
		err = -ENOMEM;
		goto out;
	}

	/* bi_sector is ALWAYS in units of 512 bytes */
	bio->bi_sector = (iet_page->index<<3)+start;
	bio->bi_bdev = bdev;
	bio->bi_end_io = cache_page_endio;
	bio->bi_private = tio_work;

	atomic_inc(&tio_work->bios_remaining);

	if (!bio_add_page(bio, iet_page->page, bytes, offset)){
		err = -ENOMEM;
		goto out;
	}

	blk_start_plug(&plug);

	submit_bio(rw, bio);

	blk_finish_plug(&plug);

	wait_for_completion(&tio_work->tio_complete);

	err = atomic_read(&tio_work->error);

	kfree(tio_work);

	return err;
out:
	bio_put(bio);
	kfree(tio_work);
	cache_err("Error occurs when page segment r/w.\n");

	return err;
}

int cache_rw_page(struct iscsi_cache_page *iet_page, int rw)
{
	struct block_device *bdev = iet_page->iscsi_cache->bdev;
	struct tio_work *tio_work;
	struct bio *bio = NULL;
	struct blk_plug plug;
	
	unsigned int bytes = PAGE_SIZE;
	int max_pages = 1;
	int err = 0;
	
	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work)
		return -ENOMEM;
	atomic_set(&tio_work->error, 0);
	atomic_set(&tio_work->bios_remaining, 0);
	init_completion(&tio_work->tio_complete);

	bio = bio_alloc(GFP_KERNEL, max_pages);
	if (!bio) {
		err = -ENOMEM;
		goto out;
	}

	/* bi_sector is ALWAYS in units of 512 bytes */
	bio->bi_sector = iet_page->index<<3;
	bio->bi_bdev = bdev;
	bio->bi_end_io = cache_page_endio;
	bio->bi_private = tio_work;
	
	atomic_inc(&tio_work->bios_remaining);
	if (!bio_add_page(bio, iet_page->page, bytes, 0)){
		err = -ENOMEM;
		goto out;
	}

	blk_start_plug(&plug);

	submit_bio(rw, bio);
	
	blk_finish_plug(&plug);

	wait_for_completion(&tio_work->tio_complete);

	err = atomic_read(&tio_work->error);
	
	kfree(tio_work);

	return err;
out:
	bio_put(bio);
	kfree(tio_work);
	cache_err("Error occurs when page r/w.\n");
	
	return err;
}


static int _cache_rw_page_blocks(struct iscsi_cache_page *iet_page, unsigned char bitmap, int rw)
{
	unsigned int i=0, start=0, last=1, sizes=0;
	int err=0;
	int tmp=1;

	/* it's more possible, so detect it first. */
	if(likely((bitmap & 0xff) == 0xff)){
		err=cache_rw_page(iet_page, rw);
		return err;
	}
	
	for(i=0; i<8; i++){
		if(bitmap & tmp) {
			if(last==1)
				sizes++;
			else{
				start=i;
				sizes=1;
			}
			last=1;
		}else{
			if(last==1){
				err=cache_rw_segment(iet_page, start, sizes, rw);
				if(unlikely(err))
					goto error;
				last=0;
			}else{
				last=0;
				tmp=tmp<<1;
				continue;
			}
		}
		tmp=tmp<<1;
	}
	if(bitmap & 0x80){
		err=cache_rw_segment(iet_page, start, sizes, rw);
		if(unlikely(err))
			goto error;
	}
	return 0;
	
error:	
	cache_err("Error occurs when submit blocks to device.\n");
	return err;
}

/**
* blocks in a page aren't always valid,so when writeback
* submit to block device separately is necessary.
*
* Just used in writeback dirty blocks.
*/
int cache_write_page_blocks(struct iscsi_cache_page *iet_page)
{
	int err;
	char bitmap=iet_page->dirty_bitmap;
	
	err = _cache_rw_page_blocks(iet_page, bitmap, WRITE);
	return err;
}
/** 
* If valid bitmap is not agreed to bitmap to read, then read the missed blocks.
*/
int cache_check_read_blocks(struct iscsi_cache_page *iet_page,
		unsigned char valid, unsigned char read)
{
	unsigned char miss;
	int err;
	miss = valid | read;
	miss = miss ^ valid;

	err = _cache_rw_page_blocks(iet_page, miss, READ);

	return err;
}

