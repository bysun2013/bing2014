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

static void blockio_bio_endio(struct bio *bio, int error)
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
static int
blockio_start_rw_single_segment(struct iscsi_cache_page *iet_page,  struct block_device *bdev,
	unsigned int start, unsigned int blocks, int rw)
{
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
	bio->bi_end_io = blockio_bio_endio;
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

static int
blockio_start_rw_page(struct iscsi_cache_page *iet_page,  struct block_device *bdev,  int rw)
{
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
	bio->bi_end_io = blockio_bio_endio;
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


static int
_blockio_start_rw_page_blocks(struct iscsi_cache_page *iet_page, 
	struct block_device *bdev, unsigned char bitmap, int rw)
{
	unsigned int i=0, start=0, last=1, sizes=0;
	int err=0;
	int tmp=1;

	/* it's more possible, so detect it first. */
	if((bitmap & 0xff) == 0xff){
		err=blockio_start_rw_page(iet_page, bdev, rw);
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
				err=blockio_start_rw_single_segment(iet_page, bdev, start, sizes, rw);
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
		err=blockio_start_rw_single_segment(iet_page, bdev, start, sizes, rw);
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
int
blockio_start_write_page_blocks(struct iscsi_cache_page *iet_page, struct block_device *bdev)
{
	int err;
	char bitmap=iet_page->dirty_bitmap;
	
	err = _blockio_start_rw_page_blocks(iet_page, bdev, bitmap, WRITE);
	return err;
}
/** 
* If valid bitmap is not agreed to bitmap to read, then read the missed blocks.
*/
static int check_blocks_to_read(struct iscsi_cache_page *iet_page, struct block_device *bdev,
		unsigned char valid, unsigned char read)
{
	unsigned char miss;
	int err;
	miss = valid | read;
	miss = miss ^ valid;

	err = _blockio_start_rw_page_blocks(iet_page, bdev, miss, READ);

	return err;
}
int iscsi_read_from_cache(void *iscsi_cachep, struct block_device *bdev, pgoff_t page_index, struct page* page, 
		char bitmap, unsigned int current_bytes, unsigned int skip_blk)
{
	struct iscsi_cache * iscsi_cache = (struct iscsi_cache *)iscsi_cachep;
	struct iscsi_cache_page *iet_page;
	int err=0;
again:
	iet_page= iscsi_find_get_page(iscsi_cache, page_index);

	if(iet_page){	/* Read Hit */
		lock_page(iet_page->page);
		
		if((iet_page->valid_bitmap & bitmap) != bitmap){
			cache_dbg("Valid bitmap is not agreed to bitmap to read.\n");
			
			err=check_blocks_to_read(iet_page, bdev, iet_page->valid_bitmap, bitmap);
			if(unlikely(err)){
				cache_err("Error occurs when read missed blocks.\n");
				unlock_page(iet_page->page);
				return err;
			}
			iet_page->valid_bitmap = iet_page->valid_bitmap & bitmap;
		}
		
		copy_cache_to_tio(iet_page, page, bitmap, skip_blk, current_bytes);

		unlock_page(iet_page->page);
		
		update_lru_list(&iet_page->lru_list);
		cache_dbg("READ HIT\n");	
	}else{	/* Read Miss, no page */
		iet_page=iscsi_get_free_page(iscsi_cache);

		iet_page->iscsi_cache=iscsi_cache;
		iet_page->bdev=bdev;
		iet_page->index=page_index;

		lock_page(iet_page->page);
		
		err=iscsi_add_page(iscsi_cache, iet_page);
		if(unlikely(err)){
			if(err==-EEXIST){
				throw_to_lru_list(&iet_page->lru_list);
				unlock_page(iet_page->page);
				iet_page=NULL;
				goto again;
			}
			cache_err("Error occurs when read, but reason is not clear.\n");
			unlock_page(iet_page->page);
			return err;
		}
		blockio_start_rw_page(iet_page, bdev, READ);
		
		copy_cache_to_tio(iet_page, page,  bitmap, skip_blk, current_bytes);
		
		iet_page->valid_bitmap =0xff;

		unlock_page(iet_page->page);
		
		iscsi_cache->total_pages++;

		add_to_lru_list(&iet_page->lru_list);
		
		cache_dbg("READ MISS, no page\n");
		}
	return err;
}

EXPORT_SYMBOL_GPL(iscsi_read_from_cache);

int  iscsi_write_into_cache(void *iscsi_cachep, struct block_device *bdev, pgoff_t page_index, struct page* page, 
		char bitmap, unsigned int current_bytes, unsigned int skip_blk)
{
		struct iscsi_cache *iscsi_cache = (struct iscsi_cache *)iscsi_cachep;
		struct iscsi_cache_page *iet_page;
		int err=0;
again:
		iet_page= iscsi_find_get_page(iscsi_cache, page_index);

		if(iet_page == NULL){	/* Write Miss */
			iet_page=iscsi_get_free_page(iscsi_cache);

			iet_page->iscsi_cache=iscsi_cache;
			iet_page->bdev=bdev;
			iet_page->index=page_index;

			lock_page(iet_page->page);
			err=iscsi_add_page(iscsi_cache, iet_page);
			if(unlikely(err)){
				if(err==-EEXIST){
					throw_to_lru_list(&iet_page->lru_list);
					unlock_page(iet_page->page);
					iet_page=NULL;
					goto again;
				}
				cache_err("Error occurs when write, but reason is not clear.\n");
				unlock_page(iet_page->page);
				return err;
			}
			
			copy_tio_to_cache(page, iet_page, bitmap, skip_blk, current_bytes);

			iet_page->valid_bitmap |= bitmap;
			iet_page->dirty_bitmap |=bitmap;
			iet_page->dirtied_when = jiffies;
			
			iscsi_set_page_tag(iet_page, ISCSICACHE_TAG_DIRTY);
			
			unlock_page(iet_page->page);

			iscsi_cache->total_pages++;
			iscsi_cache->dirty_pages++;
			
			add_to_lru_list(&iet_page->lru_list);
			cache_dbg("WRITE MISS\n");
		}else{		/* Write Hit */

			lock_page(iet_page->page);
			
			mutex_lock(&iet_page->write);
			copy_tio_to_cache(page, iet_page, bitmap, skip_blk, current_bytes);

			iet_page->valid_bitmap |= bitmap;
			if(iet_page->dirty_bitmap == 0){
				iscsi_cache->dirty_pages++;
				iet_page->dirtied_when = jiffies;
			}
			iet_page->dirty_bitmap |= bitmap;
			iscsi_set_page_tag(iet_page, ISCSICACHE_TAG_DIRTY);
			
			mutex_unlock(&iet_page->write);
			
			unlock_page(iet_page->page);
			
			update_lru_list(&iet_page->lru_list);
			cache_dbg("WRITE HIT\n");
		}
		return err;
}
EXPORT_SYMBOL_GPL(iscsi_write_into_cache);


