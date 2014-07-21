/*
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/hash.h>

#include "cache.h"
#include "cache_wb.h"

static void cache_end_page_writeback(struct iscsi_cache_page *iscsi_page);

struct tio_work {
	atomic_t error;
	atomic_t bios_remaining;
	struct completion tio_complete;
};

static void cache_page_endio(struct bio *bio, int error)
{
	struct tio_work *tio_work = bio->bi_private;
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;

	error = test_bit(BIO_UPTODATE, &bio->bi_flags) ? error : -EIO;

	if (error)
		atomic_set(&tio_work->error, error);

	do {
		struct page *page = bvec->bv_page;
		struct iscsi_cache_page *iscsi_page = (struct iscsi_cache_page *)page->mapping;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);
		if (bio_data_dir(bio) == WRITE){	
			cache_dbg("WRITEBACK one page. Index is %llu.\n", 
				(unsigned long long)iscsi_page->index);	
			cache_end_page_writeback(iscsi_page);
		}
	} while (bvec >= bio->bi_io_vec);

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

static wait_queue_head_t *page_waitqueue(struct page *page)
{
	const struct zone *zone = page_zone(page);

	return &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
}

static inline void wake_up_page(struct page *page, int bit)
{
	__wake_up_bit(page_waitqueue(page), &page->flags, bit);
}

void iscsi_set_page_tag(struct iscsi_cache_page *iscsi_page, unsigned int tag)
{
	struct iscsi_cache *iscsi_cache=iscsi_page->iscsi_cache;
	if (iscsi_cache) {	/* Race with truncate? */
		spin_lock_irq(&iscsi_cache->tree_lock);
		radix_tree_tag_set(&iscsi_cache->page_tree,
				iscsi_page->index, tag);
		spin_unlock_irq(&iscsi_cache->tree_lock);
	}
}

static void iscsi_clear_page_tag(struct iscsi_cache_page *iscsi_page, unsigned int tag)
{
	struct iscsi_cache *iscsi_cache=iscsi_page->iscsi_cache;
	
	if (iscsi_cache) {	/* Race with truncate? */
		spin_lock_irq(&iscsi_cache->tree_lock);
		radix_tree_tag_clear(&iscsi_cache->page_tree,
				iscsi_page->index, tag);
		spin_unlock_irq(&iscsi_cache->tree_lock);
	}
}

static void iscsi_tag_pages_for_writeback(struct iscsi_cache *iscsi_cache,
			     pgoff_t start, pgoff_t end)
{
#define WRITEBACK_TAG_BATCH 4096
	unsigned long tagged;

	do {
		spin_lock_irq(&iscsi_cache->tree_lock);
		tagged = radix_tree_range_tag_if_tagged(&iscsi_cache->page_tree,
				&start, end, WRITEBACK_TAG_BATCH,
				ISCSICACHE_TAG_DIRTY, ISCSICACHE_TAG_TOWRITE);
		spin_unlock_irq(&iscsi_cache->tree_lock);
		WARN_ON_ONCE(tagged > WRITEBACK_TAG_BATCH);

		cond_resched();
		/* We check 'start' to handle wrapping when end == ~0UL */
	} while (tagged >= WRITEBACK_TAG_BATCH && start);
}

static unsigned iscsi_find_get_pages_tag(struct iscsi_cache *iscsi_cache, pgoff_t *index,
			int tag, unsigned int nr_pages, struct iscsi_cache_page **pages)
{
	unsigned int i;
	unsigned int ret;
	unsigned int nr_found;

	rcu_read_lock();
restart:
	nr_found = radix_tree_gang_lookup_tag_slot(&iscsi_cache->page_tree,
				(void ***)pages, *index, nr_pages, tag);
	ret = 0;
	for (i = 0; i < nr_found; i++) {
		struct iscsi_cache_page *page;
repeat:
		page = radix_tree_deref_slot((void **)pages[i]);
		if (unlikely(!page))
			continue;

		/*
		 * This can only trigger when the entry at index 0 moves out
		 * of or back to the root: none yet gotten, safe to restart.
		 */
		if (radix_tree_deref_retry(page))
			goto restart;

		/* Has the page moved? */
		if (unlikely(page != *((void **)pages[i]))) {
			goto repeat;
		}

		pages[ret] = page;
		ret++;
	}

	/*
	 * If all entries were removed before we could secure them,
	 * try again, because callers stop trying once 0 is returned.
	 */
	if (unlikely(!ret && nr_found))
		goto restart;
	rcu_read_unlock();
	
	cond_resched();
	
	if (ret)
		*index = pages[ret - 1]->index + 1;
	
	return ret;
}

static void iscsi_delete_page(struct iscsi_cache_page *iscsi_page)
{
	struct iscsi_cache *iscsi_cache=iscsi_page->iscsi_cache;
	
	if (iscsi_cache) {	/* Race with truncate? */
		spin_lock_irq(&iscsi_cache->tree_lock);
		radix_tree_delete(&iscsi_cache->page_tree,
				iscsi_page->index);
		iscsi_page->iscsi_cache = NULL;
		spin_unlock_irq(&iscsi_cache->tree_lock);
	}
}

static int cache_test_clear_page_writeback(struct iscsi_cache_page *iscsi_page)
{
	struct iscsi_cache *iscsi_cache = iscsi_page->iscsi_cache;
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&iscsi_cache->tree_lock, flags);
	ret = TestClearPageWriteback(iscsi_page->page);
	if (ret) {
		radix_tree_tag_clear(&iscsi_cache->page_tree,
					iscsi_page->index,
					ISCSICACHE_TAG_WRITEBACK);
	}
	spin_unlock_irqrestore(&iscsi_cache->tree_lock, flags);

	return ret;
}

static int cache_test_set_page_writeback(struct iscsi_cache_page *iscsi_page)
{
	struct iscsi_cache *iscsi_cache = iscsi_page->iscsi_cache;
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&iscsi_cache->tree_lock, flags);
	ret = TestSetPageWriteback(iscsi_page->page);
	if (!ret) {
		radix_tree_tag_set(&iscsi_cache->page_tree,
					iscsi_page->index,
					ISCSICACHE_TAG_WRITEBACK);
	}
	
	radix_tree_tag_clear(&iscsi_cache->page_tree,
				iscsi_page->index,
				ISCSICACHE_TAG_DIRTY);
	radix_tree_tag_clear(&iscsi_cache->page_tree,
			     iscsi_page->index,
			     ISCSICACHE_TAG_TOWRITE);
	spin_unlock_irqrestore(&iscsi_cache->tree_lock, flags);

	return ret;

}

static void cache_end_page_writeback(struct iscsi_cache_page *iscsi_page)
{
	if (!cache_test_clear_page_writeback(iscsi_page))
		BUG();

	smp_mb__after_clear_bit();
	wake_up_page(iscsi_page->page, PG_writeback);
}

int cache_writeback_block_device(struct iscsi_cache *iscsi_cache, struct cache_writeback_control *wbc)
{
	int tag, err = 0, done =0;
//	int m;
	/* used for cache sync, only support page size now */
//	pgoff_t wb_index[PVEC_SIZE];

	struct iscsi_cache_page *pages[PVEC_SIZE];
	pgoff_t index=0;
	pgoff_t end=wbc->range_end;
	unsigned long  nr_pages = wbc->nr_to_write;
	
	if(!iscsi_cache)
		return 0;
	
	BUG_ON(!iscsi_cache->owner);
	
	if (wbc->mode == ISCSI_WB_SYNC_ALL)
		tag = ISCSICACHE_TAG_TOWRITE;
	else
		tag = ISCSICACHE_TAG_DIRTY;
	
	if (wbc->mode == ISCSI_WB_SYNC_ALL)
		iscsi_tag_pages_for_writeback(iscsi_cache, index, end);
	
	while (!done && (index <= end)) {
		int i;
//		int wrote_index = 0;
		nr_pages = iscsi_find_get_pages_tag(iscsi_cache, &index, tag,
			      min(end - index, (pgoff_t)PVEC_SIZE-1) + 1, pages);
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct iscsi_cache_page *iscsi_page = pages[i];

			if (iscsi_page->index > end) {
				done = 1;
				break;
			}

			lock_page(iscsi_page->page);

			if (unlikely(iscsi_page->iscsi_cache != iscsi_cache)) {
continue_unlock:
				unlock_page(iscsi_page->page);
//				pages[i]=	NULL;
//				wb_index[i]= -1;
				continue;
			}

			if (!(iscsi_page->dirty_bitmap & 0xff)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if(PageWriteback(iscsi_page->page)){
				if (wbc->mode != ISCSI_WB_SYNC_NONE)
					wait_on_page_writeback(iscsi_page->page);
				else
					goto continue_unlock;
			}
			BUG_ON(PageWriteback(iscsi_page->page));
			
			cache_test_set_page_writeback(iscsi_page);

			cache_alert("WRITEBACK one page. Index is %llu, dirty bitmap is %#x.\n", 
				(unsigned long long)iscsi_page->index, iscsi_page->dirty_bitmap);

			err = cache_write_page_blocks(iscsi_page);
			if (unlikely(err)) {
				cache_err("It should never show up!Maybe disk crash... \n");
				TestClearPageWriteback(iscsi_page->page);
				smp_mb__after_clear_bit();
				wake_up_page(iscsi_page->page, PG_writeback);
				goto continue_unlock;
			}
			
//			wb_index[wrote_index++]= iscsi_page->index;
			
			atomic_dec(&iscsi_cache->dirty_pages);
			iscsi_page->dirty_bitmap=0x00;
			
			if(wbc->mode == ISCSI_WB_SYNC_ALL){
				iscsi_delete_page(iscsi_page);
			}
			
			wbc->nr_to_write--;
			if(wbc->nr_to_write < 1){
				done=1;
				unlock_page(iscsi_page->page);
				break;
			}
			unlock_page(iscsi_page->page);
		}
		
		/* submit page index of written pages to peer */
/*		for(m=wrote_index; m<PVEC_SIZE && peer_is_good; m++)
			wb_index[m]= -1;
		if(iscsi_cache->owner && wrote_index && peer_is_good)
			cache_send_wrote(iscsi_cache->conn, wb_index, PVEC_SIZE);*/
//		for(m=0; m<nr_pages; m++){
//			if(!pages[m])
//				continue;
//			pages[m]->dirty_bitmap=0x00;
//			mutex_unlock(&pages[m]->write);
//		}
	
		cond_resched();
	}	
	
	return err;
}

/* return nr of wrote pages */
int writeback_single(struct iscsi_cache *iscsi_cache, unsigned int mode, unsigned long pages_to_write)
{
	int err;

	struct cache_writeback_control wbc = {
		.nr_to_write = pages_to_write,
		.mode = mode,
		.range_start = 0,
		.range_end = ULONG_MAX,
	};

	if(!iscsi_cache->owner)
		return 0;
	
	err = cache_writeback_block_device(iscsi_cache, &wbc);
	return (pages_to_write - wbc.nr_to_write);
}


/*
 * I/O completion handler for multipage BIOs.
 *
 * The mpage code never puts partial pages into a BIO (except for end-of-file).
 * If a page does not map to a contiguous run of blocks then it simply falls
 * back to block_read_full_page().
 */
static void cache_mpage_endio(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;
	struct tio_work *tio_work = bio->bi_private;
	
	err = uptodate ? err : -EIO;
	if (err)
		atomic_set(&tio_work->error, err);
	
	do {
		struct page *page = bvec->bv_page;
		struct iscsi_cache_page *iscsi_page = (struct iscsi_cache_page *)page->mapping;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);
		
		if (bio_data_dir(bio) == READ) {
			unlock_page(page);
		} else { /* WRITE */
			if (!uptodate)
				cache_err("Error when submit to block device.\n");
			
			cache_dbg("WRITEBACK one page. Index is %llu.\n", 
				(unsigned long long)iscsi_page->index);
			
			cache_end_page_writeback(iscsi_page);
		}
	} while (bvec >= bio->bi_io_vec);
	cache_err("this bio includes %d pages.\n", bio->bi_vcnt);
	
	/* If last bio signal completion */
	if (atomic_dec_and_test(&tio_work->bios_remaining))
		complete(&tio_work->tio_complete);
	
	bio_put(bio);
}

static struct bio * cache_mpage_alloc(struct block_device *bdev,
		sector_t first_sector, int nr_vecs,
		gfp_t gfp_flags)
{
	struct bio *bio;

	bio = bio_alloc(gfp_flags, nr_vecs);

	if (bio == NULL && (current->flags & PF_MEMALLOC)) {
		while (!bio && (nr_vecs /= 2))
			bio = bio_alloc(gfp_flags, nr_vecs);
	}

	if (bio) {
		bio->bi_bdev = bdev;
		bio->bi_sector = first_sector;
	}
	return bio;
}

struct bio *cache_mpage_bio_submit(struct bio *bio, int rw)
{
	bio->bi_end_io = cache_mpage_endio;
	submit_bio(rw, bio);
	return NULL;
}

struct cache_mpage_data {
	struct bio *bio;
	sector_t last_page_in_bio;
};

/**
* unlock_page() must be done in cache_mpage_endio.
*/
static int cache_do_writepage(struct iscsi_cache_page *iscsi_page, 
	struct cache_writeback_control *wbc, struct cache_mpage_data *mpd, struct tio_work *tio_work)
{	
	int err = 0;
	int length = PAGE_SIZE;
	unsigned long  nr_pages = wbc->nr_to_write;
	struct bio* bio = mpd->bio;
	struct iscsi_cache *iscsi_cache = iscsi_page->iscsi_cache;
	struct block_device * bdev = iscsi_cache->bdev;
/*	
	if ((iscsi_page->dirty_bitmap & 0xff) != 0xff){
		cache_err("This page is not 0xff.\n");
		goto confused;
	}
*/
	if (bio && (mpd->last_page_in_bio != iscsi_page->index -1))
		bio = cache_mpage_bio_submit(bio, WRITE);

alloc_new:
	if (bio == NULL) {
		bio = cache_mpage_alloc(bdev, iscsi_page->index <<3,
			  	min_t(int, nr_pages, bio_get_nr_vecs(bdev)),
				GFP_KERNEL);
		if (bio == NULL)
			goto confused;
		
		bio->bi_private = tio_work;
		atomic_inc(&tio_work->bios_remaining);
	}

	if (bio_add_page(bio, iscsi_page->page, length, 0) < length) {
		bio = cache_mpage_bio_submit(bio, WRITE);
		cache_err("can't add to bio, maybe it's full.\n");
		goto alloc_new;
	}
	
	mpd->last_page_in_bio = iscsi_page->index;
out:
	mpd->bio = bio;
	return err;
	
confused:
	cache_err("writeback blocks to device come here.\n");
	if (bio)
		bio = cache_mpage_bio_submit(bio, WRITE);

	err = cache_write_page_blocks(iscsi_page);
	if (unlikely(err)) {
		cache_err("Error when writeback blocks to device.\n");
	}

	goto out;
}

/* return nr of wrote pages */
int cache_writeback_mpage(struct iscsi_cache *iscsi_cache, struct cache_writeback_control *wbc,
			struct cache_mpage_data *mpd)
{
	int err = 0;
	int done = 0;
//	int m;
	/* used for cache sync, only support page size now */
//	pgoff_t wb_index[PVEC_SIZE];
	struct tio_work *tio_work;
	struct iscsi_cache_page *pages[PVEC_SIZE];
	pgoff_t index=0;
	pgoff_t end=wbc->range_end;
	unsigned long  nr_pages = wbc->nr_to_write;
	int tag;

	BUG_ON(!iscsi_cache->owner);

	if(!iscsi_cache)
		return 0;
	
	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work)
		return -ENOMEM;
	
	if (wbc->mode == ISCSI_WB_SYNC_ALL)
		tag = ISCSICACHE_TAG_TOWRITE;
	else
		tag = ISCSICACHE_TAG_DIRTY;
	
	if (wbc->mode == ISCSI_WB_SYNC_ALL)
		iscsi_tag_pages_for_writeback(iscsi_cache, index, end);
	
	while (!done && (index <= end)) {
		int i;
//		int wrote_index = 0;
		struct blk_plug plug;

		atomic_set(&tio_work->error, 0);
		atomic_set(&tio_work->bios_remaining, 0);
		init_completion(&tio_work->tio_complete);

		nr_pages = iscsi_find_get_pages_tag(iscsi_cache, &index, tag,
			      min(end - index, (pgoff_t)PVEC_SIZE-1) + 1, pages);
		if (nr_pages == 0)
			break;
		
		blk_start_plug(&plug);
		cache_dbg("begin to plug.\n");
		for (i = 0; i < nr_pages; i++) {
			
			struct iscsi_cache_page *iscsi_page = pages[i];

			if (iscsi_page->index > end) {
				done = 1;
				break;
			}

			lock_page(iscsi_page->page);

			if (unlikely(iscsi_page->iscsi_cache != iscsi_cache)) {
continue_unlock:
				unlock_page(iscsi_page->page);
//				pages[i]=	NULL;
//				wb_index[i]= -1;
				continue;
			}

			if (!(iscsi_page->dirty_bitmap & 0xff)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if(PageWriteback(iscsi_page->page)){
				if (wbc->mode != ISCSI_WB_SYNC_NONE)
					wait_on_page_writeback(iscsi_page->page);
				else
					goto continue_unlock;
			}
			BUG_ON(PageWriteback(iscsi_page->page));
			iscsi_page->dirty_bitmap=0x00;
			cache_test_set_page_writeback(iscsi_page);
	
			cache_alert("WRITEBACK one page. Index is %llu, dirty bitmap is %#x.\n", 
				(unsigned long long)iscsi_page->index, iscsi_page->dirty_bitmap);
			
			err = cache_do_writepage(iscsi_page, wbc, mpd, tio_work);

			if (unlikely(err)) {
				cache_err("It should never show up!Maybe disk crash... \n");
				TestClearPageWriteback(iscsi_page->page);
				smp_mb__after_clear_bit();
				wake_up_page(iscsi_page->page, PG_writeback);
				goto continue_unlock;
			}

			iscsi_clear_page_tag(iscsi_page, tag);
			if(wbc->mode == ISCSI_WB_SYNC_ALL){
				iscsi_clear_page_tag(iscsi_page, ISCSICACHE_TAG_TOWRITE);
				iscsi_delete_page(iscsi_page);
			}
			
//			wb_index[wrote_index++]= iscsi_page->index;
			
			iscsi_page->dirty_bitmap = 0x00;
			atomic_dec(&iscsi_cache->dirty_pages);
			
			cache_end_page_writeback(iscsi_page);
			
			wbc->nr_to_write--;
			if(wbc->nr_to_write < 1){
				done=1;
				unlock_page(iscsi_page->page);
				break;
			}
			unlock_page(iscsi_page->page);
		}
		if (mpd->bio)
			cache_mpage_bio_submit(mpd->bio, WRITE);
		
		cache_dbg("begin to unplug.\n");
		blk_finish_plug(&plug);
		
		wait_for_completion(&tio_work->tio_complete);
		cache_dbg("finish one submit, success.\n");
		
		/* submit page index of written pages to peer */
/*		for(m=wrote_index; m<PVEC_SIZE && peer_is_good; m++)
			wb_index[m]= -1;
		if(iscsi_cache->owner && wrote_index && peer_is_good)
			cache_send_wrote(iscsi_cache->conn, wb_index, PVEC_SIZE);*/
//		for(m=0; m<nr_pages; m++){
//			if(!pages[m])
//				continue;
//			pages[m]->dirty_bitmap=0x00;
//			mutex_unlock(&pages[m]->write);
//		}
	
		cond_resched();
	}	
	
	kfree(tio_work);
	return err;	
}


/* return nr of wrote pages */
int writeback_single_mpage(struct iscsi_cache *iscsi_cache, unsigned int mode, unsigned long pages_to_write)
{
	int ret;
	
	struct cache_writeback_control wbc = {
		.nr_to_write = pages_to_write,
		.mode = mode,
		.range_start = 0,
		.range_end = ULONG_MAX,
	};
	
	struct cache_mpage_data mpd = {
		.bio = NULL,
		.last_page_in_bio = 0,
	};
	
	ret = cache_writeback_mpage(iscsi_cache, &wbc, &mpd);
	
	if (mpd.bio)
		cache_mpage_bio_submit(mpd.bio, WRITE);

	return ret;	

}

