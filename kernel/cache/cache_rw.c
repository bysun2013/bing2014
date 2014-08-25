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
#include <asm/atomic.h>

#include "cache.h"
#include "cache_wb.h"
#include "cache_lru.h"

void cache_end_page_writeback(struct iscsi_cache_page *iscsi_page);

struct tio_work {
	atomic_t error;
	atomic_t bios_remaining;
	struct completion tio_complete;
};

/*
* called by disk driver, after data are read from disk
*/
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
		if (unlikely(bio_data_dir(bio) == WRITE)){
			cache_ignore("WRITEBACK one page. Index is %llu.\n", 
				(unsigned long long)iscsi_page->index);
			lru_add_page(iscsi_page);
			cache_end_page_writeback(iscsi_page);
		}
	} while (bvec >= bio->bi_io_vec);

	/* If last bio signal completion */
	if (atomic_dec_and_test(&tio_work->bios_remaining))
		complete(&tio_work->tio_complete);

	bio_put(bio);
}

/*
* submit single page segment to the block device, one segment includes
* several continuous blocks.
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
	cache_err("Error occurs when page segment rw\n");
	bio_put(bio);
	kfree(tio_work);
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
	cache_err("Error occurs when page rw, err = %d\n", err);
	bio_put(bio);
	kfree(tio_work);
	return err;
}

static int _cache_rw_page_blocks(struct iscsi_cache_page *iet_page, unsigned char bitmap, int rw)
{
	unsigned int i=0, start=0, last=1, sizes=0;
	int err=0;
	int tmp=1;

	if(unlikely((bitmap & 0xff) == 0xff)){
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
	cache_err("Error occurs when submit blocks to device, err = %d\n", err);
	return err;
}

/*
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
/*
* If valid bitmap is not agreed to bitmap to read, then 
* read the missed blocks.
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
	unsigned int ret = 0;
	struct radix_tree_iter iter;
	void **slot;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_tagged(slot, &iscsi_cache->page_tree,
				   &iter, *index, tag){
		struct iscsi_cache_page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				/*
				 * Transient condition which can only trigger
				 * when entry at index 0 moves out of or back
				 * to root: none yet gotten, safe to restart.
				 */
				goto restart;
			}
			/*
			 * This function is never used on a shmem/tmpfs
			 * mapping, so a swap entry won't be found here.
			 */
			BUG();
		}

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			goto repeat;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}

	rcu_read_unlock();
	
	if (ret)
		*index = pages[ret - 1]->index + 1;
	
	return ret;
}

static void iscsi_delete_page(struct iscsi_cache_page *iscsi_page)
{
	struct iscsi_cache *iscsi_cache=iscsi_page->iscsi_cache;
	
	if (iscsi_cache) {
		spin_lock_irq(&iscsi_cache->tree_lock);
		radix_tree_delete(&iscsi_cache->page_tree,
				iscsi_page->index);
		iscsi_page->iscsi_cache = NULL;
		spin_unlock_irq(&iscsi_cache->tree_lock);
	}
}

static unsigned iscsi_find_get_pages(struct iscsi_cache *iscsi_cache, pgoff_t start,
			unsigned int nr_pages, struct iscsi_cache_page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_slot(slot, &iscsi_cache->page_tree, &iter, start) {
		struct iscsi_cache_page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				/*
				 * Transient condition which can only trigger
				 * when entry at index 0 moves out of or back
				 * to root: none yet gotten, safe to restart.
				 */
				WARN_ON(iter.index);
				goto restart;
			}
			/*
			 * Otherwise, shmem/tmpfs must be storing a swap entry
			 * here as an exceptional entry: so skip over it -
			 * we only reach this from invalidate_mapping_pages().
			 */
			continue;
		}

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			goto repeat;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}

	rcu_read_unlock();
	
	return ret;
}


/*
* called when delete one volume, to destroy radix tree
*/
#define DEL_MAX_SIZE 64

void iscsi_delete_radix_tree(struct iscsi_cache *iscsi_cache)
{
	struct iscsi_cache_page *pages[DEL_MAX_SIZE];
	pgoff_t index=0;
	pgoff_t end= ULONG_MAX;
	unsigned long  nr_pages;

	if(!iscsi_cache)
		return;
	
	while (true) {
		int i;

		nr_pages = iscsi_find_get_pages(iscsi_cache, index,
			      min(end - index, (pgoff_t)DEL_MAX_SIZE-1) + 1, pages);
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct iscsi_cache_page *iscsi_page = pages[i];

			lock_page(iscsi_page->page);
			if (unlikely(iscsi_page->iscsi_cache != iscsi_cache)) {
				unlock_page(iscsi_page->page); 
				continue;
			}
			iscsi_delete_page(iscsi_page);
			unlock_page(iscsi_page->page);
		}
	}
	cache_dbg("OK, radix tree of %s is deleted.\n", iscsi_cache->path);
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

/*
* clear WB flag of page, called after data is written to disk.
*/
void cache_end_page_writeback(struct iscsi_cache_page *iscsi_page)
{
	if (!cache_test_clear_page_writeback(iscsi_page))
		BUG();

	smp_mb__after_clear_bit();
	wake_up_page(iscsi_page->page, PG_writeback);
}

/*
 * I/O completion handler for multipage BIOs.
 */
static void cache_mpage_endio(struct bio *bio, int err)
{
	LIST_HEAD(list_inactive);
	LIST_HEAD(list_active);

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
			iscsi_page->valid_bitmap = 0xff;	
			cache_ignore("READ one page. Index is %llu\n",
				(unsigned long long)iscsi_page->index);		
		} else { /* WRITE */
			
			cache_ignore("WRITEBACK one page. Index is %llu\n", 
				(unsigned long long)iscsi_page->index);
			if(!PageActive(iscsi_page->page))
				list_add(&iscsi_page->list,&list_inactive);
			else
				list_add(&iscsi_page->list,&list_active);
			iscsi_page->site = temp;
		}
	} while (bvec >= bio->bi_io_vec);
	
	if (bio_data_dir(bio) == WRITE){
		inactive_writeback_add_list(&list_inactive);
		active_writeback_add_list(&list_active);
	}
	
	cache_ignore("%s: This bio includes %d pages.\n", bio_data_dir(bio) == READ? "READ":"WRITE", bio->bi_vcnt);
	
	/* If last bio signal completion */
	if (atomic_dec_and_test(&tio_work->bios_remaining))
		complete(&tio_work->tio_complete);
	
	bio_put(bio);
}

static struct bio * cache_mpage_alloc(struct block_device *bdev,
	sector_t first_sector, unsigned int nr_vecs, gfp_t gfp_flags)
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
	}else
		cache_dbg("the bio include %d vecs.\n", nr_vecs);

	return bio;
}

struct cache_mpage_data {
	struct bio *bio;
	pgoff_t last_page_in_bio;
};

struct bio *cache_mpage_bio_submit(struct bio *bio, int rw)
{
	bio->bi_end_io = cache_mpage_endio;
	submit_bio(rw, bio);
	
	return NULL;
}

static int cache_do_readpage(struct iscsi_cache_page *iscsi_page, int nr_pages,
	struct cache_mpage_data *mpd, struct tio_work *tio_work)
{	
	int err = 0;
	int length = PAGE_SIZE;
	struct bio* bio = mpd->bio;
	struct iscsi_cache *iscsi_cache = iscsi_page->iscsi_cache;
	struct block_device * bdev = iscsi_cache->bdev;

	if (bio && (mpd->last_page_in_bio + 1 != iscsi_page->index))
		bio = cache_mpage_bio_submit(bio, READ);

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
		cache_ignore("READ: bio maybe it's full: %d pages.\n", bio->bi_vcnt);
		bio = cache_mpage_bio_submit(bio, READ);
		goto alloc_new;
	}
	
	mpd->last_page_in_bio = iscsi_page->index;
	mpd->bio = bio;
	return err;
	
confused:
	if (bio)
		bio = cache_mpage_bio_submit(bio, READ);

	err = cache_rw_page(iscsi_page, READ);
	
	mpd->bio = bio;
	return err;
}

/*
* multi-pages read/write, its pages maybe not sequential
* called by iscsi_read_cache
*/
static int _cache_read_mpage(struct iscsi_cache *iscsi_cache, struct iscsi_cache_page **iscsi_pages, 
	int pg_cnt, struct cache_mpage_data *mpd)
{
	int err = 0;
	struct tio_work *tio_work;
	int i, remain;
	struct blk_plug plug;

	if(!iscsi_cache || !pg_cnt)
		return 0;
	
	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work)
		return -ENOMEM;

	atomic_set(&tio_work->error, 0);
	atomic_set(&tio_work->bios_remaining, 0);
	init_completion(&tio_work->tio_complete);

	blk_start_plug(&plug);
	for (i = 0, remain = pg_cnt; i < pg_cnt; i++, remain--) {
		struct iscsi_cache_page *iscsi_page = iscsi_pages[i];
		
		err = cache_do_readpage(iscsi_page, remain, mpd, tio_work);
		if (unlikely(err)) {
			cache_alert("It should never show up!Maybe disk crash... \n");
			BUG();
		}
	}
	
	if (mpd->bio)
		mpd->bio = cache_mpage_bio_submit(mpd->bio, READ);

	blk_finish_plug(&plug);

	if(atomic_read(&tio_work->bios_remaining))
		wait_for_completion(&tio_work->tio_complete);
	
	err = atomic_read(&tio_work->error);
	if(err)
		cache_err("error when submit request to disk.\n");
	
	kfree(tio_work);
	return err;
}

int cache_read_mpage(struct iscsi_cache *iscsi_cache, struct iscsi_cache_page **iscsi_pages, int pg_cnt)
{
	int ret;
	
	struct cache_mpage_data mpd = {
		.bio = NULL,
		.last_page_in_bio = 0,
	};
	
	ret = _cache_read_mpage(iscsi_cache, iscsi_pages, pg_cnt, &mpd);
	
	BUG_ON(mpd.bio != NULL);

	if(unlikely(ret))
		cache_err("An error has occurred when read mpage.\n");

	return ret;
}

static int cache_do_writepage(struct iscsi_cache_page *iscsi_page, 
	struct cache_writeback_control *wbc, struct cache_mpage_data *mpd, struct tio_work *tio_work)
{	
	int err = 0;
	int length = PAGE_SIZE;
	long  nr_pages = wbc->nr_to_write;
	struct bio* bio = mpd->bio;
	struct iscsi_cache *iscsi_cache = iscsi_page->iscsi_cache;
	struct block_device * bdev = iscsi_cache->bdev;

	if (bio && (mpd->last_page_in_bio != iscsi_page->index -1))
		bio = cache_mpage_bio_submit(bio, WRITE);

alloc_new:
	if (bio == NULL) {
		bio = cache_mpage_alloc(bdev, iscsi_page->index <<3,
			  	min_t(long, nr_pages, bio_get_nr_vecs(bdev)),
				GFP_KERNEL);
		if (bio == NULL){
			cache_warn("Memory has been used up...\n");
			goto confused;
		}
		bio->bi_private = tio_work;
		atomic_inc(&tio_work->bios_remaining);
	}

	if (bio_add_page(bio, iscsi_page->page, length, 0) < length) {
		cache_ignore("WRITE: bio maybe it's full: %d pages.\n", bio->bi_vcnt);
		bio = cache_mpage_bio_submit(bio, WRITE);
		goto alloc_new;
	}
	
	mpd->last_page_in_bio = iscsi_page->index;
	mpd->bio = bio;
	return err;
	
confused:
	if (bio)
		bio = cache_mpage_bio_submit(bio, WRITE);
	
	mpd->bio = bio;
	
	/* I believe the minimal block should be 4KB */ 
	err = cache_write_page_blocks(iscsi_page);
	
	return err;
}

/*
* multi-pages are merged to one submit, to imrove efficiency
* return nr of wrote pages 
*/
int cache_writeback_mpage(struct iscsi_cache *iscsi_cache, struct cache_writeback_control *wbc,
			struct cache_mpage_data *mpd)
{
	int err = 0;
	int done = 0;
//	int m;
//	pgoff_t wb_index[PVEC_SIZE];
	struct tio_work *tio_work;
	struct iscsi_cache_page *pages[PVEC_MAX_SIZE];
	pgoff_t writeback_index = 0;
	pgoff_t index, done_index;
	pgoff_t end;
	unsigned int nr_pages, wr_pages;
	int tag;
	int cycled;
	bool is_seq;

	BUG_ON(!iscsi_cache->owner);

	if(!iscsi_cache)
		return 0;
	
	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work){
		return -ENOMEM;
	}
	
	if (wbc->range_cyclic) {
		writeback_index = iscsi_cache->writeback_index;
		index = writeback_index;
		if (index == 0)
			cycled = 1;
		else
			cycled = 0;
		end = -1;
	} else {
		index = wbc->range_start;
		end = wbc->range_end;
		cycled = 1;
	}
	
	if (wbc->mode == ISCSI_WB_SYNC_ALL)
		tag = ISCSICACHE_TAG_TOWRITE;
	else
		tag = ISCSICACHE_TAG_DIRTY;
retry:
	if (wbc->mode == ISCSI_WB_SYNC_ALL)
		iscsi_tag_pages_for_writeback(iscsi_cache, index, end);
	
	done_index = index;
	while (!done && (index <= end)) {
		int i;
//		int wrote_index = 0;
		struct blk_plug plug;

		atomic_set(&tio_work->error, 0);
		atomic_set(&tio_work->bios_remaining, 0);
		init_completion(&tio_work->tio_complete);

		nr_pages = iscsi_find_get_pages_tag(iscsi_cache, &index, tag,
			      min(end - index, (pgoff_t)PVEC_MAX_SIZE-1) + 1, pages);
		if (nr_pages == 0)
			break;
		
		wr_pages = 0;
		
		blk_start_plug(&plug);
		for (i = 0; i < nr_pages; i++) {
			struct iscsi_cache_page *iscsi_page = pages[i];

			if (iscsi_page->index > end) {
				done = 1;
				break;
			}
			done_index = iscsi_page->index;
			if(!trylock_page(iscsi_page->page)){
				if (wbc->mode != ISCSI_WB_SYNC_NONE)
					lock_page(iscsi_page->page);
				else
					continue;
			}

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
			unlock_page(iscsi_page->page);

			if(!mpd->bio)
				is_seq = 0;
			else
				is_seq = (mpd->last_page_in_bio == iscsi_page->index -1 ? 1 : 0);
			
			err = cache_do_writepage(iscsi_page, wbc, mpd, tio_work);
			
			if (unlikely(err)) {
				cache_err("It should never show up!Maybe disk crash... \n");
				TestClearPageWriteback(iscsi_page->page);
				smp_mb__after_clear_bit();
				wake_up_page(iscsi_page->page, PG_writeback);
				goto continue_unlock;
			}
			
//			wb_index[wrote_index++]= iscsi_page->index;
			
			atomic_dec(&iscsi_cache->dirty_pages);
			
			wbc->nr_to_write--;
			if(wbc->nr_to_write < 1){
				done=1;
				break;
			}
			
			++wr_pages;
			if(!is_seq && (wr_pages > PVEC_NORMAL_SIZE)){		
				/* writeback all bio, not include current bio */
				if(likely(mpd->bio))
					atomic_dec(&tio_work->bios_remaining);
				
				blk_finish_plug(&plug);
				
				if(atomic_read(&tio_work->bios_remaining))
					wait_for_completion(&tio_work->tio_complete);

				wr_pages = 0;
				atomic_set(&tio_work->error, 0);
				atomic_set(&tio_work->bios_remaining, 0);
				init_completion(&tio_work->tio_complete);
				blk_start_plug(&plug);
				if(likely(mpd->bio)){
					atomic_inc(&tio_work->bios_remaining);
					wr_pages++;
				}
			}
		}
		if (mpd->bio)
			mpd->bio = cache_mpage_bio_submit(mpd->bio, WRITE);

		blk_finish_plug(&plug);

		if(atomic_read(&tio_work->bios_remaining))
			wait_for_completion(&tio_work->tio_complete);
		
		err = atomic_read(&tio_work->error);
		if(unlikely(err)){
			cache_err("Something unpected happened, disk may be abnormal.\n");
			goto error;
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

		/* set below threshold, to decrease pages to writeback */
		
	}	
	
	if (!cycled && !done) {
		/*
		 * range_cyclic:
		 * We hit the last page and there is more work to be done: wrap
		 * back to the start of the file
		 */
		cycled = 1;
		index = 0;
		end = writeback_index - 1;
		goto retry;
	}
	if (wbc->range_cyclic)
		iscsi_cache->writeback_index = done_index;
	
error:
	if(tio_work)
		kfree(tio_work);
	return err;
}


/*
* writeback the dirty pages of one volume, return nr of wrote pages.
*
* FIXME 
* periodically kupdate don't support oldest pages writeback now. 
*/
long writeback_single(struct iscsi_cache *iscsi_cache, unsigned int mode, long pages_to_write, bool cyclic)
{
	int ret;
	
	struct cache_writeback_control wbc = {
		.nr_to_write = pages_to_write,
		.mode = mode,
		.range_start = 0,
		.range_end = LONG_MAX,
		.range_cyclic = cyclic,
	};
	
	struct cache_mpage_data mpd = {
		.bio = NULL,
		.last_page_in_bio = 0,
	};
	
	ret = cache_writeback_mpage(iscsi_cache, &wbc, &mpd);
	
	BUG_ON(mpd.bio != NULL);

	if(unlikely(ret)){
		cache_err("An error has occurred when writeback.\n");
	}
	
	return (pages_to_write - wbc.nr_to_write);
}

