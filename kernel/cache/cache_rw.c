/*
 * cache_rw.c
 *
 * handler for disk read/write
 *
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


#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/hash.h>
#include <asm/atomic.h>

#include "cache_def.h"
#include "cache_wb.h"
#include "cache_lru.h"

void dcache_end_page_writeback(struct dcache_page *dcache_page);

struct tio_work {
	atomic_t error;
	atomic_t bios_remaining;
	struct completion tio_complete;
};

/*
* called by disk driver, after data are read from disk
*/
static void dcache_page_endio(struct bio *bio, int error)
{
	struct tio_work *tio_work = bio->bi_private;
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;

	error = test_bit(BIO_UPTODATE, &bio->bi_flags) ? error : -EIO;

	if (error)
		atomic_set(&tio_work->error, error);

	do {
		struct page *page = bvec->bv_page;
		struct dcache_page *dcache_page = (struct dcache_page *)page->mapping;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);
		if (unlikely(bio_data_dir(bio) == WRITE)){
			cache_dbg("Single Page: WRITEBACK one page. Index is %llu.\n", 
				(unsigned long long)dcache_page->index);
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
static int dcache_rw_segment(struct dcache_page *dcache_page,
	unsigned int start, unsigned int blocks, int rw)
{
	struct block_device *bdev = dcache_page->dcache->bdev;
	struct tio_work *tio_work;
	struct bio *bio = NULL;
	struct blk_plug plug;
	
	unsigned int bytes = blocks * SECTOR_SIZE;
	unsigned int offset = start * SECTOR_SIZE;
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
	bio->bi_sector = (dcache_page->index<< SECTORS_ONE_PAGE_SHIFT)+start;
	bio->bi_bdev = bdev;
	bio->bi_end_io = dcache_page_endio;
	bio->bi_private = tio_work;

	atomic_inc(&tio_work->bios_remaining);

	if (!bio_add_page(bio, dcache_page->page, bytes, offset)){
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

static int dcache_rw_page(struct dcache_page *dcache_page, int rw)
{
	struct block_device *bdev = dcache_page->dcache->bdev;
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
	bio->bi_sector = dcache_page->index<< SECTORS_ONE_PAGE_SHIFT;
	bio->bi_bdev = bdev;
	bio->bi_end_io = dcache_page_endio;
	bio->bi_private = tio_work;
	
	atomic_inc(&tio_work->bios_remaining);
	
	if (!bio_add_page(bio, dcache_page->page, bytes, 0)){
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

/*
* check bitmap, and write blocks whose bitmap is 1 to disk,
* merge as much blocks as possible
*/
static int _dcache_rw_page_blocks(struct dcache_page *dcache_page, unsigned char bitmap, int rw)
{
	unsigned int i=0, start=0, last=1, sizes=0;
	int err=0;
	int tmp=1;

	if(unlikely((bitmap & 0xff) == 0xff)){
		err=dcache_rw_page(dcache_page, rw);
		return err;
	}
	
	for(i = 0; i < SECTORS_ONE_PAGE; i++){
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
				err = dcache_rw_segment(dcache_page, start, sizes, rw);
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
		err=dcache_rw_segment(dcache_page, start, sizes, rw);
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
int dcache_write_page_blocks(struct dcache_page *dcache_page)
{
	int err;
	char bitmap=dcache_page->dirty_bitmap;
	
	err = _dcache_rw_page_blocks(dcache_page, bitmap, WRITE);
	return err;
}
/*
* If valid bitmap is not agreed to bitmap to read, then 
* read the missed blocks.
*/
int dcache_check_read_blocks(struct dcache_page *dcache_page,
		unsigned char valid, unsigned char read)
{
	unsigned char miss;
	int err;
	miss = valid | read;
	miss = miss ^ valid;

	err = _dcache_rw_page_blocks(dcache_page, miss, READ);

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

void dcache_set_page_tag(struct dcache_page *dcache_page, unsigned int tag)
{
	struct dcache *dcache=dcache_page->dcache;
	if (dcache) {	/* Race with truncate? */
		spin_lock_irq(&dcache->tree_lock);
		radix_tree_tag_set(&dcache->page_tree,
				dcache_page->index, tag);
		spin_unlock_irq(&dcache->tree_lock);
	}
}

static void dcache_tag_pages_for_writeback(struct dcache *dcache,
			     pgoff_t start, pgoff_t end)
{
#define WRITEBACK_TAG_BATCH 4096
	unsigned long tagged;

	do {
		spin_lock_irq(&dcache->tree_lock);
		tagged = radix_tree_range_tag_if_tagged(&dcache->page_tree,
				&start, end, WRITEBACK_TAG_BATCH,
				DCACHE_TAG_DIRTY, DCACHE_TAG_TOWRITE);
		spin_unlock_irq(&dcache->tree_lock);
		WARN_ON_ONCE(tagged > WRITEBACK_TAG_BATCH);

		cond_resched();
		/* We check 'start' to handle wrapping when end == ~0UL */
	} while (tagged >= WRITEBACK_TAG_BATCH && start);
}

static unsigned dcache_find_get_pages_tag(struct dcache *dcache, pgoff_t *index,
			int tag, unsigned int nr_pages, struct dcache_page **pages)
{
	unsigned int ret = 0;
	struct radix_tree_iter iter;
	void **slot;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_tagged(slot, &dcache->page_tree,
				   &iter, *index, tag){
		struct dcache_page *page;
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

static void dcache_delete_page(struct dcache_page *dcache_page)
{
	struct dcache *dcache=dcache_page->dcache;
	
	if (dcache) {
		spin_lock_irq(&dcache->tree_lock);
		radix_tree_delete(&dcache->page_tree,
				dcache_page->index);
		dcache_page->dcache = NULL;
		spin_unlock_irq(&dcache->tree_lock);
	}
}

static unsigned dcache_find_get_pages(struct dcache *dcache, pgoff_t start,
			unsigned int nr_pages, struct dcache_page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_slot(slot, &dcache->page_tree, &iter, start) {
		struct dcache_page *page;
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


#define DEL_MAX_SIZE 64

/*
* called when delete one volume, to destroy radix tree
*/
void dcache_delete_radix_tree(struct dcache *dcache)
{
	struct dcache_page *pages[DEL_MAX_SIZE];
	pgoff_t index=0;
	pgoff_t end= ULONG_MAX;
	unsigned long  nr_pages;

	if(!dcache)
		return;
	
	while (true) {
		int i;
		nr_pages = dcache_find_get_pages(dcache, index,
			      min(end - index, (pgoff_t)DEL_MAX_SIZE-1) + 1, pages);
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct dcache_page *dcache_page = pages[i];

			lock_page(dcache_page->page);
			if (unlikely(dcache_page->dcache != dcache)) {
				unlock_page(dcache_page->page); 
				continue;
			}
			dcache_delete_page(dcache_page);
			unlock_page(dcache_page->page);
		}
	}
	cache_dbg("OK, radix tree of %s is deleted.\n", dcache->path);
}

static int dcache_test_clear_page_writeback(struct dcache_page *dcache_page)
{
	struct dcache *dcache = dcache_page->dcache;
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&dcache->tree_lock, flags);
	ret = TestClearPageWriteback(dcache_page->page);
	if (ret) {
		radix_tree_tag_clear(&dcache->page_tree,
					dcache_page->index,
					DCACHE_TAG_WRITEBACK);
	}
	spin_unlock_irqrestore(&dcache->tree_lock, flags);

	return ret;
}

static int dcache_test_set_page_writeback(struct dcache_page *dcache_page)
{
	struct dcache *dcache = dcache_page->dcache;
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&dcache->tree_lock, flags);
	ret = TestSetPageWriteback(dcache_page->page);
	if (!ret) {
		radix_tree_tag_set(&dcache->page_tree,
					dcache_page->index,
					DCACHE_TAG_WRITEBACK);
	}
	
	radix_tree_tag_clear(&dcache->page_tree,
				dcache_page->index,
				DCACHE_TAG_DIRTY);
	radix_tree_tag_clear(&dcache->page_tree,
			     dcache_page->index,
			     DCACHE_TAG_TOWRITE);
	spin_unlock_irqrestore(&dcache->tree_lock, flags);

	return ret;

}

/*
* clear WB flag of page, called after data is written to disk.
*/
void dcache_end_page_writeback(struct dcache_page *dcache_page)
{
	if (!dcache_test_clear_page_writeback(dcache_page))
		BUG();

	smp_mb__after_clear_bit();
	wake_up_page(dcache_page->page, PG_writeback);
}

/*
 * I/O completion handler for multipage BIOs.
 */
static void dcache_mpage_endio(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;
	struct tio_work *tio_work = bio->bi_private;
	
	err = uptodate ? err : -EIO;
	if (err)
		atomic_set(&tio_work->error, err);
	
	do {
		struct page *page = bvec->bv_page;
		struct dcache_page *dcache_page = (struct dcache_page *)page->mapping;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);
		
		if (bio_data_dir(bio) == READ) {
			dcache_page->valid_bitmap = 0xff;
			cache_ignore("READ one page. Index is %llu\n",
				(unsigned long long)dcache_page->index);		
		} else { /* WRITE */
			cache_ignore("Mpage: WRITEBACK one page. Index is %llu\n", 
				(unsigned long long)dcache_page->index);
		}
	} while (bvec >= bio->bi_io_vec);
	
	cache_ignore("%s: This bio includes %d pages.\n", bio_data_dir(bio) == READ? "READ":"WRITE", bio->bi_vcnt);
	
	/* If last bio signal completion */
	if (atomic_dec_and_test(&tio_work->bios_remaining))
		complete(&tio_work->tio_complete);
	
	bio_put(bio);
}

static struct bio * dcache_mpage_alloc(struct block_device *bdev,
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

struct bio *dcache_mpage_bio_submit(struct bio *bio, int rw)
{
	bio->bi_end_io = dcache_mpage_endio;
	submit_bio(rw, bio);
	
	return NULL;
}

static int dcache_do_readpage(struct dcache_page *dcache_page, int nr_pages,
	struct cache_mpage_data *mpd, struct tio_work *tio_work)
{	
	int err = 0;
	int length = PAGE_SIZE;
	struct bio* bio = mpd->bio;
	struct dcache *dcache = dcache_page->dcache;
	struct block_device * bdev = dcache->bdev;

	if (bio && (mpd->last_page_in_bio + 1 != dcache_page->index))
		bio = dcache_mpage_bio_submit(bio, READ);

alloc_new:
	if (bio == NULL) {
		bio = dcache_mpage_alloc(bdev, dcache_page->index <<SECTORS_ONE_PAGE_SHIFT,
			  	min_t(int, nr_pages, bio_get_nr_vecs(bdev)),
				GFP_KERNEL);
		if (bio == NULL)
			goto confused;
		
		bio->bi_private = tio_work;
		atomic_inc(&tio_work->bios_remaining);
	}

	if (bio_add_page(bio, dcache_page->page, length, 0) < length) {
		cache_ignore("READ: bio maybe it's full: %d pages.\n", bio->bi_vcnt);
		bio = dcache_mpage_bio_submit(bio, READ);
		goto alloc_new;
	}
	
	mpd->last_page_in_bio = dcache_page->index;
	mpd->bio = bio;
	return err;
	
confused:
	if (bio)
		bio = dcache_mpage_bio_submit(bio, READ);

	err = dcache_rw_page(dcache_page, READ);
	
	mpd->bio = bio;
	return err;
}

/*
* multi-pages read/write, its pages maybe not sequential
* called by iscsi_read_cache
*/
static int _dcache_read_mpage(struct dcache *dcache, struct dcache_page **dcache_pages, 
	int pg_cnt, struct cache_mpage_data *mpd)
{
	int err = 0;
	struct tio_work *tio_work;
	int i, remain;
	struct blk_plug plug;

	if(!dcache || !pg_cnt)
		return 0;
	
	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work)
		return -ENOMEM;

	atomic_set(&tio_work->error, 0);
	atomic_set(&tio_work->bios_remaining, 0);
	init_completion(&tio_work->tio_complete);

	blk_start_plug(&plug);
	for (i = 0, remain = pg_cnt; i < pg_cnt; i++, remain--) {
		struct dcache_page *dcache_page = dcache_pages[i];
		
		err = dcache_do_readpage(dcache_page, remain, mpd, tio_work);
		if (unlikely(err)) {
			cache_alert("It should never show up!Maybe disk crash... \n");
			BUG();
		}
	}
	
	if (mpd->bio)
		mpd->bio = dcache_mpage_bio_submit(mpd->bio, READ);

	blk_finish_plug(&plug);

	if(atomic_read(&tio_work->bios_remaining))
		wait_for_completion(&tio_work->tio_complete);
	
	err = atomic_read(&tio_work->error);
	if(err)
		cache_err("error when submit request to disk.\n");
	
	kfree(tio_work);
	return err;
}

int dcache_read_mpage(struct dcache *dcache, struct dcache_page **dcache_pages, int pg_cnt)
{
	int ret;
	
	struct cache_mpage_data mpd = {
		.bio = NULL,
		.last_page_in_bio = 0,
	};
	
	ret = _dcache_read_mpage(dcache, dcache_pages, pg_cnt, &mpd);
	
	BUG_ON(mpd.bio != NULL);

	if(unlikely(ret))
		cache_err("An error has occurred when read mpage.\n");

	return ret;
}

static int dcache_do_writepage(struct dcache_page *dcache_page, 
	struct cache_writeback_control *wbc, struct cache_mpage_data *mpd, struct tio_work *tio_work)
{	
	int err = 0;
	int length = PAGE_SIZE;
	long  nr_pages = wbc->nr_to_write;
	struct bio* bio = mpd->bio;
	struct dcache *dcache = dcache_page->dcache;
	struct block_device * bdev = dcache->bdev;

	if (bio && (mpd->last_page_in_bio != dcache_page->index -1))
		bio = dcache_mpage_bio_submit(bio, WRITE);

alloc_new:
	if (bio == NULL) {
		bio = dcache_mpage_alloc(bdev, dcache_page->index << SECTORS_ONE_PAGE_SHIFT,
			  	min_t(long, nr_pages, bio_get_nr_vecs(bdev)),
				GFP_KERNEL);
		if (bio == NULL){
			cache_warn("Memory has been used up...\n");
			goto confused;
		}
		bio->bi_private = tio_work;
		atomic_inc(&tio_work->bios_remaining);
	}

	if (bio_add_page(bio, dcache_page->page, length, 0) < length) {
		cache_ignore("WRITE: bio maybe it's full: %d pages.\n", bio->bi_vcnt);
		bio = dcache_mpage_bio_submit(bio, WRITE);
		goto alloc_new;
	}
	
	mpd->last_page_in_bio = dcache_page->index;
	mpd->bio = bio;
	return err;
	
confused:
	if (bio)
		bio = dcache_mpage_bio_submit(bio, WRITE);
	
	mpd->bio = bio;
	
	/* although I believe the minimal block should be 4KB, but I must check it */ 
	err = dcache_write_page_blocks(dcache_page);
	
	return err;
}

/*
* multi-pages are merged to one submit, to imrove efficiency
* return nr of wrote pages 
*/
static int dcache_writeback_mpage(struct dcache *dcache, struct cache_writeback_control *wbc,
			struct cache_mpage_data *mpd)
{
	int err = 0;
	int done = 0;
	struct tio_work *tio_work;
	struct dcache_page **pages;
	pgoff_t wb_index[PVEC_MAX_SIZE];
	pgoff_t writeback_index = 0;
	pgoff_t index, done_index;
	pgoff_t end;
	unsigned int nr_pages, wr_pages;
	int tag;
	int cycled;
	bool is_seq;

	BUG_ON(!dcache->owner);

	if(!dcache)
		return 0;
	
	pages = kzalloc(PVEC_MAX_SIZE * sizeof (struct dcache_page *), GFP_KERNEL);
	if (!pages){
		cache_err("Out of memory!\n");
		return -ENOMEM;
	}
	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work){
		cache_err("Out of memory!\n");
		kfree(pages);
		return -ENOMEM;
	}
	
	if (wbc->range_cyclic) {
		writeback_index = dcache->writeback_index;
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
	
	if (wbc->mode == DCACHE_WB_SYNC_ALL)
		tag = DCACHE_TAG_TOWRITE;
	else
		tag = DCACHE_TAG_DIRTY;
retry:
	if (wbc->mode == DCACHE_WB_SYNC_ALL)
		dcache_tag_pages_for_writeback(dcache, index, end);
	
	done_index = index;
	while (!done && (index <= end)) {
		int i;
		int wrote_index = 0;
		struct blk_plug plug;
		struct cache_request* req = NULL;
		LIST_HEAD(list_inactive);
		LIST_HEAD(list_active);
		
		atomic_set(&tio_work->error, 0);
		atomic_set(&tio_work->bios_remaining, 0);
		init_completion(&tio_work->tio_complete);

		nr_pages = dcache_find_get_pages_tag(dcache, &index, tag,
			      min(end - index, (pgoff_t)PVEC_MAX_SIZE-1) + 1, pages);
		if (nr_pages == 0)
			break;
		
		wr_pages = 0;
		
		blk_start_plug(&plug);
		for (i = 0; i < nr_pages; i++) {
			struct dcache_page *dcache_page = pages[i];

			if (dcache_page->index > end) {
				done = 1;
				break;
			}
			done_index = dcache_page->index;
			if(!trylock_page(dcache_page->page)){
				if (wbc->mode != DCACHE_WB_SYNC_NONE)
					lock_page(dcache_page->page);
				else
					continue;
			}

			if (unlikely(dcache_page->dcache != dcache)) {
continue_unlock:
				unlock_page(dcache_page->page);
				continue;
			}

			if (!(dcache_page->dirty_bitmap & 0xff)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if(PageWriteback(dcache_page->page)){
				if (wbc->mode != DCACHE_WB_SYNC_NONE)
					wait_on_page_writeback(dcache_page->page);
				else
					goto continue_unlock;
			}
			BUG_ON(PageWriteback(dcache_page->page));
			dcache_test_set_page_writeback(dcache_page);
			unlock_page(dcache_page->page);

			if(!mpd->bio)
				is_seq = 0;
			else
				is_seq = (mpd->last_page_in_bio == dcache_page->index -1 ? 1 : 0);
			
			err = dcache_do_writepage(dcache_page, wbc, mpd, tio_work);
			
			if (unlikely(err)) {
				cache_err("It should never show up!Maybe disk crash... \n");
				TestClearPageWriteback(dcache_page->page);
				smp_mb__after_clear_bit();
				wake_up_page(dcache_page->page, PG_writeback);
				goto continue_unlock;
			}
			
			if(!PageActive(dcache_page->page))
				list_add(&dcache_page->list, &list_inactive);
			else
				list_add(&dcache_page->list, &list_active);
			dcache_page->site = temp;
			
			wb_index[wrote_index++]= dcache_page->index;
			
			atomic_dec(&dcache->dirty_pages);
			
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
			mpd->bio = dcache_mpage_bio_submit(mpd->bio, WRITE);

		blk_finish_plug(&plug);

		if(atomic_read(&tio_work->bios_remaining))
			wait_for_completion(&tio_work->tio_complete);
		
		err = atomic_read(&tio_work->error);
		if(unlikely(err)) {
			cache_err("Something unpected happened, disk may be abnormal.\n");
			goto error;
		}
		
sync_again:
		/* submit page index of written pages to peer */
/*		if(dcache->owner && wrote_index && peer_is_good) {
			int m;
			for(m = wrote_index; m < PVEC_NORMAL_SIZE; m++)
				wb_index[m]= -1;
			
			cache_send_wrote(dcache->conn, wb_index, m, &req);
			cache_dbg("wait for wrote ack.\n");
			if(wait_for_completion_timeout(&req->done, HZ*60) == 0 && peer_is_good) {
				cache_warn("timeout when wait for wrote ack.\n");
				cache_request_dequeue(req);
				goto sync_again;
			}else{
				kmem_cache_free(cache_request_cache, req);
				cache_dbg("ok, get wrote ack, go on!\n");
			}			
		}
*/
		inactive_writeback_add_list(&list_inactive);
		active_writeback_add_list(&list_active);
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
		dcache->writeback_index = done_index;
	
error:
	if(tio_work)
		kfree(tio_work);
	if(pages)
		kfree(pages);
	return err;
}


/*
* writeback the dirty pages of one volume, return nr of wrote pages.
*
* FIXME 
* periodically kupdate don't support oldest pages writeback now. 
*/
long writeback_single(struct dcache *dcache, unsigned int mode, 
		long pages_to_write, bool cyclic)
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
	
	ret = dcache_writeback_mpage(dcache, &wbc, &mpd);
	
	BUG_ON(mpd.bio != NULL);

	if(unlikely(ret)){
		cache_err("An error has occurred when writeback, err = %d\n", ret);
	}
	
	return (pages_to_write - wbc.nr_to_write);
}

