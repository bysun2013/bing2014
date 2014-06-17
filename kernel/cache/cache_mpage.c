#include "cache.h"


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
	
	err = test_bit(BIO_UPTODATE, &bio->bi_flags) ? err : -EIO;
	if (err)
		atomic_set(&tio_work->error, err);
	
	do {
		struct page *page = bvec->bv_page;
		struct iscsi_cache_page *iscsi_page = (struct iscsi_cache_page *)page->mapping;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);
		if (bio_data_dir(bio) == READ) {
			if (uptodate) {
				SetPageUptodate(page);
			} else {
				ClearPageUptodate(page);
				SetPageError(page);
			}
			unlock_page(page);
		} else { /* WRITE */
			if (!uptodate) {
				SetPageError(page);
				cache_err("Error when submit to block device.\n");
			}
			
			cache_err("WRITEBACK one page. Index is %llu, dirty bitmap is %#x.\n", 
				(unsigned long long)iscsi_page->index, iscsi_page->dirty_bitmap);
			
			iscsi_page->dirty_bitmap=0x00;
			iscsi_page->iscsi_cache->dirty_pages--;
			mutex_unlock(&iscsi_page->write);
			
			iscsi_clear_page_tag(iscsi_page, ISCSICACHE_TAG_TOWRITE);
			iscsi_clear_page_tag(iscsi_page, ISCSICACHE_TAG_DIRTY);

			unlock_page(iscsi_page->page);
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

/**
* unlock_page() must be done in cache_mpage_endio.
*/
static int cache_do_writepage(struct iscsi_cache_page *iscsi_page, 
	struct cache_wb_control *wbc, struct mpage_data *mpd, struct tio_work *tio_work)
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
	
	//cache_set_page_writeback(iscsi_page);
out:
	mpd->bio = bio;
	return err;
	
confused:
	cache_err("writeback blocks to device come here.\n");
	if (bio)
		bio = cache_mpage_bio_submit(bio, WRITE);

	err = cache_write_page_blocks(iscsi_page, iscsi_page->bdev);
	if (unlikely(err)) {
		cache_err("Error when writeback blocks to device.\n");
	}

	goto out;
}

#define PVEC_SIZE		16

/* return nr of wrote pages */
int cache_writeback_mpage(struct iscsi_cache *iscsi_cache, struct cache_wb_control *wbc,
			struct mpage_data *mpd)
{
	int err = 0;
	int done = 0;
	unsigned long wrote = 0;
	struct iscsi_cache_page *pages[PVEC_SIZE];
	pgoff_t index=0;
	pgoff_t end=wbc->range_end;
	unsigned long  nr_pages = wbc->nr_to_write;
	
	int tag;
	
	if (wbc->sync_mode == ISCSI_WB_SYNC_ALL)
		tag = ISCSICACHE_TAG_TOWRITE;
	else
		tag = ISCSICACHE_TAG_DIRTY;

	if(!iscsi_cache)
		return 0;

	if (wbc->sync_mode == ISCSI_WB_SYNC_ALL)
		iscsi_tag_pages_for_writeback(iscsi_cache, index, end);

	while (!done && (index <= end)) {
		int i;
		struct blk_plug plug;
		struct tio_work *tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
		if (!tio_work)
			return -ENOMEM;
		atomic_set(&tio_work->error, 0);
		atomic_set(&tio_work->bios_remaining, 0);
		init_completion(&tio_work->tio_complete);
		
		nr_pages = iscsi_find_get_pages_tag(iscsi_cache, &index, tag,
			      min(end - index, (pgoff_t)PVEC_SIZE-1) + 1, pages);
		if (nr_pages == 0)
			break;

		blk_start_plug(&plug);
		cache_err("begin to plug.\n");

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
				continue;
			}

			if (!(iscsi_page->dirty_bitmap & 0xff)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if (!mutex_trylock(&iscsi_page->write)) {
				if (wbc->sync_mode == ISCSI_WB_SYNC_ALL)
					mutex_lock(&iscsi_page->write);
				else
					goto continue_unlock;
			}
			
			err = cache_do_writepage(iscsi_page, wbc, mpd, tio_work);
			if (unlikely(err)) {
				cache_err("Error when writeback blocks to device.\n");
				continue;
			}
			wrote++;

			if(--nr_pages < 1 && wbc->sync_mode == ISCSI_WB_SYNC_NONE){
				done=1;
				break;
			}
		}
		if (mpd->bio)
			cache_mpage_bio_submit(mpd->bio, WRITE);
		
		cache_err("begin to unplug.\n");
		blk_finish_plug(&plug);
		
		wait_for_completion(&tio_work->tio_complete);
		cache_err("finish one submit, success.\n");
		
		err = atomic_read(&tio_work->error);
		if(err)
			cache_err("Error when subumit to block device.\n");
		kfree(tio_work);
		
		cond_resched();
	}
	return wrote;
}


/* return nr of wrote pages */
int writeback_single(struct iscsi_cache *iscsi_cache, unsigned int mode, unsigned long pages_to_write)
{
	int ret;
	
	struct cache_wb_control wbc = {
		.nr_to_write = pages_to_write,
		.sync_mode = mode,
		.range_start = 0,
		.range_end = ULONG_MAX,
	};
	
	struct mpage_data mpd = {
		.bio = NULL,
		.last_page_in_bio = 0,
	};
	
	ret = cache_writeback_mpage(iscsi_cache, &wbc, &mpd);
	
	if (mpd.bio)
		cache_mpage_bio_submit(mpd.bio, WRITE);

	return ret;	

}

