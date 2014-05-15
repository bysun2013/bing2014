/*
 * Target device block I/O.
 *
 * Based on file I/O driver from FUJITA Tomonori
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2006 Andre Brinkmann <brinkman at hni dot upb dot de>
 * (C) 2007 Ross Walker <rswwalker at hotmail dot com>
 * (C) 2007 Ming Zhang <blackmagic02881 at gmail dot com>
 * This code is licenced under the GPL.
 */

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include <linux/buffer_head.h>

#include "iscsi.h"
#include "iscsi_dbg.h"
#include "iotype.h"
#include "iscsi_cache.h"


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

/*
 * Blockio_make_request(): The function translates an iscsi-request into
 * a number of requests to the corresponding block device.
 */
static int
blockio_make_request(struct iet_volume *volume, struct tio *tio, int rw)
{
	struct blockio_data *bio_data = volume->private;
	struct request_queue *bdev_q = bdev_get_queue(bio_data->bdev);
	struct tio_work *tio_work;
	struct bio *tio_bio = NULL, *bio = NULL, *biotail = NULL;
	struct blk_plug plug;

	u32 size = tio->size;
	u32 tio_index = 0;

	int max_pages = 1;
	int err = 0;

	loff_t ppos = tio->offset;

	/* Calculate max_pages for bio_alloc (memory saver) */
	if (bdev_q)
		max_pages = bio_get_nr_vecs(bio_data->bdev);

	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work)
		return -ENOMEM;

	atomic_set(&tio_work->error, 0);
	atomic_set(&tio_work->bios_remaining, 0);
	init_completion(&tio_work->tio_complete);
	
	/* Main processing loop, allocate and fill all bios */
	while (size && tio_index < tio->pg_cnt) {
		bio = bio_alloc(GFP_KERNEL, min(max_pages, BIO_MAX_PAGES));
		if (!bio) {
			err = -ENOMEM;
			goto out;
		}

		/* bi_sector is ALWAYS in units of 512 bytes */
		bio->bi_sector = ppos >> 9;
		bio->bi_bdev = bio_data->bdev;
		bio->bi_end_io = blockio_bio_endio;
		bio->bi_private = tio_work;

		if (tio_bio)
			biotail = biotail->bi_next = bio;
		else
			tio_bio = biotail = bio;

		atomic_inc(&tio_work->bios_remaining);

		/* Loop for filling bio */
		while (size && tio_index < tio->pg_cnt) {
			unsigned int bytes = PAGE_SIZE;

			if (bytes > size)
				bytes = size;

			if (!bio_add_page(bio, tio->pvec[tio_index], bytes, 0))
				break;

			size -= bytes;
			ppos += bytes;

			tio_index++;
		}
	}

	blk_start_plug(&plug);

	/* Walk the list, submitting bios 1 by 1 */
	while (tio_bio) {
		bio = tio_bio;
		tio_bio = tio_bio->bi_next;
		bio->bi_next = NULL;

		submit_bio(rw, bio);
	}

	blk_finish_plug(&plug);

	wait_for_completion(&tio_work->tio_complete);

	err = atomic_read(&tio_work->error);

	kfree(tio_work);

	return err;
out:
	while (tio_bio) {
		bio = tio_bio;
		tio_bio = tio_bio->bi_next;

		bio_put(bio);
	}

	kfree(tio_work);

	return err;
}

/**
	submit single page segment to the block device, 
	one segment includes several continuous blocks.
*/
static int
blockio_start_rw_single_segment(struct iet_cache_page *iet_page,  
	unsigned int start, unsigned int blocks, int rw)
{
	struct blockio_data *bio_data = iet_page->volume->private;
	struct tio_work *tio_work;
	struct bio *bio = NULL;
	struct blk_plug plug;
	
	unsigned int bytes = blocks*512;
	unsigned int offset = start*512;
	int max_pages = 1;
	int err = 0;

	if(blocks==0)
		return err;
	printk(KERN_ALERT"submit blocks to device, start=%d, sizes=%d\n", start, blocks);
	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work)
		return -ENOMEM;

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
	bio->bi_bdev = bio_data->bdev;
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

	return err;
}

static int
blockio_start_rw_page(struct iet_cache_page *iet_page,   int rw)
{
	struct blockio_data *bio_data = iet_page->volume->private;
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
	bio->bi_bdev = bio_data->bdev;
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
	printk(KERN_ALERT"Error when rw page.\n");

	kfree(tio_work);

	return err;
}

/**
* blocks in a page aren't always valid,so when writeback
* submit to block device separately is necessary.
*
* Just used in writeback dirty blocks.
*/
int
blockio_start_rw_page_blocks(struct iet_cache_page *iet_page,  int rw)
{
	char bitmap=iet_page->dirty_bitmap;
	unsigned int i=0, start=0, last=1, sizes=0;
	int err=0;
	int tmp=1;

	/* it's more possible, so detect it first. */
	if((iet_page->dirty_bitmap & 0xff) == 0xff){
		err=blockio_start_rw_page(iet_page, WRITE);
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
				err=blockio_start_rw_single_segment(iet_page, start, sizes, rw);
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
		err=blockio_start_rw_single_segment(iet_page, start, sizes, rw);
		if(unlikely(err))
			goto error;
	}
	return 0;
	
error:	
	printk(KERN_ALERT"Error when submit blocks to device.\n");
	return err;
}

static int
blockio_make_write_request(struct iet_volume *volume, struct tio *tio, int rw)
{
	struct iet_cache_page *iet_page;
	
	u32 size = tio->size;
	u32 tio_index = 0;
	u32 sector_num;
	int err = 0;
	char bitmap;
	loff_t ppos = tio->offset;
	sector_t lba, alba, lba_off;
	u64 page_index;
	assert(ppos%512==0);
	
	/* Main processing loop */
	while (size && tio_index < tio->pg_cnt) {
			unsigned int current_bytes, bytes = PAGE_SIZE;
			unsigned int  skip_blk=0;

			if (bytes > size)
				bytes = size;

			while(bytes>0){
				lba=ppos>>9;
				page_index=lba>>3;
				alba=page_index<<3;
				lba_off=lba-alba;
printk(KERN_ALERT"WRITE ppos=%lld, LBA=%llu, page num=%lu", ppos, lba, (unsigned long)page_index);				
				current_bytes=PAGE_SIZE-(lba_off<<9);
				if(current_bytes>bytes)
					current_bytes=bytes;
				sector_num=current_bytes>>9;
				bitmap=get_bitmap(lba_off, sector_num);
again:
				iet_page= iet_find_get_page(volume, page_index);

				if(iet_page == NULL){	/* Write Miss */
					iet_page=iet_get_free_page();

					iet_page->volume=volume;
					iet_page->index=page_index;

					lock_page(iet_page->page);
					err=iet_add_page(volume, iet_page);
					if(unlikely(err)){
						if(err==-EEXIST){
							throw_to_lru_list(&iet_page->lru_list);
							unlock_page(iet_page->page);
							iet_page=NULL;
							goto again;
						}
						printk(KERN_ERR"Error, but reason is not clear.\n");
						unlock_page(iet_page->page);
						return err;
					}
					
					copy_tio_to_cache(tio->pvec[tio_index], iet_page, bitmap, skip_blk, current_bytes);

					iet_page->valid_bitmap |= bitmap;
					iet_page->dirty_bitmap |=bitmap;
					//iet_set_page_tag(iet_page, IETCACHE_TAG_DIRTY);
					
					unlock_page(iet_page->page);
					
					add_to_lru_list(&iet_page->lru_list);
					add_to_wb_list(&iet_page->wb_list);
					printk(KERN_ALERT"WRITE MISS\n");
				}else{		/* Write Hit */

					lock_page(iet_page->page);
					
					 mutex_lock(&iet_page->write);
					copy_tio_to_cache(tio->pvec[tio_index], iet_page, bitmap, skip_blk, current_bytes);

					iet_page->valid_bitmap |= bitmap;
					iet_page->dirty_bitmap |= bitmap;
					//iet_set_page_tag(iet_page, IETCACHE_TAG_DIRTY);
					
					 mutex_unlock(&iet_page->write);
					
					unlock_page(iet_page->page);
					
					update_lru_list(&iet_page->lru_list);
					add_to_wb_list(&iet_page->wb_list);

					printk(KERN_ALERT"WRITE HIT\n");
				}
				bytes-=current_bytes;
				size -=current_bytes;
				skip_blk+=sector_num;
				ppos+=current_bytes;
			}
			
			tio_index++;
	}
	return err;
}

static int
blockio_make_read_request(struct iet_volume *volume, struct tio *tio, int rw)
{
	struct iet_cache_page *iet_page;
	
	u32 size = tio->size;
	u32 tio_index = 0;
	u32 sector_num;
	int err = 0;
	char bitmap;
	loff_t ppos = tio->offset;
	sector_t lba, alba, lba_off;
	pgoff_t page_index;
	
	assert(ppos%512==0);

	/* Main processing loop */
	while (size && tio_index < tio->pg_cnt) {
			unsigned int bytes = PAGE_SIZE;
			unsigned int current_bytes, skip_blk=0;

			if (bytes > size)
				bytes = size;

			while(bytes>0){
				lba=ppos>>9;
				page_index=lba>>3;
				alba=page_index<<3;
				lba_off=lba-alba;
printk(KERN_ALERT"READ ppos=%lld, LBA=%llu, page num=%lu", ppos, lba, (unsigned long)page_index);
				current_bytes=PAGE_SIZE-(lba_off<<9);
				if(current_bytes>bytes)
					current_bytes=bytes;
				sector_num=current_bytes>>9;
				bitmap=get_bitmap(lba_off, sector_num);
again:
				iet_page= iet_find_get_page(volume, page_index);
				
				if(iet_page){	/* Read Hit */
					lock_page(iet_page->page);
					
					copy_cache_to_tio(iet_page, tio->pvec[tio_index], bitmap, skip_blk, current_bytes);
					
					assert(iet_page->valid_bitmap & bitmap);

					unlock_page(iet_page->page);
					
					update_lru_list(&iet_page->lru_list);
					printk(KERN_ALERT"READ HIT\n");	
				}

				if(!iet_page){	/* Read Miss, no page */
					iet_page=iet_get_free_page();

					iet_page->volume=volume;
					iet_page->index=page_index;

					lock_page(iet_page->page);
					
					err=iet_add_page(volume, iet_page);
					if(unlikely(err)){
						if(err==-EEXIST){
							throw_to_lru_list(&iet_page->lru_list);
							unlock_page(iet_page->page);
							iet_page=NULL;
							goto again;
						}
						printk(KERN_ERR"Error, but reason is not clear.\n");
						unlock_page(iet_page->page);
						return err;
					}
					blockio_start_rw_page(iet_page, READ);
					
					copy_cache_to_tio(iet_page, tio->pvec[tio_index],  bitmap, skip_blk, current_bytes);
					
					iet_page->valid_bitmap =0xff;

					unlock_page(iet_page->page);					
					
					add_to_lru_list(&iet_page->lru_list);
					
					printk(KERN_ALERT"READ MISS, no page\n");	
				}
				bytes-=current_bytes;
				size -=current_bytes;
				skip_blk+=sector_num;
				ppos+=current_bytes;
			}
			tio_index++;
	}

	return err;
}

static int
blockio_open_path(struct iet_volume *volume, const char *path)
{
	struct blockio_data *bio_data = volume->private;
	struct block_device *bdev;
	int flags = FMODE_EXCL | FMODE_READ | (LUReadonly(volume) ? 0 : FMODE_WRITE);
	int err = 0;

	bio_data->path = kstrdup(path, GFP_KERNEL);
	if (!bio_data->path)
		return -ENOMEM;

	bdev = blkdev_get_by_path(path, flags, THIS_MODULE);
	if (IS_ERR(bdev)) {
		err = PTR_ERR(bdev);
		eprintk("Can't open device %s, error %d\n", path, err);
		bio_data->bdev = NULL;
	} else {
		bio_data->bdev = bdev;
		fsync_bdev(bio_data->bdev);
	}

	return err;
}

/* Create an enumeration of our accepted actions */
enum
{
	opt_path, opt_ignore, opt_err,
};

/* Create a match table using our action enums and their matching options */
static match_table_t tokens = {
	{opt_path, "path=%s"},
	{opt_ignore, "scsiid=%s"},
	{opt_ignore, "scsisn=%s"},
	{opt_ignore, "type=%s"},
	{opt_ignore, "iomode=%s"},
	{opt_ignore, "blocksize=%s"},
	{opt_err, NULL},
};

static int
parse_blockio_params(struct iet_volume *volume, char *params)
{
	struct blockio_data *info = volume->private;
	int err = 0;
	char *p, *q;

	/* Loop through parameters separated by commas, look up our
	 * parameter in match table, return enumeration and arguments
	 * select case based on the returned enum and run the action */
	while ((p = strsep(&params, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;
		iet_strtolower(p);
		token = match_token(p, tokens, args);
		switch (token) {
		case opt_path:
			if (info->path) {
				iprintk("Target %s, LUN %u: "
					"duplicate \"Path\" param\n",
					volume->target->name, volume->lun);
				err = -EINVAL;
				goto out;
			}
			if (!(q = match_strdup(&args[0]))) {
				err = -ENOMEM;
				goto out;
			}
			err = blockio_open_path(volume, q);
			kfree(q);
			if (err < 0)
				goto out;
			break;
		case opt_ignore:
			break;
		default:
			iprintk("Target %s, LUN %u: unknown param %s\n",
				volume->target->name, volume->lun, p);
			return -EINVAL;
		}
	}

	if (!info->path) {
		iprintk("Target %s, LUN %u: missing \"Path\" param\n",
			volume->target->name, volume->lun);
		err = -EINVAL;
	}

  out:
	return err;
}

static void
blockio_detach(struct iet_volume *volume)
{
	struct blockio_data *bio_data = volume->private;
	int flags = FMODE_EXCL | FMODE_READ | (LUReadonly(volume) ? 0 : FMODE_WRITE);

	if (bio_data->bdev)
		blkdev_put(bio_data->bdev, flags);
	kfree(bio_data->path);

	kfree(volume->private);
}

static int
blockio_attach(struct iet_volume *volume, char *args)
{
	struct blockio_data *bio_data;
	int err = 0;

	if (volume->private) {
		eprintk("Lun %u already attached on Target %s \n",
			volume->lun, volume->target->name);
		return -EBUSY;
	}

	bio_data = kzalloc(sizeof (*bio_data), GFP_KERNEL);
	if (!bio_data)
		return -ENOMEM;

	volume->private = bio_data;

	err = parse_blockio_params(volume, args);
	if (!err) {
		/* see Documentation/ABI/testing/sysfs-block */
		unsigned bsz = bdev_logical_block_size(bio_data->bdev);
		if (!volume->blk_shift)
			volume->blk_shift = blksize_bits(bsz);
		else if (volume->blk_shift < blksize_bits(bsz)) {
			eprintk("Specified block size (%u) smaller than "
				"device %s logical block size (%u)\n",
				(1 << volume->blk_shift), bio_data->path, bsz);
			err = -EINVAL;
		}
	}
	if (err < 0) {
		eprintk("Error attaching Lun %u to Target %s \n",
			volume->lun, volume->target->name);
		goto out;
	}

	volume->blk_cnt = bio_data->bdev->bd_inode->i_size >> volume->blk_shift;

	/* Offer neither write nor read caching */
	ClearLURCache(volume);
	ClearLUWCache(volume);

  out:
	if (err < 0)
		blockio_detach(volume);

	return err;
}

static void
blockio_show(struct iet_volume *volume, struct seq_file *seq)
{
	struct blockio_data *bio_data = volume->private;

	/* Used to display blockio volume info in /proc/net/iet/volumes */
	seq_printf(seq, " path:%s\n", bio_data->path);
}

struct iotype blockio = {
	.name = "blockio",
	.attach = blockio_attach,
	.make_read_request = blockio_make_read_request,
	.make_write_request = blockio_make_write_request,
	.detach = blockio_detach,
	.show = blockio_show,
};
