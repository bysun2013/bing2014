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

static int
blockio_make_write_request(struct iet_volume *volume, struct tio *tio, int rw)
{
	u32 size = tio->size;
	loff_t ppos = tio->offset;
	int err;
	
	err = iscsi_write_cache(volume->iscsi_cache, tio->pvec, tio->pg_cnt, size, ppos);

	return err;
}

static int
blockio_make_read_request(struct iet_volume *volume, struct tio *tio, int rw)
{
	u32 size = tio->size;
	loff_t ppos = tio->offset;
	int err;

	err = iscsi_read_cache(volume->iscsi_cache, tio->pvec, tio->pg_cnt, size, ppos);
	
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
