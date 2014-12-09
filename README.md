dcache
=========
A Independent Disk Cache Module

Based on IET(iSCSI Enterprise Target), it provide a independent disk cache for block IO, which is different from page cache of linux kernel.

dcache store disk data in continuous independent memory region, which is reserved when linux kernel starts.
this memory region is managed by dcache, and linux kernel can't control this memory region, so dcache can 
do what it want to do in this memory region.
