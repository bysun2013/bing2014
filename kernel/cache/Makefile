#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

dcache-y	:= cache.o cache_lru.o cache_wb.o cache_rw.o cache_proc.o

obj-m		+= dcache.o
