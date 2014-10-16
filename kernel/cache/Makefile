#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.
EXTRA_CFLAGS += -g -I$(src)/../../include 

dcache-y	:= cache.o cache_lru.o cache_wb.o cache_rw.o cache_proc.o
dcache-y		+= cache_conn/cache_conn.o cache_conn/cache_receiver.o cache_conn/cache_sender.o \
				cache_conn/cache_cio.o cache_config.o cache_conn/cache_request.o

obj-m		+= dcache.o
