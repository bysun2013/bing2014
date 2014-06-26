#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.
EXTRA_CFLAGS += -I$(src)/../../include 

obj-m		+= iscsi_caches.o
iscsi_caches-objs	:= cache.o cache_wb.o cache_rw.o cache_proc.o 
iscsi_caches-y		+= cache_conn/cache_conn.o cache_conn/cache_receiver.o cache_conn/cache_sender.o \
				cache_conn/cache_cio.o cache_config.o

