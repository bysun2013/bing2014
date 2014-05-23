#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

ifneq ($(KERNELRELEASE) , )
	obj-m := iscsi_caches.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	make -C $(KERNELDIR) M=$(PWD) modules

endif

iscsi_caches-objs	:= iscsi_cache.o writeback.o

