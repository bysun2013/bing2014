#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

#export KSRC := /usr/src/linux

DEPMOD = depmod

SUBDIRS := $(shell pwd)

ifeq ($(KSRC),)
	KSRC ?= /lib/modules/$(shell uname -r)/build
endif


ifneq ($(wildcard $(KSRC)/include/generated/utsrelease.h),)
	VERSION_FILE := $(KSRC)/include/generated/utsrelease.h
else
  ifneq ($(wildcard $(KSRC)/include/linux/utsrelease.h),)
	  VERSION_FILE := $(KSRC)/include/linux/utsrelease.h
  else
	  VERSION_FILE := $(KSRC)/include/linux/version.h
  endif
endif

KVER := $(shell $(CC) $(CFLAGS) $(LDFLAGS) -E -dM $(VERSION_FILE) | \
	grep UTS_RELEASE | awk '{ print $$3 }' | sed 's/\"//g')

KMOD := /lib/modules/$(KVER)/extra

KMAJ := $(shell echo $(KVER) | \
	sed -e 's/^\([0-9][0-9]*\)\.[0-9][0-9]*\.[0-9][0-9]*.*/\1/')
KMIN := $(shell echo $(KVER) | \
	sed -e 's/^[0-9][0-9]*\.\([0-9][0-9]*\)\.[0-9][0-9]*.*/\1/')
KREV := $(shell echo $(KVER) | \
	sed -e 's/^[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*/\1/')

kver_eq = $(shell [ $(KMAJ) -eq $(1) -a $(KMIN) -eq $(2) -a $(KREV) -eq $(3) ] && \
	echo 1 || echo 0)
kver_lt = $(shell [ $(KMAJ) -lt $(1) -o \
	$(KMAJ) -eq $(1) -a $(KMIN) -lt $(2) -o \
        $(KMAJ) -eq $(1) -a $(KMIN) -eq $(2) -a $(KREV) -lt $(3) ] && \
	echo 1 || echo 0)
kver_le = $(shell [ $(KMAJ) -lt $(1) -o \
        $(KMAJ) -eq $(1) -a $(KMIN) -lt $(2) -o \
        $(KMAJ) -eq $(1) -a $(KMIN) -eq $(2) -a $(KREV) -le $(3) ] && \
	echo 1 || echo 0)
kver_gt = $(shell [ ( $(KMAJ) -gt $(1) ) -o \
        $(KMAJ) -eq $(1) -a $(KMIN) -gt $(2) -o \
        $(KMAJ) -eq $(1) -a $(KMIN) -eq $(2) -a $(KREV) -gt $(3) ] && \
	echo 1 || echo 0)
kver_ge = $(shell [ ( $(KMAJ) -gt $(1) ) -o \
        $(KMAJ) -eq $(1) -a $(KMIN) -gt $(2) -o \
        $(KMAJ) -eq $(1) -a $(KMIN) -eq $(2) -a $(KREV) -ge $(3) ] && \
	echo 1 || echo 0)
kver_lk = $(shell [ `echo $(KVER) | egrep $(1)` ] && echo 1 || echo 0)


# Compatibility patches for SuSE distros
ifneq ($(wildcard /etc/SuSE-release),)
	# Compatibility patch for SLES 10 SP2
	ifeq ($(call kver_lk,"2\.6\.16\.60-.*"),1)
		PATCHES += compat-sles10sp2.patch
		UNSUPPORTED :=
	endif
endif

# Compatibility patches for Redhat distros
ifneq ($(wildcard /etc/redhat-release),)
	# Compatibility patch for RHEL4/CentOS4
	ifeq ($(call kver_lk,"2\.6\.9-.*\.(EL|plus\.c4)"),1)
		PATCHES += compat-rhel4.patch
		UNSUPPORTED :=
	endif
endif

MANPAGES:= ietadm.8 ietd.8 ietd.conf.5

ifeq ($(MANDIR),)
	MANPATH := $(shell (manpath 2>/dev/null || \
		echo $MANPATH) | sed 's/:/ /g')
	ifneq ($(MANPATH),)
		test_dir = $(findstring $(dir), $(MANPATH))
	else
		test_dir = $(shell [ -e $(dir) ] && echo $(dir))
	endif
	MANDIR := /usr/share/man /usr/man
	MANDIR := $(foreach dir, $(MANDIR), $(test_dir))
	MANDIR := $(firstword $(MANDIR))
endif

ifeq ($(MANDIR),)
	MANDIR := /usr/share/man
endif

DOCS:= ChangeLog COPYING RELEASE_NOTES README README.vmware README.initiators

ifeq ($(DOCDIR),)
	DOCDIR := /usr/share/doc/iscsitarget
endif

all: usr kernel  usr_cache

usr: patch
	$(MAKE) -C usr

kernel: patch
	$(MAKE) -C $(KSRC) SUBDIRS=$(shell pwd)/kernel modules

usr_cache: patch
	$(MAKE) -C usr_cache

patch: $(UNSUPPORTED) integ_check $(PATCHES)

$(UNSUPPORTED):
	@echo "Sorry, your kernel version and/or distribution is currently"
	@echo "not supported."
	@echo ""
	@echo "Please read the README file for information on how you can"
	@echo "contribute compatibility/bug fixes to the IET project."
	@exit 1

integ_check:
	@if [ -e .patched.* -a ! -e .patched.$(KVER) ]; then \
		$(MAKE) unpatch; \
	fi

$(PATCHES): .patched.$(KVER)

.patched.$(KVER):
	@set -e; \
	if [ ! -e .patched.* ]; then \
		for p in $(PATCHES); do \
			echo "Applying Patch $$p"; \
			patch -p1 < patches/$$p; \
			echo $$p >>.patched.$(KVER); \
		done; \
	fi

unpatch:
	@set -e; \
	if [ -e .patched.* ]; then \
		for p in `cat .patched.*`; do \
			reverse="$$p $$reverse"; \
		done; \
		for r in $$reverse; do \
			echo "Reversing patch $$r"; \
			patch -p1 -R < patches/$$r; \
		done; \
		rm -f .patched.*; \
	fi

depmod:
	@echo "Running depmod"
	@if [ x$(DESTDIR) != x -o x$(INSTALL_MOD_PATH) != x ]; then \
		$(DEPMOD) -aq -b $(DESTDIR)$(INSTALL_MOD_PATH) $(KVER); \
	else \
		$(DEPMOD) -aq $(KVER); \
	fi

install-files: install-usr install-etc install-doc install-kernel

install: install-files depmod

install-kernel: kernel/iscsi_trgt.ko kernel/cache/dcache.ko
	@if [ -d $(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/$(KVER) ]; then \
		if [ -f /etc/debian_version ]; then \
			find $(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/$(KVER) \
				-name iscsi_trgt.ko -type f \
				-exec /bin/sh -c "dpkg-divert --rename {}" \;; \
		else \
			find $(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/$(KVER) \
				-name iscsi_trgt.ko -type f \
				-execdir mv \{\} \{\}.orig \;; \
		fi \
	fi
	@if [ -d $(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/$(KVER) ]; then \
		if [ -f /etc/debian_version ]; then \
			find $(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/$(KVER) \
				-name dcache.ko -type f \
				-exec /bin/sh -c "dpkg-divert --rename {}" \;; \
		else \
			find $(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/$(KVER) \
				-name dcache.ko -type f \
				-execdir mv \{\} \{\}.orig \;; \
		fi \
	fi	
	@install -vD -m 644 kernel/iscsi_trgt.ko \
		$(DESTDIR)$(INSTALL_MOD_PATH)$(KMOD)/iscsi/iscsi_trgt.ko
	@install -vD -m 644 kernel/cache/dcache.ko \
		$(DESTDIR)$(INSTALL_MOD_PATH)$(KMOD)/iscsi/dcache.ko

install-usr: usr/ietd usr/ietadm  usr_cache/ietd_cache usr_cache/ietadm_cache
	@install -vD usr/ietd $(DESTDIR)/usr/sbin/ietd
	@install -vD usr/ietadm $(DESTDIR)/usr/sbin/ietadm
	@install -vD usr_cache/ietd_cache $(DESTDIR)/usr/sbin/ietd_cache
	@install -vD usr_cache/ietadm_cache $(DESTDIR)/usr/sbin/ietadm_cache
	
install-etc: install-initd
	@if [ ! -e $(DESTDIR)/etc/ietd.conf ]; then \
		if [ ! -e $(DESTDIR)/etc/iet/ietd.conf ]; then \
			install -vD -m 640 etc/ietd.conf \
				$(DESTDIR)/etc/iet/ietd.conf; \
		fi \
	fi
	@if [ ! -e $(DESTDIR)/etc/initiators.allow ]; then \
		if [ ! -e $(DESTDIR)/etc/iet/initiators.allow ]; then \
			install -vD -m 644 etc/initiators.allow \
				$(DESTDIR)/etc/iet/initiators.allow; \
		fi \
	fi
	@if [ ! -e $(DESTDIR)/etc/targets.allow ]; then \
		if [ ! -e $(DESTDIR)/etc/iet/targets.allow ]; then \
			install -vD -m 644 etc/targets.allow \
				$(DESTDIR)/etc/iet/targets.allow; \
		fi \
	fi
	@if [ ! -e $(DESTDIR)/etc/cache.conf ]; then \
		if [ ! -e $(DESTDIR)/etc/iet/cache.conf ]; then \
			install -vD -m 640 etc/cache.conf \
				$(DESTDIR)/etc/iet/cache.conf; \
		fi \
	fi
install-initd:
	@if [ -f /etc/debian_version ]; then \
		install -vD -m 755 etc/initd/initd.debian \
			$(DESTDIR)/etc/init.d/iscsi-target; \
	elif [ -f /etc/redhat-release ]; then \
		install -vD -m 755 etc/initd/initd.redhat \
			$(DESTDIR)/etc/rc.d/init.d/iscsi-target; \
	elif [ -f /etc/gentoo-release ]; then \
		install -vD -m 755 etc/initd/initd.gentoo \
			$(DESTDIR)/etc/init.d/iscsi-target; \
	elif [ -f /etc/slackware-version ]; then \
		install -vD -m 755 etc/initd/initd \
			$(DESTDIR)/etc/rc.d/iscsi-target; \
	else \
		install -vD -m 755 etc/initd/initd \
			$(DESTDIR)/etc/init.d/iscsi-target; \
	fi

install-doc: install-man
	@ok=true; for f in $(DOCS) ; \
		do [ -e $$f ] || \
			{ echo $$f missing ; ok=false; } ; \
	done ; $$ok
	@set -e; for f in $(DOCS) ; do \
		install -v -D -m 644 $$f \
			$(DESTDIR)$(DOCDIR)/$$f ; \
	done

install-man:
	@ok=true; for f in $(MANPAGES) ; \
		do [ -e doc/manpages/$$f ] || \
			{ echo doc/manpages/$$f missing ; ok=false; } ; \
	done ; $$ok
	@set -e; for f in $(MANPAGES) ; do \
		s=$${f##*.}; \
		install -v -D -m 644 doc/manpages/$$f \
			$(DESTDIR)$(MANDIR)/man$$s/$$f ; \
	done

uninstall: uninstall-kernel depmod uninstall-usr uninstall-etc uninstall-doc

uninstall-kernel:
	rm -f $(DESTDIR)$(INSTALL_MOD_PATH)$(KMOD)/iscsi/iscsi_trgt.ko
	@if [ -f /etc/debian_version ]; then \
		find $(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/$(KVER) \
			-name iscsi_trgt.ko.distrib -type f \
			-exec /bin/sh -c "dpkg-divert --remove --rename \
				\`dirname {}\`/iscsi_trgt.ko" \;; \
	else \
		find $(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/$(KVER) \
			-name iscsi_trgt.ko.orig -type f \
			-execdir mv \{\} iscsi_trgt.ko \;; \
        fi

uninstall-usr:
	@rm -f $(DESTDIR)/usr/sbin/ietd
	@rm -f $(DESTDIR)/usr/sbin/ietadm
	@rm -f $(DESTDIR)/usr/sbin/ietd_cache
	@rm -f $(DESTDIR)/usr/sbin/ietadm_cache
	
uninstall-etc: uninstall-initd

uninstall-initd:
	if [ -f /etc/debian_version ]; then \
		rm -f $(DESTDIR)/etc/init.d/iscsi-target; \
	elif [ -f /etc/redhat-release ]; then \
		rm -f $(DESTDIR)/etc/rc.d/init.d/iscsi-target; \
	elif [ -f /etc/gentoo-release ]; then \
		rm -f $(DESTDIR)/etc/init.d/iscsi-target; \
	elif [ -f /etc/slackware-version ]; then \
		rm -f $(DESTDIR)/etc/rc.d/iscsi-target; \
	else \
		rm -f $(DESTDIR)/etc/init.d/iscsi-target; \
	fi

uninstall-doc: uninstall-man
	rm -rf $(DESTDIR)$(DOCDIR)

uninstall-man:
	set -e; for f in $(MANPAGES) ; do \
		s=$${f##*.}; \
		rm -f $(DESTDIR)$(MANDIR)/man$$s/$$f ; \
	done

clean:
	$(MAKE) -C usr clean 
	$(MAKE) -C usr_cache clean 
	$(MAKE) -C $(KSRC) SUBDIRS=$(shell pwd)/kernel clean

distclean: unpatch clean
	find . -name \*.orig -exec rm -f \{\} \;
	find . -name \*.rej -exec rm -f \{\} \;
	find . -name \*~ -exec rm -f \{\} \;
	find . -name Module.symvers -exec rm -f \{\} \;
