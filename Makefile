# SPDX-License-Identifier: GPL-2.0
#
# Makefile for so iptables module.
#

KVER	?= $(shell uname -r)
KDIR	?= /lib/modules/$(KVER)/build/
DEPMOD	= /sbin/depmod -a
CC	?= gcc
XFLAGS	?= $(shell pkg-config xtables --cflags 2>/dev/null)
XDIR	?= $(shell pkg-config --variable xtlibdir xtables)
VERSION	= $(shell git -C $M describe --dirty)
VOPT	= '-DVERSION="$(VERSION)"'
obj-m	= xt_so.o
CFLAGS_xt_so.o = -DDEBUG $(VOPT)

all: xt_so.ko libxt_so.so

xt_so.ko: xt_so.c xt_so.h
	make -C $(KDIR) M=$(CURDIR) modules CONFIG_DEBUG_INFO=y

install: install-mod install-lib

install-mod: xt_so.ko
	make -C $(KDIR) M=$(CURDIR) modules_install INSTALL_MOD_PATH=$(DESTDIR)

install-lib: libxt_so.so
	install -D $< $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/$<

test:
	./tests.sh test

%.so: %_sh.o
	gcc -shared -o $@ $<

%_sh.o: libxt_so.c xt_so.h
	gcc -O2 -Wall -Wunused -fPIC ${XFLAGS} ${CFLAGS} -o $@ -c $<

clean:
	-make -C $(KDIR) M=$(CURDIR) clean
	-rm -f *.so *.o modules.order

.PHONY: clean all install install-mod install-lib test
