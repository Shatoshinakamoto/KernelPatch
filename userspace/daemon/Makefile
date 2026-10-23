# SPDX-License-Identifier: GPL-2.0
CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -Wformat -Werror=format-security
LDLIBS   ?= -lcrypto
PREFIX   ?= /usr
SBINDIR  ?= $(PREFIX)/sbin
LIBEXEC  ?= $(PREFIX)/libexec/secure-sudo
UNITDIR  ?= /lib/systemd/system

all: secure-sudod

secure-sudod: secure-sudod.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

install: secure-sudod
	install -D -m0755 secure-sudod $(DESTDIR)$(SBINDIR)/secure-sudod
	install -D -m0755 helpers/apply-net.sh  $(DESTDIR)$(LIBEXEC)/apply-net.sh
	install -D -m0755 helpers/quarantine.sh $(DESTDIR)$(LIBEXEC)/quarantine.sh
	install -D -m0644 secure-sudod.service  $(DESTDIR)$(UNITDIR)/secure-sudod.service

clean:
	rm -f secure-sudod

.PHONY: all install clean
