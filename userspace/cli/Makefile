# SPDX-License-Identifier: GPL-2.0
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wformat -Werror=format-security
PREFIX  ?= /usr
BINDIR  ?= $(PREFIX)/bin

all: secure-sudo

secure-sudo: secure-sudo.c
	$(CC) $(CFLAGS) -o $@ $<

install: secure-sudo
	install -D -m0755 secure-sudo $(DESTDIR)$(BINDIR)/secure-sudo

clean:
	rm -f secure-sudo

.PHONY: all install clean
