# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# secure-sudo-pheonixbox - PheonixBox (#21): snapshot-based runtime tamper
# protection with automatic repair.
#
# Needs OpenSSL (SHA-256, -lcrypto) for the integrity manifest and zlib
# (-lz) for the compressed snapshot store. POSIX ACL capture/restore is done
# at runtime via getfacl/setfacl if present, so there is no libacl link
# dependency here.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wformat -Werror=format-security
PREFIX  ?= /usr
BINDIR  ?= $(PREFIX)/bin
LDLIBS  := -lcrypto -lz

all: secure-sudo-pheonixbox

secure-sudo-pheonixbox: pheonixbox.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

install: secure-sudo-pheonixbox
	install -D -m0755 secure-sudo-pheonixbox $(DESTDIR)$(BINDIR)/secure-sudo-pheonixbox

clean:
	rm -f secure-sudo-pheonixbox

.PHONY: all install clean
