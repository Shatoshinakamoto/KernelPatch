# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
# secure-sudo-locus - built with the shared add-on logging + store helpers.
CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -Wformat -Werror=format-security
CPPFLAGS += -I../common
PREFIX   ?= /usr
BINDIR   ?= $(PREFIX)/bin
COMMON    = ../common/ssaddon_log.c ../common/ssaddon_tls.c ../common/ssaddon_store.c ../common/ssaddon_conf.c ../common/ssaddon_trust.c
HDRS      = ../common/ssaddon_log.h ../common/ssaddon_tls.h ../common/ssaddon_store.h ../common/ssaddon_conf.h ../common/ssaddon_trust.h
LDLIBS   := -lssl -lcrypto -lz
BIN       = secure-sudo-locus
SRC       = locus.c

all: $(BIN)

$(BIN): $(SRC) $(COMMON) $(HDRS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(SRC) $(COMMON) $(LDLIBS)

install: $(BIN)
	install -D -m0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

clean:
	rm -f $(BIN)

.PHONY: all install clean
