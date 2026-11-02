# SPDX-License-Identifier: Apache-2.0
# secure-sudo-bootguard - built with the shared add-on logging + store helpers.
CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -Wformat -Werror=format-security
CPPFLAGS += -I../common
PREFIX   ?= /usr
BINDIR   ?= $(PREFIX)/bin
COMMON    = ../common/ssaddon_log.c ../common/ssaddon_store.c
HDRS      = ../common/ssaddon_log.h ../common/ssaddon_store.h
LDLIBS   := -lcrypto -lz
BIN       = secure-sudo-bootguard
SRC       = bootguard.c

all: $(BIN)

$(BIN): $(SRC) $(COMMON) $(HDRS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(SRC) $(COMMON) $(LDLIBS)

install: $(BIN)
	install -D -m0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

clean:
	rm -f $(BIN)

.PHONY: all install clean
