# SPDX-License-Identifier: GPL-2.0
# secure-sudo-addon-failure - reports a failed add-on unit through the shared logging.
CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -Wformat -Werror=format-security
CPPFLAGS += -I../common
PREFIX   ?= /usr
BINDIR   ?= $(PREFIX)/libexec/secure-sudo
COMMON    = ../common/ssaddon_log.c ../common/ssaddon_conf.c
HDRS      = ../common/ssaddon_log.h ../common/ssaddon_conf.h
LDLIBS   :=
BIN       = secure-sudo-addon-failure
SRC       = failure.c

all: $(BIN)

$(BIN): $(SRC) $(COMMON) $(HDRS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(SRC) $(COMMON) $(LDLIBS)

install: $(BIN)
	install -D -m0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

clean:
	rm -f $(BIN)

.PHONY: all install clean
