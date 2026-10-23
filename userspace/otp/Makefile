# SPDX-License-Identifier: GPL-2.0
#
# secure-sudo-otp - OTP helper.
#
# QR output needs libqrencode + zlib. If QR_SUPPORT=1 (the default; the
# installer ensures libqrencode-dev is present), show-qr renders a local PNG.
# Without it the binary still builds and every other subcommand works; show-qr
# just tells the user to use show-key instead.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wformat -Werror=format-security
PREFIX  ?= /usr
BINDIR  ?= $(PREFIX)/bin
LDLIBS  := -lcrypto -lcrypt

QR_SUPPORT ?= 1
ifeq ($(QR_SUPPORT),1)
CFLAGS += -DHAVE_QRENCODE
LDLIBS += -lqrencode -lz
endif

all: secure-sudo-otp

secure-sudo-otp: secure-sudo-otp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

install: secure-sudo-otp
	install -D -m0755 secure-sudo-otp $(DESTDIR)$(BINDIR)/secure-sudo-otp

clean:
	rm -f secure-sudo-otp

.PHONY: all install clean
