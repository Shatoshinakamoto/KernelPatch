# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# secure-sudo-attest (TODO P2-1): TPM quote of the boot chain for remote
# attestation, plus the host report helper and the off-box verifier.
# Needs tpm2-tss (libtss2-esys, -tctildr, -mu, -rc) and OpenSSL.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wformat -Werror=format-security
PREFIX  ?= /usr
BINDIR  ?= $(PREFIX)/bin
LIBEXEC ?= $(PREFIX)/libexec/secure-sudo
LDLIBS  := -ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-rc -lcrypto

all: secure-sudo-attest

secure-sudo-attest: attest.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

install: secure-sudo-attest
	install -D -m0755 secure-sudo-attest $(DESTDIR)$(LIBEXEC)/secure-sudo-attest
	install -D -m0755 attest-report.sh $(DESTDIR)$(LIBEXEC)/attest-report.sh
	install -D -m0755 secure-sudo-attest-verify $(DESTDIR)$(BINDIR)/secure-sudo-attest-verify

clean:
	rm -f secure-sudo-attest

.PHONY: all install clean
