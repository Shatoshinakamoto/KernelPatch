# SPDX-License-Identifier: Apache-2.0
# secure-sudo-gui - a pure Python 3 stdlib service; nothing to compile.
#
# The server reads index.html from its own directory, so the script and the
# page are installed together into SHAREDIR, and a tiny wrapper on PATH execs
# the real script (a bare symlink would move __file__ off SHAREDIR).
PREFIX   ?= /usr
BINDIR   ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/secure-sudo-gui

all:
	@python3 -c 'import ast,sys; ast.parse(open("secure-sudo-gui").read()); print("secure-sudo-gui: syntax OK")'

install:
	install -d -m0755 $(DESTDIR)$(SHAREDIR)
	install -m0755 secure-sudo-gui $(DESTDIR)$(SHAREDIR)/secure-sudo-gui
	install -m0644 index.html      $(DESTDIR)$(SHAREDIR)/index.html
	install -d -m0755 $(DESTDIR)$(BINDIR)
	printf '#!/bin/sh\nexec %s/secure-sudo-gui "$$@"\n' '$(SHAREDIR)' \
		> $(DESTDIR)$(BINDIR)/secure-sudo-gui
	chmod 0755 $(DESTDIR)$(BINDIR)/secure-sudo-gui

clean:
	@:
.PHONY: all install clean
