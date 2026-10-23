# SPDX-License-Identifier: GPL-2.0
#
# PAM modules for secure_sudo.
#
# SECDIR is the distro's PAM module directory and MUST be set correctly by the
# installer (it differs per family):
#   Debian/Ubuntu : /lib/x86_64-linux-gnu/security  (or $(libdir)/security)
#   Fedora/RHEL   : /usr/lib64/security
#   Arch          : /usr/lib/security
#   openSUSE      : /usr/lib64/security
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -Wformat -Werror=format-security
LDFLAGS ?= -shared
PAMLIBS ?= -lpam
SECDIR  ?= /lib/security

MODULES = pam_secure_sudo.so pam_secure_otp.so

all: $(MODULES)

pam_%.so: pam_%.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(PAMLIBS)

install: all
	install -D -m0644 pam_secure_sudo.so $(DESTDIR)$(SECDIR)/pam_secure_sudo.so
	install -D -m0644 pam_secure_otp.so  $(DESTDIR)$(SECDIR)/pam_secure_otp.so

clean:
	rm -f $(MODULES)

.PHONY: all install clean
