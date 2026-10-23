# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the secure_sudo LSM.
#
# Built into the kernel (not a module): LSM credential hooks are only
# available to built-in security modules.

obj-$(CONFIG_SECURITY_SECURE_SUDO) += secure_sudo.o

secure_sudo-y := ss_core.o \
		 ss_creds.o \
		 ss_exec.o \
		 ss_firmware.o \
		 ss_tpm.o \
		 ss_ram.o \
		 ss_tmpexec.o \
		 ss_net.o \
		 ss_log.o \
		 ss_node.o \
		 ss_cooldown.o \
		 ss_driver.o \
		 ss_timevault.o \
		 ss_home.o \
		 ss_binvault.o \
		 ss_radio.o
