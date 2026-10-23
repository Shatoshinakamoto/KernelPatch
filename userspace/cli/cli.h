/* SPDX-License-Identifier: GPL-2.0 */
/* cli.h - shared bits of the secure-sudo CLI (secure-sudo.c + subcommands). */
#ifndef SECURE_SUDO_CLI_H
#define SECURE_SUDO_CLI_H

#include <stddef.h>

#define SYSFS  "/sys/kernel/secure_sudo"
#define SECFS  "/sys/kernel/security/secure_sudo"
#define CONFIG_DIR "/etc/secure_sudo"

/* Write @len bytes to a kernel file in one write(); 0 on success. */
int write_file(const char *path, const char *data, size_t len);

/* vault_allow.c */
int  cmd_vault_allow(int argc, char **argv);
void vault_allow_usage(void);

/* detect_admins.c */
int cmd_detect_admins(int argc, char **argv);

#endif
