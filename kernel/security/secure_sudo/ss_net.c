// SPDX-License-Identifier: GPL-2.0
/*
 * ss_net.c - Protection #10 (kernel half): network-mode socket lockdown.
 *
 * The four network modes (monitor / host / lan-only / public-only) are mostly
 * a userspace job: the daemon detects the LAN/router subnets and writes one
 * nft table, which is far more robust than v2's in-kernel Netfilter hook (that
 * used the long-removed nf_register_hook() API and, worse, took a mutex and
 * wrote a log file from softirq context on every packet - an instant crash).
 *
 * What stays in the kernel is the one thing nft cannot do: in HOST mode, deny
 * the creation of packet/raw sockets outright, so pcap-style sniffing fails
 * even if libpcap and tcpdump are installed. This is a deliberate attack-
 * surface cut for a locked-down host, so it applies to everyone (raw sockets
 * are a root capability anyway); kernel-internal sockets are untouched.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/capability.h>
#include <linux/string.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

#ifdef CONFIG_SECURITY_NETWORK
static int ss_socket_create(int family, int type, int protocol, int kern)
{
	if (kern)
		return 0;	/* kernel-internal socket */
	if (READ_ONCE(ss_cfg.net_mode) != SS_NET_HOST)
		return 0;

	if (family == AF_PACKET || type == SOCK_RAW) {
		pr_warn_ratelimited("host mode: denied raw/packet socket (family=%d type=%d)\n",
				    family, type);
		return -EPERM;
	}
	return 0;
}

static struct security_hook_list ss_net_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(socket_create, ss_socket_create),
};

void __init ss_net_init(void)
{
	security_add_hooks(ss_net_hooks, ARRAY_SIZE(ss_net_hooks), &ss_lsmid);
}
#else
void __init ss_net_init(void)
{
	pr_warn("CONFIG_SECURITY_NETWORK off: host-mode socket block unavailable\n");
}
#endif /* CONFIG_SECURITY_NETWORK */

/* ---------------------------- sysfs knob --------------------------------- */

static const char *const net_mode_names[] = {
	[SS_NET_MONITOR]     = "monitor",
	[SS_NET_HOST]        = "host",
	[SS_NET_LAN_ONLY]    = "lan-only",
	[SS_NET_PUBLIC_ONLY] = "public-only",
};

static ssize_t net_mode_show(struct kobject *k, struct kobj_attribute *a,
			     char *buf)
{
	enum ss_net_mode m = READ_ONCE(ss_cfg.net_mode);

	return sysfs_emit(buf, "%s\n", net_mode_names[m]);
}

static ssize_t net_mode_store(struct kobject *k, struct kobj_attribute *a,
			      const char *buf, size_t count)
{
	unsigned int i;

	if (!ss_may_admin(NULL))
		return -EPERM;
	if (ss_locked())
		return -EPERM;

	for (i = 0; i <= SS_NET_MODE_MAX; i++) {
		if (sysfs_streq(buf, net_mode_names[i])) {
			WRITE_ONCE(ss_cfg.net_mode, i);
			return count;
		}
	}
	return -EINVAL;
}

static struct kobj_attribute net_mode_attr =
	__ATTR(net_mode, 0600, net_mode_show, net_mode_store);

static struct attribute *ss_net_attrs[] = {
	&net_mode_attr.attr,
	NULL,
};
static const struct attribute_group ss_net_group = {
	.attrs = ss_net_attrs,
};

int ss_net_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_net_group);
}
