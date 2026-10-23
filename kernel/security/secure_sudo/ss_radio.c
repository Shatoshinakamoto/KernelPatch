// SPDX-License-Identifier: GPL-2.0
/*
 * ss_radio.c - Protection #19: RadioGuard (Wi-Fi / Bluetooth lockdown,
 * "Ethernet-only" mode).
 *
 * ============================ WHAT IT DOES ===============================
 * RadioGuard lets an operator turn the machine's wireless radios off and keep
 * them off, so a box can be constrained to wired Ethernet only. Wireless
 * interfaces are a large, remote attack surface (rogue APs, BlueBorne-class
 * Bluetooth bugs, Wi-Fi driver memory-corruption CVEs) and on a fixed-location
 * appliance they are usually pure liability. There are three knobs:
 *
 *   block_wifi       1 = keep Wi-Fi off
 *   block_bluetooth  1 = keep Bluetooth off
 *   ethernet_only    1 = keep BOTH off (a single master switch; it does not
 *                        need the two individual knobs set as well)
 *
 * The effective state is the OR of the specific knob and the master switch:
 *      Wi-Fi is blocked      when block_wifi      OR ethernet_only
 *      Bluetooth is blocked  when block_bluetooth OR ethernet_only
 * so `ethernet_only=1` alone is enough to lock the box to wired networking,
 * and clearing it falls back to whatever the two specific knobs say.
 *
 * All three are normal secure_sudo knobs: root-only (0600), refused once the
 * #16 config lock latches, and pushed in at boot by `secure-sudo load`. The
 * friendly CLI wrapper is `secure-sudo radio <wifi|bluetooth|ethernet-only>
 * <on|off>` (see the CLI); `secure-sudo set block_wifi 1` works too.
 *
 * ========================= HOW IT ENFORCES (3 LAYERS) ====================
 * A config flag by itself is not enforcement - something has to make the
 * radios actually unusable and keep them that way. We do it in the kernel, in
 * three independent layers, exactly because any single layer can be sidestepped
 * on some hardware:
 *
 *  LAYER 1 - block the driver stack from loading (kernel_read_file /
 *            READING_MODULE). Every Wi-Fi driver depends on the core module
 *            `cfg80211` (and usually `mac80211`); every Bluetooth driver
 *            depends on the core module `bluetooth`. If the core module is
 *            refused, no dependent driver can initialise - modprobe loads
 *            dependencies first, so denying the core denies the whole stack.
 *            We match the loaded module's file basename against a small core
 *            list (plus a few common transport modules for robustness).
 *
 *  LAYER 2 - deny AF_BLUETOOTH sockets (socket_create). Even if a Bluetooth
 *            stack were somehow already live, no process can open an L2CAP /
 *            RFCOMM / HCI socket to use it. (Wi-Fi has no dedicated socket
 *            family - it rides ordinary AF_INET/AF_PACKET on the wireless
 *            netdev - so this layer is Bluetooth-specific; Wi-Fi is covered by
 *            layers 1 and 3.)
 *
 *  LAYER 3 - deny writes to /dev/rfkill (file_open, FMODE_WRITE). rfkill is the
 *            subsystem that soft-blocks/unblocks radios; denying writes to it
 *            means a blocked radio cannot be un-blocked from userspace while
 *            the guard is on. (Reads are left alone so `rfkill list` still
 *            works for diagnostics.)
 *
 * ========================= HONEST LIMITATIONS ===========================
 * (Documented, not hidden; see docs/SECURITY_REVIEW.md #16.)
 *   - If the Wi-Fi/Bluetooth drivers are compiled *into* the kernel rather than
 *     built as modules, layer 1 has nothing to intercept. On such a build the
 *     real guarantees are layer 3 (rfkill) plus simply not compiling those
 *     drivers in; RadioGuard then prevents re-enabling, not the initial
 *     presence. An Ethernet-only appliance should build without wireless
 *     drivers and use RadioGuard as belt-and-braces.
 *   - Turning a knob on does NOT tear down a radio that is *already* live this
 *     boot (the module is already resident). Because `secure-sudo load` runs in
 *     the daemon's ExecStartPre at early boot, the module load is denied from
 *     the start on a configured box; to clamp a radio that is already up on a
 *     running box, `rfkill block` it (or reboot) after setting the knob.
 *   - init_module(2) with a raw buffer carries no filename, so layer 1 matches
 *     only finit_module(2) (what modprobe actually uses). The #16 lock's
 *     `lock_modules` blocks *all* module loads and is the backstop for a truly
 *     locked appliance.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/err.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/kernel_read_file.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/lsm_hooks.h>

#include "secure_sudo.h"

/* Effective state: a specific knob OR the ethernet_only master switch. */
static inline bool wifi_blocked(void)
{
	return READ_ONCE(ss_cfg.block_wifi) || READ_ONCE(ss_cfg.ethernet_only);
}
static inline bool bt_blocked(void)
{
	return READ_ONCE(ss_cfg.block_bluetooth) || READ_ONCE(ss_cfg.ethernet_only);
}

/*
 * Core module names whose load we refuse. A driver cannot run without its core
 * stack, so this short list disables the whole of Wi-Fi / Bluetooth without
 * having to enumerate every chipset driver. Compared without the ".ko"
 * suffix; '-' and '_' are both spelled '_' here because module names normalise
 * dashes to underscores.
 */
static const char *const wifi_modules[] = {
	"cfg80211", "mac80211", "mac80211_hwsim",
};
static const char *const bt_modules[] = {
	"bluetooth", "btusb", "btrtl", "btintel", "btbcm", "btmtk",
	"hci_uart", "btqca", "hci_vhci",
};

/* Does @name (a module basename, maybe with ".ko") match one of @list? */
static bool name_in(const char *name, const char *const *list, size_t n)
{
	char norm[64];
	size_t i, j;

	/* Copy without any ".ko"/".ko.zst" suffix, normalising '-' to '_'. */
	for (i = 0; i < sizeof(norm) - 1 && name[i] && name[i] != '.'; i++)
		norm[i] = (name[i] == '-') ? '_' : name[i];
	norm[i] = '\0';

	for (j = 0; j < n; j++)
		if (!strcmp(norm, list[j]))
			return true;
	return false;
}

/* --------- LAYER 1: refuse loading the wireless/Bluetooth stack ---------- */
static int ss_radio_read_file(struct file *file, enum kernel_read_file_id id,
			      bool contents)
{
	char *buf;
	const char *base;
	int ret = 0;

	if (id != READING_MODULE)		/* only care about module loads */
		return 0;
	if (!wifi_blocked() && !bt_blocked())
		return 0;			/* nothing to guard */

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return 0;	/* don't fail an unrelated module load on OOM */

	base = ss_file_path(&file->f_path, buf, PATH_MAX);
	if (IS_ERR(base)) {
		kfree(buf);
		return 0;
	}
	base = kbasename(base);

	if (wifi_blocked() && name_in(base, wifi_modules, ARRAY_SIZE(wifi_modules))) {
		pr_warn("radio: refused Wi-Fi module load: %s\n", base);
		ss_event("radio: refused Wi-Fi module %s", base);
		ret = -EPERM;
	} else if (bt_blocked() && name_in(base, bt_modules, ARRAY_SIZE(bt_modules))) {
		pr_warn("radio: refused Bluetooth module load: %s\n", base);
		ss_event("radio: refused Bluetooth module %s", base);
		ret = -EPERM;
	}
	kfree(buf);
	return ret;
}

/* ------------- LAYER 2: deny AF_BLUETOOTH sockets when BT off ------------ */
#ifdef CONFIG_SECURITY_NETWORK
static int ss_radio_socket_create(int family, int type, int protocol, int kern)
{
	if (kern)			/* kernel-internal socket: leave alone */
		return 0;
	if (family == AF_BLUETOOTH && bt_blocked()) {
		pr_warn_ratelimited("radio: denied AF_BLUETOOTH socket\n");
		ss_event("radio: denied AF_BLUETOOTH socket");
		return -EPERM;
	}
	return 0;
}
#endif

/* --------------- LAYER 3: deny writes to /dev/rfkill --------------------- */
static int ss_radio_file_open(struct file *file)
{
	char *buf, *p;
	int ret = 0;

	if (!(file->f_mode & FMODE_WRITE))
		return 0;			/* reads (rfkill list) are fine */
	if (!wifi_blocked() && !bt_blocked())
		return 0;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return 0;
	p = ss_file_path(&file->f_path, buf, PATH_MAX);
	if (!IS_ERR(p) && !strcmp(p, "/dev/rfkill")) {
		pr_warn_ratelimited("radio: denied write to /dev/rfkill (radios are locked off)\n");
		ss_event("radio: denied /dev/rfkill write");
		ret = -EPERM;
	}
	kfree(buf);
	return ret;
}

static struct security_hook_list ss_radio_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(kernel_read_file, ss_radio_read_file),
	LSM_HOOK_INIT(file_open,        ss_radio_file_open),
#ifdef CONFIG_SECURITY_NETWORK
	LSM_HOOK_INIT(socket_create,    ss_radio_socket_create),
#endif
};

void __init ss_radio_init(void)
{
	security_add_hooks(ss_radio_hooks, ARRAY_SIZE(ss_radio_hooks), &ss_lsmid);
}

/* ---------------------------- sysfs knobs -------------------------------- */
/*
 * Three boolean knobs, each root-only (ss_may_admin), refused once locked
 * (ss_locked), 0600. Identical plumbing to every other secure_sudo toggle, so
 * `secure-sudo get/set/load/status` and the generic config path all work; the
 * `radio` subcommand is just a friendlier spelling on top.
 */
#define RADIO_BOOL(field)						\
static ssize_t field##_show(struct kobject *k, struct kobj_attribute *a,\
			    char *buf)					\
{									\
	return sysfs_emit(buf, "%d\n", READ_ONCE(ss_cfg.field));		\
}									\
static ssize_t field##_store(struct kobject *k, struct kobj_attribute *a,\
			     const char *buf, size_t count)		\
{									\
	bool v;								\
	if (!ss_may_admin(NULL))					\
		return -EPERM;						\
	if (ss_locked())						\
		return -EPERM;						\
	if (kstrtobool(buf, &v))					\
		return -EINVAL;						\
	WRITE_ONCE(ss_cfg.field, v);					\
	return count;							\
}									\
static struct kobj_attribute field##_attr =				\
	__ATTR(field, 0600, field##_show, field##_store)

RADIO_BOOL(block_wifi);
RADIO_BOOL(block_bluetooth);
RADIO_BOOL(ethernet_only);

static struct attribute *ss_radio_attrs[] = {
	&block_wifi_attr.attr,
	&block_bluetooth_attr.attr,
	&ethernet_only_attr.attr,
	NULL,
};
static const struct attribute_group ss_radio_group = {
	.attrs = ss_radio_attrs,
};

int ss_radio_sysfs(struct kobject *kobj)
{
	return sysfs_create_group(kobj, &ss_radio_group);
}
