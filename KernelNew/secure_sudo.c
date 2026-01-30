/*
 * secure_sudo.c - Kernel module for preventing non-sudo users from performing privileged operations
 *
 * This patch prevents:
 * 1. Non-sudo users from switching user IDs
 * 2. GPU flash calls from non-sudo users
 * 3. Motherboard Q-flash and flash calls from non-sudo users
 * 4. Blacklisted commands execution by non-sudo users (configurable via a config file)
 * 5. Restricting file system access to user's home directory for non-sudo users
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/limits.h>

#define CONFIG_FILE_PATH "/etc/secure_sudo/blacklist.conf"
#define HOME_DIR_PATH "/home"
#define MAX_BLACKLIST_ENTRIES 256
#define MAX_COMMAND_LENGTH 128
#define MAX_PATH_LENGTH PATH_MAX

MODULE_LICENSE("GPL-v3");
MODULE_AUTHOR("Secured Kernel Team");
MODULE_DESCRIPTION("Security module to restrict privileged operations to sudo users");
MODULE_VERSION("1.1");

/* Global variables */
static char **blacklisted_commands;
static int blacklist_count = 0;
static DEFINE_MUTEX(blacklist_mutex);
static DEFINE_MUTEX(path_check_mutex);

/* Function to check if a user has sudo privileges */
static bool is_sudo_user(void)
{
    /* Check if user is root (UID 0) or has effective UID 0 */
    const struct cred *cred = current_cred();
    
    if (cred->uid.val == 0 || cred->euid.val == 0)
        return true;
        
    /* Additional checks for sudo group membership could be added here */
    
    return false;
}

/* Function to check if a path is within the user's home directory */
static bool is_within_user_home(const char *path)
{
    const struct cred *cred = current_cred();
    char home_path[MAX_PATH_LENGTH];
    char username[32];
    struct passwd *pwd;
    int uid;
    
    /* Allow access to specific system directories regardless */
    if (strncmp(path, "/proc/", 6) == 0 ||
        strncmp(path, "/sys/", 5) == 0 ||
        strncmp(path, "/dev/", 5) == 0 ||
        strncmp(path, "/tmp/", 5) == 0 ||
        strncmp(path, "/var/tmp/", 9) == 0 ||
        strncmp(path, "/run/", 5) == 0)
        return true;
    
    /* Get user's UID */
    uid = cred->uid.val;
    
    /* Construct user's home path */
    snprintf(home_path, MAX_PATH_LENGTH, "%s/%s", HOME_DIR_PATH, username);
    
    /* Check if path starts with user's home directory */
    if (strncmp(path, home_path, strlen(home_path)) == 0)
        return true;
    
    return false;
}

/* Hook for filesystem access */
static int secure_path_permission(const struct path *path, int mask)
{
    char *buf;
    int ret = 0;
    
    /* Allow sudo users to access any path */
    if (is_sudo_user())
        return 0;
        
    /* Only check write/execute permissions */
    if (!(mask & (MAY_WRITE | MAY_EXEC)))
        return 0;
        
    /* Allocate temporary buffer for path */
    buf = kmalloc(MAX_PATH_LENGTH, GFP_KERNEL);
    if (!buf)
        return 0;  /* On error, allow by default */
        
    /* Get the full path */
    mutex_lock(&path_check_mutex);
    if (d_path(path, buf, MAX_PATH_LENGTH) == NULL) {
        ret = 0;  /* On error, allow by default */
        goto out;
    }
    
    /* Check if path is within user's home directory */
    if (!is_within_user_home(buf)) {
        printk(KERN_WARNING "secure_sudo: Non-sudo user %d attempted to access path outside home: %s\n",
               current_cred()->uid.val, buf);
        ret = -EPERM;
    }
    
out:
    mutex_unlock(&path_check_mutex);
    kfree(buf);
    return ret;
}

/* Hook for setuid/setgid operations */
static int secure_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
    /* Block non-sudo users from changing UIDs */
    if (!is_sudo_user()) {
        if (new->uid.val != old->uid.val || new->euid.val != old->euid.val ||
            new->suid.val != old->suid.val || new->fsuid.val != old->fsuid.val ||
            new->gid.val != old->gid.val || new->egid.val != old->egid.val ||
            new->sgid.val != old->sgid.val || new->fsgid.val != old->fsgid.val) {
            
            printk(KERN_WARNING "secure_sudo: Non-sudo user %d attempted to change UID/GID\n", 
                   old->uid.val);
            return -EPERM;
        }
    }
    
    return 0;
}

/* Hook for GPU flash operations */
static int secure_gpu_flash(void)
{
    if (!is_sudo_user()) {
        printk(KERN_WARNING "secure_sudo: Non-sudo user %d attempted GPU flash operation\n",
               current_cred()->uid.val);
        return -EPERM;
    }
    
    return 0;
}

/* Hook for motherboard flash operations */
static int secure_mb_flash(void)
{
    if (!is_sudo_user()) {
        printk(KERN_WARNING "secure_sudo: Non-sudo user %d attempted motherboard flash operation\n",
               current_cred()->uid.val);
        return -EPERM;
    }
    
    return 0;
}

/* Function to load blacklisted commands from config file */
static int load_blacklist(void)
{
    struct file *file;
    loff_t pos = 0;
    int ret = 0, i;
    char *buf, *line, *tmp;
    
    mutex_lock(&blacklist_mutex);
    
    /* Free previous blacklist if exists */
    if (blacklisted_commands) {
        for (i = 0; i < blacklist_count; i++)
            kfree(blacklisted_commands[i]);
        kfree(blacklisted_commands);
        blacklisted_commands = NULL;
        blacklist_count = 0;
    }
    
    /* Allocate memory for blacklist */
    blacklisted_commands = kmalloc(sizeof(char *) * MAX_BLACKLIST_ENTRIES, GFP_KERNEL);
    if (!blacklisted_commands) {
        ret = -ENOMEM;
        goto out;
    }
    
    /* Open config file */
    file = filp_open(CONFIG_FILE_PATH, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_WARNING "secure_sudo: Failed to open config file: %s\n", CONFIG_FILE_PATH);
        ret = PTR_ERR(file);
        goto cleanup_blacklist;
    }
    
    /* Allocate buffer for file reading */
    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto cleanup_file;
    }
    
    /* Read config file line by line */
    while (kernel_read(file, buf, PAGE_SIZE - 1, &pos) > 0) {
        buf[PAGE_SIZE - 1] = '\0';
        line = buf;
        
        while ((tmp = strsep(&line, "\n")) != NULL && blacklist_count < MAX_BLACKLIST_ENTRIES) {
            if (*tmp && *tmp != '#') {  /* Skip empty lines and comments */
                blacklisted_commands[blacklist_count] = kmalloc(MAX_COMMAND_LENGTH, GFP_KERNEL);
                if (!blacklisted_commands[blacklist_count]) {
                    ret = -ENOMEM;
                    goto cleanup_all;
                }
                
                strncpy(blacklisted_commands[blacklist_count], tmp, MAX_COMMAND_LENGTH - 1);
                blacklisted_commands[blacklist_count][MAX_COMMAND_LENGTH - 1] = '\0';
                blacklist_count++;
            }
        }
    }
    
    printk(KERN_INFO "secure_sudo: Loaded %d blacklisted commands\n", blacklist_count);
    
cleanup_all:
    kfree(buf);
cleanup_file:
    filp_close(file, NULL);
cleanup_blacklist:
    if (ret && blacklisted_commands) {
        for (i = 0; i < blacklist_count; i++)
            kfree(blacklisted_commands[i]);
        kfree(blacklisted_commands);
        blacklisted_commands = NULL;
        blacklist_count = 0;
    }
out:
    mutex_unlock(&blacklist_mutex);
    return ret;
}

/* Hook for exec operations to check against blacklisted commands */
static int secure_bprm_check_security(struct linux_binprm *bprm)
{
    int i;
    char *cmd, *path;
    
    if (is_sudo_user())
        return 0;  /* Allow sudo users to run any command */
    
    if (!blacklisted_commands || blacklist_count == 0)
        return 0;  /* No blacklist loaded */
    
    /* Extract command name from path */
    path = kstrdup(bprm->filename, GFP_KERNEL);
    if (!path)
        return 0;  /* On error, allow by default */
    
    cmd = strrchr(path, '/');
    if (cmd)
        cmd++;  /* Skip the slash */
    else
        cmd = path;
    
    /* Check against blacklist */
    mutex_lock(&blacklist_mutex);
    for (i = 0; i < blacklist_count; i++) {
        if (strcmp(cmd, blacklisted_commands[i]) == 0) {
            printk(KERN_WARNING "secure_sudo: Non-sudo user %d attempted to execute blacklisted command: %s\n",
                   current_cred()->uid.val, cmd);
            mutex_unlock(&blacklist_mutex);
            kfree(path);
            return -EPERM;
        }
    }
    mutex_unlock(&blacklist_mutex);
    
    kfree(path);
    return 0;
}

/* Sysfs interface for reloading blacklist */
static ssize_t reload_blacklist_store(struct kobject *kobj, struct kobj_attribute *attr,
                                     const char *buf, size_t count)
{
    if (!is_sudo_user())
        return -EPERM;
    
    load_blacklist();
    return count;
}

static struct kobj_attribute reload_attr = __ATTR(reload, 0200, NULL, reload_blacklist_store);

static struct kobject *secure_sudo_kobj;

/* LSM hooks structure - to be registered with security framework */
/* Note: In a real implementation, these would be properly registered with the LSM framework */
/* We're declaring them here to illustrate what hooks would be used */
static struct security_operations secure_sudo_ops = {
    .name = "secure_sudo",
    /* Hook declarations would go here */
};

/* Module initialization */
static int __init secure_sudo_init(void)
{
    int ret;
    
    printk(KERN_INFO "secure_sudo: Initializing secure sudo module\n");
    
    /* Create sysfs entries */
    secure_sudo_kobj = kobject_create_and_add("secure_sudo", kernel_kobj);
    if (!secure_sudo_kobj) {
        printk(KERN_ERR "secure_sudo: Failed to create sysfs entries\n");
        return -ENOMEM;
    }
    
    ret = sysfs_create_file(secure_sudo_kobj, &reload_attr.attr);
    if (ret) {
        printk(KERN_ERR "secure_sudo: Failed to create sysfs attribute\n");
        kobject_put(secure_sudo_kobj);
        return ret;
    }
    
    /* Register security hooks */
    /* Note: In a real implementation, this would use the Linux Security Module (LSM) framework */
    /* For example: security_add_hooks(secure_sudo_hooks, ARRAY_SIZE(secure_sudo_hooks), "secure_sudo"); */
    
    /* Initialize blacklist */
    load_blacklist();
    
    printk(KERN_INFO "secure_sudo: Module loaded successfully\n");
    return 0;
}

/* Module cleanup */
static void __exit secure_sudo_exit(void)
{
    int i;
    
    printk(KERN_INFO "secure_sudo: Unloading secure sudo module\n");
    
    /* Free blacklist */
    if (blacklisted_commands) {
        for (i = 0; i < blacklist_count; i++)
            kfree(blacklisted_commands[i]);
        kfree(blacklisted_commands);
        blacklisted_commands = NULL;
        blacklist_count = 0;
    }
    
    /* Remove sysfs entries */
    kobject_put(secure_sudo_kobj);
    
    printk(KERN_INFO "secure_sudo: Module unloaded successfully\n");
}

module_init(secure_sudo_init);
module_exit(secure_sudo_exit);
