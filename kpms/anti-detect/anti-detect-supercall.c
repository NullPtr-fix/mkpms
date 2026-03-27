/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * anti-detect-supercall: Require superkey for ALL KernelPatch supercall commands
 *
 * KP's supercall handler (syscall 45) allows HELLO/VER/KLOG etc. without
 * superkey verification — any "su"-auth'd app can probe KP presence.
 *
 * This module adds a guard in the hook chain (runs after KP's handler).
 * If KP processed the call but the key isn't the superkey, we override
 * the result with -ENOENT to mimic truncate(2) failure.
 *
 * Usage: load module with superkey as argument
 *   kpatch kpm load anti-detect.kpm "superkey"
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <syscall.h>
#include <kputils.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/scdefs.h>

#define MAX_KEY_LEN 128

static long stored_key_hash;
static int hook_installed;

/*
 * Before handler — runs AFTER KP's before() in the chain.
 * If KP handled a supercall (skip_origin=1) and the caller's key
 * doesn't match our stored superkey hash, override result.
 */
static void supercall_guard_before(hook_fargs8_t *args, void *udata)
{
    long ver_xx_cmd = (long)syscall_argn(args, 1);
    long cmd = ver_xx_cmd & 0xFFFF;

    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX)
        return;

    /* Only intercept calls that KP already processed */
    if (!args->skip_origin)
        return;

    const char __user *ukey = (const char __user *)syscall_argn(args, 0);
    char key[MAX_KEY_LEN];
    long len = compat_strncpy_from_user(key, ukey, sizeof(key));
    if (len <= 0 || hash_key(key) != stored_key_hash)
        args->ret = -ENOENT;
}

/*
 * [用途] 初始化 supercall 防护：未携带正确 superkey 的调用统一伪装为 -ENOENT。
 * [输入] superkey: 从模块加载参数传入。
 * [输出] 0 成功，-1 失败。
 */
int supercall_guard_init(const char *superkey)
{
    if (!superkey || !superkey[0]) {
        pr_info("anti-detect: no superkey provided, supercall guard disabled\n");
        return 0;
    }

    stored_key_hash = hash_key(superkey);

    hook_err_t err = hook_syscalln(__NR_supercall, 6, supercall_guard_before, 0, 0);
    if (err) {
        pr_err("anti-detect: hook supercall failed: %d\n", err);
        return -1;
    }

    hook_installed = 1;
    pr_info("anti-detect: supercall guard installed\n");
    return 0;
}

/* [用途] 退出防护模块，移除 supercall hook。 */
void supercall_guard_exit(void)
{
    if (hook_installed) {
        unhook_syscalln(__NR_supercall, supercall_guard_before, 0);
        hook_installed = 0;
        pr_info("anti-detect: supercall guard removed\n");
    }
}
