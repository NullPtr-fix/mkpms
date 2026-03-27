/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef KPM_DEMO_HELPERS_H
#define KPM_DEMO_HELPERS_H

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>

#ifndef KPM_MODULE_INFO
#define KPM_MODULE_INFO(name, version, license, author, description) \
    KPM_NAME(name);                                                  \
    KPM_VERSION(version);                                            \
    KPM_LICENSE(license);                                            \
    KPM_AUTHOR(author);                                              \
    KPM_DESCRIPTION(description)
#endif

/*
 * [用途] 将内核态字符串复制到用户态缓冲。
 * [输入] msg: 源字符串；out_msg/outlen: 用户态目标缓冲。
 * [输出] compat_copy_to_user 返回值（成功时一般为 0）。
 * [实现] 先做空指针/长度检查，再截断到 outlen-1，保证以 '\0' 结尾复制。
 */
static inline long kpm_demo_copy_message(const char *msg, char *__user out_msg,
                                         int outlen)
{
    int len;

    if (!out_msg || outlen <= 0)
        return 0;

    len = strlen(msg ? msg : "");
    if (len < 0)
        return len;

    if (len >= outlen)
        len = outlen - 1;

    return compat_copy_to_user(out_msg, msg ? msg : "", len + 1);
}

/*
 * [用途] 统一 demo 初始化日志。
 * [输入] name/event/args: 模块名、触发事件、加载参数。
 * [输出] 固定返回 0，便于直接作为 KPM_INIT 返回值。
 */
static inline long kpm_demo_log_init(const char *name, const char *event,
                                     const char *args)
{
    pr_info("%s init, event: %s, args: %s\n",
            name ? name : "kpm-demo",
            event ? event : "(null)",
            args ? args : "(null)");
    return 0;
}

/* [用途] 统一 demo 退出日志。 */
static inline long kpm_demo_log_exit(const char *name)
{
    pr_info("%s exit\n", name ? name : "kpm-demo");
    return 0;
}

/*
 * [用途] 处理 control 接口：打印“模块 + 参数”并把同样信息回传到用户态。
 * [实现] 先 snprintf 到内核栈缓冲，再走 kpm_demo_copy_message。
 */
static inline long kpm_demo_echo_control(const char *name, const char *args,
                                         char *__user out_msg, int outlen)
{
    char buf[256];

    snprintf(buf, sizeof(buf), "%s control args: %s",
             name ? name : "kpm-demo",
             args ? args : "");
    pr_info("%s\n", buf);
    return kpm_demo_copy_message(buf, out_msg, outlen);
}

/*
 * [用途] 处理 control 接口：仅记录日志，回传原始 args。
 * [差异] 与 kpm_demo_echo_control 的区别是回传内容更“原始”。
 */
static inline long kpm_demo_log_control(const char *name, const char *args,
                                        char *__user out_msg, int outlen)
{
    pr_info("%s control args: %s\n",
            name ? name : "kpm-demo",
            args ? args : "(null)");
    return kpm_demo_copy_message(args ? args : "", out_msg, outlen);
}

#endif
