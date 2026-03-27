/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include "../common/kpm_demo_helpers.h"

KPM_MODULE_INFO("kpm-inline-hook-demo",
                "1.0.0",
                "GPL v2",
                "bmax121",
                "KernelPatch Module Inline Hook Example");

/* [用途] 被 hook 的目标函数，用于验证 before/after 链路。 */
int __noinline add(int a, int b)
{
    logkd("origin add called\n");
    int ret = a + b;
    return ret;
}

/* [用途] 前置 hook：观察原始入参。 */
void before_add(hook_fargs2_t *args, void *udata)
{
    logkd("before add arg0: %d, arg1: %d\n", (int)args->arg0, (int)args->arg1);
}

/*
 * [用途] 后置 hook：观察返回值并主动改写。
 * [实现] 演示通过 args->ret 把返回值强制改为 100。
 */
void after_add(hook_fargs2_t *args, void *udata)
{
    logkd("after add arg0: %d, arg1: %d, ret: %d\n", (int)args->arg0, (int)args->arg1, (int)args->ret);
    args->ret = 100;
}

/*
 * [用途] 模块初始化：先调用一次原函数，再安装 hook，再次调用观察差异。
 * [实现] 使用 hook_wrap2 安装 before/after 双回调。
 */
static long inline_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    logkd("kpm inline-hook-demo init\n");

    int a = 20;
    int b = 10;

    int ret = add(a, b);
    logkd("%d + %d = %d\n", a, b, ret);

    hook_err_t err = hook_wrap2((void *)add, before_add, after_add, 0);
    logkd("hook err: %d\n", err);

    ret = add(a, b);
    logkd("%d + %d = %d\n", a, b, ret);

    return 0;
}

/* [用途] control 接口，复用公共日志 helper。 */
static long inline_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    return kpm_demo_log_control("kpm inline-hook-demo", args, out_msg, outlen);
}

/*
 * [用途] 模块退出：解除 hook 并验证函数行为恢复。
 * [输出] 0。
 */
static long inline_hook_demo_exit(void *__user reserved)
{
    unhook((void *)add);

    int a = 20;
    int b = 10;

    int ret = add(a, b);
    logkd("%d + %d = %d\n", a, b, ret);

    logkd("kpm inline-hook-demo  exit\n");
    return 0;
}

KPM_INIT(inline_hook_demo_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_demo_exit);
