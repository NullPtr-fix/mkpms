/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include "../common/kpm_demo_helpers.h"

///< The name of the module, each KPM must has a unique name.
KPM_MODULE_INFO("kpm-hello-demo", "1.0.0", "GPL v2", "bmax121", "KernelPatch Module Example");

/*
 * [用途] 模块初始化入口（KPM_INIT）。
 * [输入] args: 加载参数；event: 触发事件；reserved: 保留参数。
 * [输出] 0 表示成功。
 * [实现] 调用公共 helper 打印统一初始化日志。
 */
static long hello_init(const char *args, const char *event, void *__user reserved)
{
    (void)reserved;
    return kpm_demo_log_init("kpm hello", event, args);
}

/*
 * [用途] 控制接口 0（KPM_CTL0）。
 * [实现] 把控制参数回显到日志，并可选复制给用户态。
 */
static long hello_control0(const char *args, char *__user out_msg, int outlen)
{
    return kpm_demo_echo_control("kpm hello", args, out_msg, outlen);
}

/*
 * [用途] 控制接口 1（KPM_CTL1）示例。
 * [实现] 打印三个透传参数，便于调试调用约定。
 */
static long hello_control1(void *a1, void *a2, void *a3)
{
    pr_info("kpm hello control1, a1: %llx, a2: %llx, a3: %llx\n", a1, a2, a3);
    return 0;
}

/* [用途] 模块退出入口（KPM_EXIT）。 */
static long hello_exit(void *__user reserved)
{
    (void)reserved;
    return kpm_demo_log_exit("kpm hello");
}

KPM_INIT(hello_init);
KPM_CTL0(hello_control0);
KPM_CTL1(hello_control1);
KPM_EXIT(hello_exit);
