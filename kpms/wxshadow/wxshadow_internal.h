/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory KPM Module - Internal Header
 * Copyright (C) 2024
 */

/*
 * wxshadow 模块内部头文件
 *
 * 位置：本文件是所有 wxshadow 子模块（wxshadow.c / wxshadow_bp.c /
 *       wxshadow_pgtable.c / wxshadow_handlers.c / wxshadow_scan.c）共享的
 *       内部接口头文件，不对外暴露。
 *
 * 用途：集中定义以下内容，使各 .c 文件无需重复声明：
 *   - ARM64 CPU 原语（cpu_relax、per-page PTE 自旋锁）
 *   - KP 框架 bug 修复版 next_task()
 *   - 所有通过 kallsyms 动态解析的内核函数指针
 *   - 地址翻译辅助变量与函数
 *   - ESR 异常综合寄存器解析宏与内联函数
 *   - 全局状态（page_list、global_lock、wx_in_flight）
 *   - 各子模块对外声明的函数原型
 */
#ifndef _KPM_WXSHADOW_INTERNAL_H_
#define _KPM_WXSHADOW_INTERNAL_H_

/*
 * ========== 头文件依赖 ==========
 * 引入 KernelPatch 框架及 Linux 内核适配头文件。
 * 注意：init_task 不由框架导出，改用 wx_init_task（通过 kallsyms 解析）。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <hook.h>
#include <ksyms.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/rculist.h>
/* init_task: use wx_init_task via kallsyms (framework doesn't export it) */
#include <pgtable.h>
#include <asm/current.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/ptrace.h>
#include <asm/atomic.h>
#include <linux/err.h>

#include <predata.h>
#include "wxshadow.h"

/*
 * ========== ARM64 CPU 原语 ==========
 *
 * 位置：最底层硬件辅助，被本文件内的自旋等待循环和 PTE 锁直接使用。
 * 用途：在忙等待（busy-wait）时向流水线提示让出执行单元，降低功耗和总线竞争。
 */

/* cpu_relax - 发出 ARM64 YIELD 提示，在自旋等待循环中使用以降低功耗 */
static inline void cpu_relax(void)
{
    asm volatile("yield" ::: "memory");
}

/*
 * Per-page PTE 重写锁（逻辑自旋锁）。
 *
 * 位置：每个 wxshadow_page 结构体内嵌 pte_lock 原子变量。
 * 用途：这是 wxshadow 自己的逻辑锁，不是内核页表锁。它序列化对同一页的
 *       PTE 状态切换（shadow ↔ original ↔ stepping），防止 release / fault
 *       / step / GUP 等路径并发竞争导致 PTE 状态不一致。
 * 实现：CAS 循环，0=未锁，1=已锁；unlock 直接 atomic_set 为 0。
 */
static inline void wxshadow_page_pte_lock(struct wxshadow_page *page)
{
    while (atomic_cmpxchg(&page->pte_lock, 0, 1) != 0)
        cpu_relax();
}

/* wxshadow_page_pte_unlock - 释放 per-page PTE 逻辑锁 */
static inline void wxshadow_page_pte_unlock(struct wxshadow_page *page)
{
    atomic_set(&page->pte_lock, 0);
}

/*
 * task_struct 偏移量说明：
 * KP 框架（linux/sched.h）已提供：comm_offset、cred_offset、
 * real_cred_offset 等。wxshadow 需自行检测 tasks_offset、mm_offset。
 * PID/TGID 通过 wxfunc(__task_pid_nr_ns) 获取（见下方 wxfunc 宏系统）。
 */

/*
 * ========== KP 框架 next_task() 修复版 ==========
 *
 * 位置：替代 linux/sched.h 中 KP 框架提供的 next_task()。
 * 用途：KP 框架原版存在 bug——对指针做减法时会被编译器当作指针算术
 *       （步长 = sizeof(struct list_head) = 16），导致偏移量被放大 16 倍。
 * 实现：先将 task 指针转为 (char *) 再做字节级偏移运算，确保结果正确。
 */
static inline struct task_struct *wx_next_task(struct task_struct *task)
{
    struct list_head *head = (struct list_head *)((char *)task + task_struct_offset.tasks_offset);
    struct list_head *next = head->next;
    return (struct task_struct *)((char *)next - task_struct_offset.tasks_offset);
}

/*
 * ========== 内核函数指针（通过 kallsyms 动态解析） ==========
 *
 * 位置：模块初始化阶段（resolve_symbols）填充以下所有函数指针。
 * 用途：KPM 模块无法直接链接内核符号，必须在运行时通过 kallsyms_lookup_name
 *       查找地址，再转为函数指针调用。
 * 实现：每个指针在 wxshadow.c 中定义并初始化为 NULL，由 resolve_symbols()
 *       赋值；调用前需检查非 NULL（可选函数除外）。
 */

/* -------- 内存管理 -------- */
extern void *(*kfunc_find_vma)(void *mm, unsigned long addr); /* 查找包含 addr 的 VMA */
extern void *(*kfunc_get_task_mm)(void *task);                /* 获取进程 mm，增加引用计数 */
extern void (*kfunc_mmput)(void *mm);                         /* 释放 mm 引用，对应 get_task_mm */
/* find_task_by_vpid: use find_task_by_vpid() from linux/sched.h */

/* exit_mmap hook */
extern void *kfunc_exit_mmap; /* exit_mmap 的函数地址，用于 hook（进程退出时清理 shadow） */

/* -------- 物理页分配 -------- */
extern unsigned long (*kfunc___get_free_pages)(unsigned int gfp_mask, unsigned int order); /* 分配 2^order 个连续物理页，返回内核虚地址 */
extern void (*kfunc_free_pages)(unsigned long addr, unsigned int order);                   /* 释放 __get_free_pages 分配的页 */

/*
 * -------- 地址翻译变量 --------
 * ARM64 线性映射：va = pa - memstart_addr + PAGE_OFFSET
 * 或：va = pa + physvirt_offset（新内核优先使用）
 */
extern s64 *kvar_memstart_addr;       /* 指向内核 memstart_addr 变量，物理内存起始地址 */
extern s64 *kvar_physvirt_offset;     /* 指向内核 physvirt_offset 变量（5.10+ 内核） */
extern unsigned long page_offset_base;/* 线性映射区基地址（PAGE_OFFSET），运行时检测 */
extern s64 detected_physvirt_offset;  /* 运行时自行检测到的 physvirt_offset 值 */
extern int physvirt_offset_valid;     /* 非 0 表示 detected_physvirt_offset 已有效 */

/* -------- 页表配置 -------- */
extern int wx_page_shift; /* 当前内核页大小的位移（通常为 12，即 4KB 页） */
extern int wx_page_level; /* 页表级数（3 或 4 级，取决于内核配置） */

/*
 * ========== wxfunc 宏系统：本地函数指针封装 ==========
 *
 * 位置：替代 KP 框架的 kfunc_def/kfunc_match 宏，使用 wx_ 前缀命名。
 * 用途：KP 框架内部已有 kf_ 前缀的同名符号（如 kf__raw_spin_lock），
 *       直接复用会导致链接冲突或行为不符预期。用 wx_ 前缀的独立函数指针
 *       可以避免这一问题，同时保持与框架相同的调用惯例。
 * 实现：
 *   - wxfunc_def(func)  展开为 (*wx_##func)，用于声明/定义函数指针变量
 *   - wxfunc(func)      展开为 wx_##func，用于调用
 *   - 查找时调用 kallsyms_lookup_name 填充指针（见 resolve_symbols）
 *
 * 使用示例：
 *   声明：extern void wxfunc_def(_raw_spin_lock)(raw_spinlock_t *lock);
 *   定义：void wxfunc_def(_raw_spin_lock)(raw_spinlock_t *lock) = 0;
 *   查找：wxfunc_lookup_name(_raw_spin_lock);
 *   调用：wxfunc(_raw_spin_lock)(lock);
 */
#define wxfunc(func) wx_##func       /* 生成函数指针变量名，用于调用 */
#define wxfunc_def(func) (*wx_##func)/* 生成函数指针声明语法片段 */

/* -------- 自旋锁函数指针 -------- */
extern void wxfunc_def(_raw_spin_lock)(raw_spinlock_t *lock);   /* 内核 _raw_spin_lock，用于 spin_lock */
extern void wxfunc_def(_raw_spin_unlock)(raw_spinlock_t *lock); /* 内核 _raw_spin_unlock，用于 spin_unlock */

/*
 * 覆盖框架提供的 spin_lock/spin_unlock 宏，使其指向 wxfunc 版本。
 * 原因：KP 框架将 spin_lock 展开为依赖 kf__raw_spin_lock 的调用，
 *       而该符号未被导出，会导致链接错误。此处 undef 后重定义为
 *       调用 wx__raw_spin_lock，解决此问题。
 */
#undef spin_lock
#undef spin_unlock
#undef raw_spin_lock
#undef raw_spin_unlock
#define raw_spin_lock(lock) wxfunc(_raw_spin_lock)(lock)   /* 使用 wx_ 版本的原始自旋锁 */
#define raw_spin_unlock(lock) wxfunc(_raw_spin_unlock)(lock)/* 使用 wx_ 版本的原始自旋解锁 */
#define spin_lock(lock) raw_spin_lock(&(lock)->rlock)      /* spin_lock → raw_spin_lock */
#define spin_unlock(lock) raw_spin_unlock(&(lock)->rlock)  /* spin_unlock → raw_spin_unlock */

/* -------- 任务查找函数指针 -------- */
extern struct task_struct *wxfunc_def(find_task_by_vpid)(pid_t nr); /* 通过虚拟 PID 查找 task_struct */
extern pid_t wxfunc_def(__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns); /* 获取指定命名空间中的 PID/TGID */

/* init_task - 通过 kallsyms 解析，因为 KP 框架不导出此符号 */
extern struct task_struct *wx_init_task; /* 指向内核 init_task（swapper/0 进程），用于遍历进程链表 */

/* -------- Cache 操作函数指针 -------- */
extern void (*kfunc_flush_dcache_page)(void *page);                              /* 将 struct page 对应的 dcache 刷写到 PoC */
extern void (*kfunc___flush_icache_range)(unsigned long start, unsigned long end);/* 使 [start, end) 范围的 icache 失效 */

/* -------- 调试/单步执行 -------- */
extern void (*kfunc_user_enable_single_step)(void *task);  /* 为目标任务开启硬件单步（MDSCR_EL1.SS） */
extern void (*kfunc_user_disable_single_step)(void *task); /* 关闭目标任务的硬件单步 */

/* -------- 直接 hook 的异常处理函数地址 -------- */
extern void *kfunc_brk_handler;          /* 内核 brk_handler 函数地址，BRK 指令触发时调用 */
extern void *kfunc_single_step_handler;  /* 内核 single_step_handler 函数地址，单步完成时调用 */

/* -------- register_user_*_hook API（备用注册路径） -------- */
extern void (*kfunc_register_user_break_hook)(struct wx_break_hook *hook); /* 注册用户态 BRK hook（部分内核版本支持） */
extern void (*kfunc_register_user_step_hook)(struct wx_step_hook *hook);   /* 注册用户态单步 hook（部分内核版本支持） */
extern spinlock_t *kptr_debug_hook_lock; /* 内核调试 hook 链表锁，备用路径需要持有 */

/* Locking - NOT USED (lockless operation) */

/* -------- RCU 操作 -------- */
extern void (*kfunc_rcu_read_lock)(void);       /* 进入 RCU 读临界区 */
extern void (*kfunc_rcu_read_unlock)(void);     /* 离开 RCU 读临界区 */
extern void (*kfunc_synchronize_rcu)(void);     /* 等待所有 RCU 读者完成（可睡眠） */
extern void (*kfunc_kick_all_cpus_sync)(void);  /* 强制所有 CPU 经历一次调度点，用于保证 IPI 同步 */

/* -------- 内存分配 -------- */
extern void *(*kfunc_kzalloc)(size_t size, unsigned int flags);         /* 分配 size 字节并清零 */
extern void *(*kfunc_kcalloc)(size_t n, size_t size, unsigned int flags);/* 分配 n*size 字节并清零（首选，有溢出检查） */
extern void (*kfunc_kfree)(void *ptr);                                   /* 释放 kzalloc/kcalloc 分配的内存 */

/* -------- 安全内存访问 -------- */
extern long (*kfunc_copy_from_kernel_nofault)(void *dst, const void *src, size_t size); /* 从内核地址安全读取，失败返回负值而非 oops */

/* -------- 页错误 hook -------- */
extern void *kfunc_do_page_fault;    /* do_page_fault 函数地址，hook 用于拦截 shadow/original 权限 fault */

/* -------- follow_page_pte hook（GUP 隐藏） -------- */
extern void *kfunc_follow_page_pte; /* follow_page_pte 函数地址，hook 用于向 GUP 隐藏 shadow 页的真实 PTE */

/* -------- fork 保护 hook -------- */
extern void *kfunc_dup_mmap;         /* dup_mmap 函数地址，fork 时复制 mm 的 hook 点 */
extern void *kfunc_uprobe_dup_mmap;  /* uprobe_dup_mmap 函数地址，uprobe 相关的 fork mm 复制 hook */
extern void *kfunc_copy_process;     /* copy_process 函数地址，创建子进程时 hook，用于标记子进程 */
extern void *kfunc_cgroup_post_fork; /* cgroup_post_fork 函数地址，fork 后期 hook，备用保护点 */

/* -------- TLB 刷新 -------- */
extern void (*kfunc_flush_tlb_page)(void *vma, unsigned long uaddr); /* 刷新单页 TLB（优先使用） */
extern void (*kfunc___flush_tlb_range)(void *vma, unsigned long start, unsigned long end,
                                        unsigned long stride, bool last_level, int tlb_level); /* 刷新地址范围 TLB（备用） */

/* -------- 透明大页拆分 -------- */
extern void (*kfunc___split_huge_pmd)(void *vma, void *pmd, unsigned long address,
                                       bool freeze, void *page); /* 将 THP PMD 拆分为普通 PTE 映射，以便单页操作 */

/*
 * ========== mm_struct / VMA 偏移量变量 ==========
 *
 * 位置：由 wxshadow_scan.c 中的扫描函数在模块初始化时填充。
 * 用途：不同内核版本的结构体字段布局不同，必须动态检测偏移量，
 *       不能硬编码。-1 表示尚未检测。
 */

extern int16_t vma_vm_mm_offset; /* vm_area_struct.vm_mm 字段偏移，用于从 VMA 取得所属 mm */
/* mm_pgd_offset: use mm_struct_offset.pgd_offset from KP framework (linux/mm_types.h) */
/* NOTE: mm_page_table_lock_offset and mm_mmap_lock_offset_dyn are NOT used (lockless) */

/* mm->context.id 偏移量，用于读取 ASID（运行时通过 TTBR0_EL1 匹配检测，-1 表示未检测） */
extern int16_t mm_context_id_offset;

/* TLB 刷新策略：0=flush_tlb_page，1=__flush_tlb_range，2=TLBI 指令直接操作 */
extern int tlb_flush_mode;

/*
 * ========== 全局状态 ==========
 *
 * 位置：wxshadow.c 定义，各子模块通过 extern 共享。
 * 用途：维护所有已安装 shadow 页的全局链表及保护它的自旋锁，
 *       以及用于安全卸载的 in-flight 计数器。
 */

/* 使用 KP 框架的 spinlock_t 和 list_head（来自 linux/spinlock.h 和 linux/list.h） */
extern struct list_head page_list; /* 全局 wxshadow_page 链表，记录所有已创建的 shadow 页 */
extern spinlock_t global_lock;     /* 保护 page_list 及各页状态字段的全局自旋锁 */

/*
 * In-flight 处理器计数器。
 *
 * 位置：每个 hook 处理函数（brk/step/fault/prctl 等）入口/出口处更新。
 * 用途：wxshadow_exit() 在 unhook 所有处理函数后必须等待此计数归零，
 *       才能安全返回。KP 框架会在 exit() 返回后立即调用 kp_free_exec()
 *       释放模块代码段，若此时仍有处理函数在执行则会崩溃。
 * 实现：原子加减，spin-wait 直到归零。
 */
extern atomic_t wx_in_flight;

#define WX_HANDLER_ENTER() atomic_inc(&wx_in_flight) /* 处理函数入口：in-flight 计数 +1 */
#define WX_HANDLER_EXIT()  atomic_dec(&wx_in_flight) /* 处理函数出口：in-flight 计数 -1 */

#define WXSHADOW_RELEASE_WAIT_LOOPS 2000000 /* 卸载时等待 in-flight 归零的最大自旋次数 */

/* init_task: use init_task from linux/init_task.h (KernelPatch framework) */

/* ========== BRK/Step hook ========== */
/* NOTE: Using direct brk_handler/single_step_handler hook, no struct needed */

/*
 * ========== ESR（Exception Syndrome Register）解析宏 ==========
 *
 * 位置：ARM64 异常处理路径（do_page_fault / brk_handler / step_handler）。
 * 用途：从 ESR_ELx 寄存器值中提取异常类型（EC）、指令长度（IL）、
 *       指令特定综合（ISS）字段，以及数据中止的写标志（WNR）等，
 *       用于判断触发异常的访问类型（执行/读/写）。
 * 实现：纯宏位运算，无函数调用开销。
 */

/* ESR_ELx 字段位域定义 */
#define ESR_ELx_EC_SHIFT        26                              /* EC 字段起始位 */
#define ESR_ELx_EC_MASK         (0x3FUL << ESR_ELx_EC_SHIFT)   /* EC 字段掩码（6 位） */
#define ESR_ELx_EC(esr)         (((esr) & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT) /* 提取 EC 值 */
#define ESR_ELx_IL_SHIFT        25                              /* IL（指令长度）位 */
#define ESR_ELx_IL              (1UL << ESR_ELx_IL_SHIFT)       /* IL 标志：1=32位指令，0=16位 */
#define ESR_ELx_ISS_MASK        0x01FFFFFFUL                    /* ISS 字段掩码（25 位） */
#define ESR_ELx_WNR_SHIFT       6                               /* WNR（写非读）标志位 */
#define ESR_ELx_WNR             (1UL << ESR_ELx_WNR_SHIFT)      /* WNR=1 表示写访问触发 data abort */
#define ESR_ELx_S1PTW_SHIFT     7                               /* S1PTW：stage-1 页表遍历 fault */
#define ESR_ELx_S1PTW           (1UL << ESR_ELx_S1PTW_SHIFT)
#define ESR_ELx_CM_SHIFT        8                               /* CM：cache 维护操作触发 fault */
#define ESR_ELx_CM              (1UL << ESR_ELx_CM_SHIFT)

/* ARM64 异常类型（EC）值 */
#define ESR_ELx_EC_UNKNOWN      0x00 /* 未知异常 */
#define ESR_ELx_EC_IABT_LOW     0x20 /* 低异常级（EL0）指令中止（取指权限 fault） */
#define ESR_ELx_EC_IABT_CUR     0x21 /* 当前异常级（EL1）指令中止 */
#define ESR_ELx_EC_DABT_LOW     0x24 /* 低异常级（EL0）数据中止（读/写权限 fault） */
#define ESR_ELx_EC_DABT_CUR    0x25 /* 当前异常级（EL1）数据中止 */

/* is_el0_instruction_abort - 判断是否为 EL0 指令取指 fault（执行权限违例） */
static inline bool is_el0_instruction_abort(unsigned int esr)
{
    return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW;
}

/* is_el0_data_abort - 判断是否为 EL0 数据访问 fault（读/写权限违例） */
static inline bool is_el0_data_abort(unsigned int esr)
{
    return ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_LOW;
}

/* is_permission_fault - 判断 fault 状态码是否为权限违例（FSC[5:2] == 0b0011） */
static inline bool is_permission_fault(unsigned int esr)
{
    unsigned int fsc = esr & 0x3F;
    return (fsc & 0x3C) == 0x0C;
}

/*
 * wxshadow_fault_access - wxshadow 关心的访问类型枚举
 *
 * 用途：wxshadow_classify_permission_fault() 返回此枚举，
 *       供页 fault 处理逻辑决定切换到哪种页面状态。
 */
enum wxshadow_fault_access {
    WXSHADOW_FAULT_NONE = 0, /* 非权限 fault 或无需处理的类型 */
    WXSHADOW_FAULT_EXEC,     /* 执行权限 fault → 需要 shadow 页执行 BRK */
    WXSHADOW_FAULT_READ,     /* 读权限 fault → 需要切换到 original 页供读取 */
    WXSHADOW_FAULT_WRITE,    /* 写权限 fault → 目标页被写入，需拆除 shadow */
};

/*
 * wxshadow_classify_permission_fault - 将 ESR 值解析为访问类型
 *
 * 位置：do_page_fault hook 的前置处理。
 * 用途：根据 EC 和 ISS 字段区分执行/读/写，决定后续如何切换 PTE 映射。
 * 实现：
 *   - 非权限 fault → NONE
 *   - IABT_LOW → EXEC
 *   - DABT_LOW + S1PTW → NONE（页表遍历，忽略）
 *   - DABT_LOW + CM → READ（cache 维护视为读）
 *   - DABT_LOW + WNR → WRITE，否则 → READ
 */
static inline enum wxshadow_fault_access
wxshadow_classify_permission_fault(unsigned int esr)
{
    if (!is_permission_fault(esr))
        return WXSHADOW_FAULT_NONE;

    if (is_el0_instruction_abort(esr))
        return WXSHADOW_FAULT_EXEC;

    if (!is_el0_data_abort(esr))
        return WXSHADOW_FAULT_NONE;

    /*
     * Cache maintenance and stage-1 page-table walk faults are not direct
     * writes to the tracked page contents. Treat CM like a read-side access so
     * we can flip back to the original mapping, and ignore S1PTW entirely.
     */
    if (esr & ESR_ELx_S1PTW)
        return WXSHADOW_FAULT_NONE;
    if (esr & ESR_ELx_CM)
        return WXSHADOW_FAULT_READ;

    return (esr & ESR_ELx_WNR) ? WXSHADOW_FAULT_WRITE
                               : WXSHADOW_FAULT_READ;
}

/*
 * 使用 KP 框架提供的链表和自旋锁操作（来自 linux/spinlock.h 和 linux/list.h）：
 * - spin_lock() / spin_unlock()
 * - INIT_LIST_HEAD() / list_add() / list_del_init() / list_empty()
 * - list_for_each() / list_for_each_safe()
 * - container_of()（来自 linux/container_of.h）
 */

/*
 * ========== 内核地址有效性检查 ==========
 *
 * 位置：在读取或操作内核指针前调用，防止非法地址解引用。
 * 用途：快速判断一个地址是否落在 ARM64 内核虚拟地址空间（TTBR1 区域）。
 */

/*
 * is_kva - 检查地址是否为合法的内核虚拟地址
 * ARM64 内核虚拟地址（TTBR1 映射）高 16 位均为 0xffff，
 * 包括动态分配的 slab/kmalloc 地址。
 */
static inline bool is_kva(unsigned long addr)
{
    return (addr >> 48) == 0xffff;
}

/*
 * ========== 安全内存读取辅助函数 ==========
 *
 * 位置：偏移量扫描（wxshadow_scan.c）和地址翻译路径中使用。
 * 用途：在不确定目标地址是否合法时安全地读取内核内存，
 *       避免直接解引用无效指针导致内核 panic。
 * 实现：优先使用 kfunc_copy_from_kernel_nofault（内核提供的安全读取接口），
 *       若未解析则退回到直接指针解引用（仅在 is_kva 检查后）。
 */

/*
 * safe_read_u64 - 安全读取内核内存中的 u64 值
 * 成功返回 true，地址无效或读取失败返回 false
 * 注意：kfunc_copy_from_kernel_nofault 在本文件后面声明
 */
static inline bool safe_read_u64(unsigned long addr, u64 *out)
{
    extern long (*kfunc_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);

    if (!is_kva(addr))
        return false;

    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(out, (const void *)addr, sizeof(*out)) != 0)
            return false;
    } else {
        /* Fallback: direct access (less safe) */
        *out = *(u64 *)addr;
    }
    return true;
}

/*
 * safe_read_ptr - 安全读取内核内存中的指针值
 * 封装 safe_read_u64，类型转为 void *
 */
static inline bool safe_read_ptr(unsigned long addr, void **out)
{
    return safe_read_u64(addr, (u64 *)out);
}

/*
 * ========== VMA 字段访问辅助 ==========
 *
 * 位置：所有需要读取 VMA 或 mm 字段的代码路径。
 * 用途：vm_area_struct 的字段偏移在不同内核版本下不同，必须通过
 *       运行时检测到的偏移量访问，不能直接使用结构体成员。
 * 实现：GET_FIELD/SET_FIELD 宏提供类型安全的按偏移量访问；
 *       内联函数封装常用字段，统一错误处理。
 */

#define VMA_VM_START_OFFSET     0x00 /* vm_area_struct.vm_start 字段固定偏移（所有内核版本一致） */
#define VMA_VM_END_OFFSET       0x08 /* vm_area_struct.vm_end 字段固定偏移（所有内核版本一致） */

#define GET_FIELD(ptr, offset, type) (*(type *)((char *)(ptr) + (offset)))      /* 按偏移量读取字段 */
#define SET_FIELD(ptr, offset, type, val) (*(type *)((char *)(ptr) + (offset)) = (val)) /* 按偏移量写入字段 */

/* vma_mm - 从 VMA 获取所属 mm_struct 指针 */
static inline void *vma_mm(void *vma) {
    if (vma_vm_mm_offset < 0) {
        pr_err("wxshadow: vma_vm_mm_offset not initialized!\n");
        return NULL;
    }
    return GET_FIELD(vma, vma_vm_mm_offset, void *);
}

/* vma_start - 获取 VMA 的起始虚拟地址 */
static inline unsigned long vma_start(void *vma) {
    return GET_FIELD(vma, VMA_VM_START_OFFSET, unsigned long);
}

/* vma_end - 获取 VMA 的结束虚拟地址（不含） */
static inline unsigned long vma_end(void *vma) {
    return GET_FIELD(vma, VMA_VM_END_OFFSET, unsigned long);
}

/* mm_pgd - 获取 mm_struct 的 PGD（顶级页表）指针，使用 KP 框架检测到的偏移 */
static inline void *mm_pgd(void *mm) {
    /* Use KP framework's mm_struct_offset.pgd_offset (linux/mm_types.h) */
    if (mm_struct_offset.pgd_offset < 0) {
        pr_err("wxshadow: mm_struct_offset.pgd_offset not initialized!\n");
        return NULL;
    }
    return GET_FIELD(mm, mm_struct_offset.pgd_offset, void *);
}

/* NOTE: mm_mmap_lock helper removed - lockless operation */

/*
 * ========== 安全的 kcalloc 封装 ==========
 *
 * 位置：所有需要分配清零内存的地方（替代直接调用 kfunc_kcalloc）。
 * 用途：kcalloc 是可选解析符号；若未找到则退回 kzalloc + 手动溢出检查，
 *       保持分配语义一致。
 */

/* safe_kcalloc - 分配 n*size 字节清零内存，自动回退到 kzalloc */
static inline void *safe_kcalloc(size_t n, size_t size, unsigned int flags)
{
    if (kfunc_kcalloc)
        return kfunc_kcalloc(n, size, flags);
    if (n != 0 && size > ((size_t)-1) / n)
        return NULL;
    return kfunc_kzalloc(n * size, flags);
}

/*
 * ========== 地址翻译辅助函数 ==========
 *
 * 位置：页表操作（wxshadow_pgtable.c）和偏移量扫描（wxshadow_scan.c）中使用。
 * 用途：在物理地址与内核虚拟地址之间相互转换，以及将用户虚地址翻译为物理地址。
 * 实现：
 *   - vaddr_to_paddr_at：通过 AT S1E1R 指令在内核侧执行地址翻译，读取 PAR_EL1
 *   - phys_to_virt_safe：按优先级使用 detected_physvirt_offset / kvar_physvirt_offset
 *                        / memstart_addr + page_offset_base 三种方式计算内核虚地址
 *   - kaddr_to_phys：上述的逆操作
 *   - kaddr_to_pfn：内核虚地址 → 页帧号（PFN）
 *   - pfn_to_kaddr：PFN → 内核虚地址
 */

/* vaddr_to_paddr_at - 用 AT S1E1R 指令将内核虚地址翻译为物理地址，失败返回 0 */
static inline unsigned long vaddr_to_paddr_at(unsigned long vaddr)
{
    u64 par;
    asm volatile("at s1e1r, %0" : : "r"(vaddr));
    asm volatile("isb");
    asm volatile("mrs %0, par_el1" : "=r"(par));
    if (par & 1)
        return 0;
    return (par & 0x0000FFFFFFFFF000UL) | (vaddr & 0xFFF);
}

/* phys_to_virt_safe - 物理地址 → 内核虚拟地址（按优先级选择翻译方法） */
static inline unsigned long phys_to_virt_safe(unsigned long pa)
{
    if (physvirt_offset_valid)
        return pa + detected_physvirt_offset;
    else if (kvar_physvirt_offset)
        return pa + *kvar_physvirt_offset;
    else
        return (pa - *kvar_memstart_addr) + page_offset_base;
}

/* kaddr_to_phys - 内核虚拟地址 → 物理地址（phys_to_virt_safe 的逆操作） */
static inline unsigned long kaddr_to_phys(unsigned long vaddr)
{
    if (physvirt_offset_valid)
        return vaddr - detected_physvirt_offset;
    else if (kvar_physvirt_offset)
        return vaddr - *kvar_physvirt_offset;
    else
        return (vaddr - page_offset_base) + *kvar_memstart_addr;
}

/* kaddr_to_pfn - 内核虚拟地址 → 页帧号（PFN = 物理地址 >> PAGE_SHIFT） */
static inline unsigned long kaddr_to_pfn(unsigned long vaddr)
{
    return kaddr_to_phys(vaddr) >> PAGE_SHIFT;
}

/* pfn_to_kaddr - 页帧号 → 内核虚拟地址（先算物理地址再转虚地址） */
static inline void *pfn_to_kaddr(unsigned long pfn)
{
    unsigned long pa = pfn << PAGE_SHIFT;
    return (void *)phys_to_virt_safe(pa);
}

#define safe_kunmap(addr) do { } while(0) /* 空宏：本模块不使用 kmap，保留以兼容调用点 */

/*
 * ========== Cache 刷新辅助函数 ==========
 *
 * 位置：shadow 页内容修改后（memcpy / copy_from_user）必须调用。
 * 用途：确保修改后的数据对指令取指可见（D-cache → PoU → I-cache）。
 *
 * 为什么必须用内核虚地址（KVA）刷 dcache：
 *   1. 内核虚地址始终有效（TTBR1 映射），dc cvau 一定能命中目标缓存行。
 *   2. 跨进程 patch（pid != 0）时，目标进程的用户虚地址未映射在调用者的
 *      TTBR0 中，在调用者上下文用用户虚地址刷 dcache 是 NOP，不起作用。
 *   3. ARM64 dcache 是 PIPT，用内核虚地址刷的缓存行与用户侧取指使用的
 *      物理行是同一条，因此刷内核 VA 等价于刷用户侧的物理行。
 */

/*
 * wxshadow_flush_kern_dcache_area - 将内核虚地址范围的 dcache 刷写到 PoU
 * kva: 起始内核虚地址；size: 字节数
 */
static inline void wxshadow_flush_kern_dcache_area(unsigned long kva, unsigned long size)
{
    unsigned long addr, end;
    u64 ctr_el0, line_size;

    /* Read cache line size from CTR_EL0.DminLine */
    asm volatile("mrs %0, ctr_el0" : "=r"(ctr_el0));
    line_size = 4 << ((ctr_el0 >> 16) & 0xf);

    end = kva + size;
    for (addr = kva & ~(line_size - 1); addr < end; addr += line_size)
        asm volatile("dc cvau, %0" : : "r"(addr) : "memory");

    asm volatile("dsb ish" : : : "memory");
}

/*
 * wxshadow_flush_icache_range - 使 [start, end) 范围的 icache 失效
 * 优先调用内核 __flush_icache_range；若未解析则退回全局 IC IALLUIS。
 */
static inline void wxshadow_flush_icache_range(unsigned long start, unsigned long end)
{
    if (kfunc___flush_icache_range) {
        kfunc___flush_icache_range(start, end);
        asm volatile("isb" : : : "memory");
        return;
    }
    /* Fallback: global icache invalidate (dcache must already be clean) */
    asm volatile("ic ialluis" : : : "memory");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

/* wxshadow_flush_icache_page - 使整个页（PAGE_SIZE）的 icache 失效 */
static inline void wxshadow_flush_icache_page(unsigned long addr)
{
    wxshadow_flush_icache_range(addr & PAGE_MASK, (addr & PAGE_MASK) + PAGE_SIZE);
}

/* ========== 页表辅助备注 ========== */

/* NOTE: mm_page_table_lock helper removed - lockless operation */
/* NOTE: mm_get_asid removed - using kernel flush_tlb_page directly */

/*
 * ========== 核心函数声明（wxshadow.c） ==========
 *
 * 位置：wxshadow.c 实现，供 wxshadow_bp.c / wxshadow_handlers.c /
 *       wxshadow_pgtable.c 调用。
 * 用途：管理 wxshadow_page 的生命周期（创建/查找/释放/断点管理），
 *       以及处理写 fault、脏页同步等核心逻辑。
 */

/*
 * wxshadow_page_put - 释放对 wxshadow_page 的一次引用。
 * 引用计数降为零时 kfree 该结构。
 * 可在任意上下文调用；内部会获取 global_lock。
 */
void wxshadow_page_put(struct wxshadow_page *page);

struct wxshadow_page *wxshadow_find_page(void *mm, unsigned long addr);    /* 在 page_list 中查找包含 addr 的 shadow 页 */
struct wxshadow_page *wxshadow_create_page(void *mm, unsigned long page_addr); /* 分配并初始化新的 wxshadow_page，加入 page_list */
void wxshadow_free_page(struct wxshadow_page *page);                       /* 释放 wxshadow_page 结构及其 shadow 物理页 */
struct wxshadow_bp *wxshadow_find_bp(struct wxshadow_page *page_info, unsigned long addr); /* 在页内查找指定地址的断点结构 */
void wxshadow_sync_page_tracking(struct wxshadow_page *page);              /* 同步 shadow 页的跟踪位图（bp/patch 脏位） */
int wxshadow_validate_page_mapping(void *mm, void *vma, struct wxshadow_page *page_info, unsigned long page_addr); /* 验证 shadow 页的 VMA 映射是否仍然有效 */
int wxshadow_teardown_page(struct wxshadow_page *page, const char *reason);/* 完全拆除一个 shadow 页（恢复原始 PTE，释放资源） */
int wxshadow_teardown_pages_for_mm(void *mm, const char *reason);          /* 拆除属于指定 mm 的所有 shadow 页（进程退出时调用） */
int wxshadow_release_page_logically(struct wxshadow_page *page,
                                    const char *reason);                   /* 逻辑释放：保留 shadow 页数据但解除 PTE 映射 */
int wxshadow_release_pages_for_mm(void *mm, const char *reason);           /* 逻辑释放属于指定 mm 的所有 shadow 页 */
int wxshadow_handle_write_fault(void *mm, unsigned long addr);             /* 处理写权限 fault：目标页被写入，拆除 shadow */
void wxshadow_sync_shadow_exec_zero(struct wxshadow_page *page,
                                    const char *reason);                   /* 将 shadow 页中无断点/patch 的位置清零同步 */
void wxshadow_mark_patch_dirty(struct wxshadow_page *page, unsigned long offset,
                               unsigned long len);                         /* 标记 [offset, offset+len) 范围为 patch 脏区 */
void wxshadow_mark_bp_dirty(struct wxshadow_page *page, unsigned long offset);  /* 标记断点偏移为脏（需写入 BRK 指令） */
void wxshadow_clear_bp_dirty(struct wxshadow_page *page, unsigned long offset); /* 清除断点偏移的脏标记（断点已删除） */
bool wxshadow_page_has_patch_dirty(struct wxshadow_page *page);            /* 检查页内是否存在未同步的 patch 脏区 */
void wxshadow_clear_page_tracking(struct wxshadow_page *page);             /* 清除页内所有跟踪位图 */
int wxshadow_restore_shadow_ranges(struct wxshadow_page *page);            /* 将 shadow 页脏区内容重新写入（用于 fork 后子进程恢复） */

/*
 * ========== 页表操作函数声明（wxshadow_pgtable.c） ==========
 *
 * 位置：wxshadow_pgtable.c 实现，供 wxshadow.c 和 wxshadow_handlers.c 调用。
 * 用途：完成 shadow 页的 PTE 级操作：查找/创建 PTE、切换页面状态、
 *       TLB 刷新、PMD 拆分、GUP 隐藏、子进程 PTE 恢复等。
 * 实现：直接操作内核页表（无内核页表锁，依赖 pte_lock 和 global_lock 序列化）。
 */

u64 *get_user_pte(void *mm, unsigned long addr, void **ptlp);  /* 获取用户地址的 PTE 指针（加锁，需配对 pte_unmap_unlock） */
int wxshadow_try_split_pmd(void *mm, void *vma, unsigned long addr); /* 若地址落在 THP PMD 中，强制拆分为 PTE 映射 */
void pte_unmap_unlock(u64 *pte, void *ptl);                    /* 解锁并 unmap get_user_pte 返回的 PTE */
void wxshadow_flush_tlb_page(void *vma, unsigned long uaddr);  /* 刷新用户地址的 TLB（按 tlb_flush_mode 选择方法） */
u64 make_pte(unsigned long pfn, u64 prot);                     /* 用 PFN 和权限位构造 PTE 值 */
int wxshadow_page_activate_shadow(struct wxshadow_page *page, void *vma,
                                  unsigned long addr);          /* 将 shadow 页设为 SHADOW_X 状态（--x 权限，触发 BRK） */
int wxshadow_page_activate_shadow_locked(struct wxshadow_page *page, void *vma,
                                         unsigned long addr);  /* 同上，调用者已持有 pte_lock */
int wxshadow_page_enter_original(struct wxshadow_page *page, void *vma,
                                 unsigned long addr);          /* 切换到 ORIGINAL 状态（r-- 权限，允许读取原始代码） */
int wxshadow_page_resume_shadow(struct wxshadow_page *page, void *vma,
                                unsigned long addr);           /* 从 ORIGINAL 状态恢复回 SHADOW_X 状态 */
int wxshadow_page_begin_stepping(struct wxshadow_page *page, void *vma,
                                 unsigned long addr, void *task); /* 切换到 STEPPING 状态（r-x 权限，执行原始指令） */
int wxshadow_page_finish_stepping(struct wxshadow_page *page, void *vma,
                                  unsigned long addr, void *task); /* 单步完成后切回 SHADOW_X 状态 */
int wxshadow_page_restore_original_for_teardown_locked(
    struct wxshadow_page *page, void *vma, unsigned long addr); /* 拆除前恢复原始 PTE（调用者已持有 pte_lock） */
int wxshadow_page_begin_gup_hide(struct wxshadow_page *page, void *mm,
                                 unsigned long addr, u64 **out_ptep,
                                 u64 *out_orig_pte);           /* GUP 隐藏开始：临时将 PTE 切换回原始页供 GUP 读取 */
int wxshadow_page_finish_gup_hide(struct wxshadow_page *page, void *vma,
                                  unsigned long addr, u64 *ptep,
                                  u64 orig_pte);               /* GUP 隐藏结束：恢复 shadow PTE */
int wxshadow_page_restore_child_original_locked(struct wxshadow_page *page,
                                                void *child_mm,
                                                unsigned long addr); /* fork 后为子进程恢复原始 PTE（子进程不继承 shadow） */
int wxshadow_page_enter_dormant_locked(struct wxshadow_page *page, void *vma,
                                       unsigned long addr);    /* 将页置入休眠状态（PTE 指回原始页，shadow 数据保留） */

/*
 * ========== Fork 保护 hook 函数声明（wxshadow_handlers.c） ==========
 *
 * 位置：wxshadow_handlers.c 实现，在模块初始化时注册到对应 hook 点。
 * 用途：拦截 fork/clone 流程，确保子进程不继承父进程的 shadow 页映射，
 *       防止子进程因持有 shadow PTE 而崩溃或产生安全漏洞。
 */

void before_dup_mmap_wx(hook_fargs2_t *args, void *udata);          /* dup_mmap 前置 hook：保存 fork 上下文 */
void after_dup_mmap_wx(hook_fargs2_t *args, void *udata);           /* dup_mmap 后置 hook：为子进程恢复原始 PTE */
void before_uprobe_dup_mmap_wx(hook_fargs2_t *args, void *udata);   /* uprobe_dup_mmap 前置 hook */
void after_uprobe_dup_mmap_wx(hook_fargs2_t *args, void *udata);    /* uprobe_dup_mmap 后置 hook */
void before_copy_process_wx(hook_fargs8_t *args, void *udata);      /* copy_process 前置 hook：标记父进程正在 fork */
void after_copy_process_wx(hook_fargs8_t *args, void *udata);       /* copy_process 后置 hook：清理 fork 标记 */

/*
 * ========== 页 fault / 异常处理函数声明（wxshadow_handlers.c） ==========
 *
 * 位置：wxshadow_handlers.c 实现，由 hook 框架在异常发生时调用。
 * 用途：拦截 do_page_fault、follow_page_pte（GUP）、exit_mmap、
 *       brk_handler（BRK 断点）和 single_step_handler（单步），
 *       实现 shadow/original/stepping 页面状态机的驱动逻辑。
 */

int wxshadow_handle_read_fault(void *mm, unsigned long addr);        /* 处理读权限 fault：切换至 ORIGINAL 页 */
int wxshadow_handle_exec_fault(void *mm, unsigned long addr);        /* 处理执行权限 fault：从 ORIGINAL 切回 SHADOW_X */
void do_page_fault_before(hook_fargs3_t *args, void *udata);         /* do_page_fault 前置 hook：拦截 shadow 页权限 fault */
void follow_page_pte_before(hook_fargs5_t *args, void *udata);       /* follow_page_pte 前置 hook：GUP 访问前临时暴露原始页 */
void follow_page_pte_after(hook_fargs5_t *args, void *udata);        /* follow_page_pte 后置 hook：GUP 完成后恢复 shadow PTE */
void exit_mmap_before(hook_fargs1_t *args, void *udata);             /* exit_mmap 前置 hook：进程退出时拆除所有 shadow 页 */
int wxshadow_brk_handler(struct pt_regs *regs, unsigned int esr);    /* BRK 异常处理：触发断点回调，切换到单步模式 */
int wxshadow_step_handler(struct pt_regs *regs, unsigned int esr);   /* 单步异常处理：完成原指令执行，切回 SHADOW_X */
void brk_handler_before(hook_fargs3_t *args, void *udata);           /* brk_handler 前置 hook：拦截 BRK #0x7 */
void single_step_handler_before(hook_fargs3_t *args, void *udata);   /* single_step_handler 前置 hook：拦截单步完成 */

/*
 * ========== 断点操作函数声明（wxshadow_bp.c） ==========
 *
 * 位置：wxshadow_bp.c 实现，由 prctl hook 调用。
 * 用途：实现 prctl 接口的核心操作——设置/删除断点、修改寄存器、
 *       自定义 patch、释放 shadow 页。
 */

int wxshadow_do_set_bp(void *mm, unsigned long addr);                /* 在 addr 处设置隐藏断点（写入 BRK 指令到 shadow 页） */
int wxshadow_do_set_reg(void *mm, unsigned long addr, unsigned int reg_idx, unsigned long value); /* 为断点添加寄存器修改规则 */
int wxshadow_do_del_bp(void *mm, unsigned long addr);                /* 删除 addr 处的断点（从 shadow 页移除 BRK 指令） */
int wxshadow_do_patch(void *mm, unsigned long addr, void __user *buf, unsigned long len); /* 将用户提供的字节序列 patch 到 shadow 页 */
int wxshadow_do_release(void *mm, unsigned long addr);               /* 释放 addr 所在 shadow 页，恢复进程原始映射 */
void prctl_before(hook_fargs4_t *args, void *udata);                 /* prctl 前置 hook：解析 PR_WXSHADOW_* 命令并分发 */

/*
 * ========== 扫描/符号解析函数声明（wxshadow_scan.c） ==========
 *
 * 位置：wxshadow_scan.c 实现，在模块 init 阶段调用。
 * 用途：动态检测内核版本相关的结构体偏移量和符号地址，
 *       使模块能跨内核版本运行。
 */

int resolve_symbols(void);               /* 通过 kallsyms 解析所有必须/可选内核符号，填充 kfunc_* 指针 */
int scan_mm_struct_offsets(void);        /* 扫描 mm_struct 的 context.id 等动态偏移量 */
int scan_vma_struct_offsets(void);       /* 扫描 vm_area_struct.vm_mm 等字段偏移量 */
int detect_task_struct_offsets(void);    /* 检测 task_struct.tasks_offset 和 mm_offset */
int try_scan_mm_context_id_offset(void); /* 尝试通过 TTBR0_EL1 ASID 匹配检测 mm_context_id_offset */
void debug_print_tasks_list(int max_count); /* 调试用：遍历并打印前 max_count 个进程的 comm 和 PID */

#endif /* _KPM_WXSHADOW_INTERNAL_H_ */
