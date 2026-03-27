/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory KPM Module
 * Copyright (C) 2024
 */
/*
 * 文件概述：wxshadow.h
 *
 * 本头文件是 W^X Shadow Memory KPM（内核补丁模块）的公共接口定义文件。
 * 该模块通过"影子页面"（Shadow Page）技术，在 ARM64 用户进程代码段设置
 * 对调试工具不可见的隐藏断点。
 *
 * 核心思路：
 *   - 为包含断点的页面分配一个"影子页"，将 BRK 指令写入其中；
 *   - 将用户进程的页表项（PTE）指向影子页，权限设为 --x（不可读、不可写、可执行）；
 *   - 进程读取该地址时，MMU 触发 fault，模块临时切回原始页（r--）供读取；
 *   - 进程执行该地址时，影子页的 BRK 被触发，模块处理断点逻辑，
 *     随后切换到原始页（r-x）执行原始指令，完成后再切回影子页。
 *
 * 本文件定义了以下内容（详见各节注释）：
 *   1. 页面大小常量
 *   2. 用户态控制接口（prctl 选项）
 *   3. TLB 刷新模式枚举
 *   4. BRK 指令相关常量
 *   5. 页面状态枚举
 *   6. 每断点寄存器修改结构体
 *   7. 每断点信息结构体
 *   8. 每补丁记录结构体
 *   9. 每页影子状态结构体（核心数据结构）
 *   10. BRK 处理钩子返回值
 *   11. 钩子方法枚举
 *   12. 断点/单步钩子结构体
 *   13. PTE 位定义
 */

#ifndef _KPM_WXSHADOW_H_
#define _KPM_WXSHADOW_H_

#include <ktypes.h>
#include <stdbool.h>

/*
 * 页面大小常量
 *
 * 用途：ARM64 标准 4K 页面的移位量、大小和对齐掩码。
 * 这些常量在模块内部用于页地址对齐、PFN 计算和影子页分配。
 * 当内核头文件中已有定义时，此处的定义可能被宏保护覆盖；
 * 此处显式定义是为了确保模块在裁剪内核环境下也能独立编译。
 */
/* Page size constants */
#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE - 1))

/*
 * 用户态控制接口——prctl 选项
 *
 * 用途：用户进程（或调试工具）通过 prctl(2) 系统调用向模块发送控制命令。
 * 模块在内部 hook 了 prctl 系统调用，识别以下 option 值后执行对应操作。
 *
 * 命名约定：0x5758 为 ASCII "WX" 的大写十六进制，后四位为命令序号。
 *
 * 用法示例：
 *   prctl(PR_WXSHADOW_SET_BP,  pid, addr, 0, 0);        // 在 addr 设置断点
 *   prctl(PR_WXSHADOW_SET_REG, pid, addr, reg_idx, val); // 断点触发时修改寄存器
 *   prctl(PR_WXSHADOW_DEL_BP,  pid, addr, 0, 0);        // 删除断点
 *   prctl(PR_WXSHADOW_PATCH,   pid, addr, buf, len);    // 写入影子页字节补丁
 *   prctl(PR_WXSHADOW_RELEASE, pid, addr, 0, 0);        // 释放影子页，恢复原始映射
 */
/* prctl options for wxshadow */
#define PR_WXSHADOW_SET_BP      0x57580001  /* WX + 1 */
#define PR_WXSHADOW_SET_REG     0x57580002  /* WX + 2 */
#define PR_WXSHADOW_DEL_BP      0x57580003  /* WX + 3 */
#define PR_WXSHADOW_SET_TLB_MODE 0x57580004 /* WX + 4: Set TLB flush mode */
#define PR_WXSHADOW_GET_TLB_MODE 0x57580005 /* WX + 5: Get TLB flush mode */
#define PR_WXSHADOW_PATCH       0x57580006  /* WX + 6: Patch shadow page via kernel VA */
#define PR_WXSHADOW_RELEASE     0x57580008  /* WX + 8: Release shadow */

/*
 * TLB 刷新模式枚举
 *
 * 用途：ARM64 中刷新 TLB 有多种粒度，不同内核版本和安全策略对可用指令有限制。
 * 本枚举允许用户/调试者根据目标内核能力和性能需求手动选择刷新策略，
 * 也可使用 AUTO 模式让模块自动选择最优策略。
 *
 * 各模式说明：
 *   AUTO      - 优先使用 ASID 精确刷新，若 mm_context_id_offset 未检测到则退化为广播
 *   PRECISE   - 使用 TLBI VALE1IS 指令，仅刷新目标 ASID+VA，性能最好，需要 ASID
 *   BROADCAST - 使用 TLBI VAALE1IS 指令，广播刷新所有 ASID 的该 VA
 *   FULL      - 使用 TLBI VMALLE1IS 指令，刷新整个 TLB，开销最大，兼容性最好
 */
/* TLB flush modes */
enum wxshadow_tlb_mode {
    WX_TLB_MODE_AUTO = 0,       /* 自动：有 ASID 时使用精确刷新，否则广播 */
    WX_TLB_MODE_PRECISE,        /* 精确：使用 ASID（TLBI VALE1IS），仅刷新目标地址 */
    WX_TLB_MODE_BROADCAST,      /* 广播：刷新所有 ASID 的该地址（TLBI VAALE1IS） */
    WX_TLB_MODE_FULL,           /* 全刷：刷新整个 TLB（TLBI VMALLE1IS），兼容性最佳 */
};

/*
 * BRK 指令相关常量
 *
 * 用途：ARM64 的 BRK 指令用于触发同步调试异常（ESR_ELx.EC = 0x3C）。
 * BRK 指令编码格式为：1101 0100 001x xxxx xxxx xxxx xxx0 0000，
 * 其中 imm16 字段（第5..20位）为立即数。
 *
 * WXSHADOW_BRK_IMM  = 0x7：选用立即数 7 作为模块专属标识，
 *                         内核 brk_handler 分发时用 imm 匹配对应处理器。
 * AARCH64_BREAK_MON = BRK 指令的基础编码（imm=0）。
 * WXSHADOW_BRK_INSN = 最终写入影子页的 BRK 指令机器码（小端 32 位）。
 * AARCH64_INSN_SIZE = AArch64 固定指令宽度 4 字节，用于偏移量计算。
 */
/* BRK immediate value */
#define WXSHADOW_BRK_IMM        0x007

/* BRK instruction encoding */
#define AARCH64_BREAK_MON       0xd4200000
#define WXSHADOW_BRK_INSN       (AARCH64_BREAK_MON | (WXSHADOW_BRK_IMM << 5))

/* Instruction size */
#define AARCH64_INSN_SIZE       4

/*
 * 影子页面状态枚举 wxshadow_state
 *
 * 用途：每个 wxshadow_page 在任意时刻处于以下五种状态之一，
 * 状态决定了用户态 VA 当前映射到哪个物理页以及对应的 PTE 权限。
 *
 * 状态转换简图：
 *   NONE ──(set_bp)──► SHADOW_X ◄──(step 完成)── STEPPING
 *                          │                          ▲
 *                    (BRK 触发)                  (BRK 处理)
 *                          │                          │
 *                          ▼                          │
 *                      ORIGINAL ──────────────────────┘
 *                          │
 *                    (logical release)
 *                          ▼
 *                       DORMANT
 *
 * 权限对照（ARM64 PTE）：
 *   SHADOW_X  → --x  (prot=0，即 PTE_USER 缺失，UXN=0)
 *   ORIGINAL  → r--  (PTE_USER | PTE_RDONLY | PTE_UXN)
 *   STEPPING  → r-x  (PTE_USER | PTE_RDONLY)
 */
/* Page states */
enum wxshadow_state {
    WX_STATE_NONE = 0,      /* 未分配影子页，页表项指向原始物理页 */
    WX_STATE_ORIGINAL,      /* VA 临时映射回原始页（r--），供读取或 fork 使用 */
    WX_STATE_SHADOW_X,      /* VA 映射到影子页（--x），执行时触发 BRK */
    WX_STATE_STEPPING,      /* BRK 已处理，VA 指向原始页（r-x）执行原始指令 */
    WX_STATE_DORMANT,       /* 钩子已退休：VA 恢复原始页，影子页保留备用 */
};

/*
 * 容量限制常量
 *
 * 用途：限制每个影子页上允许挂载的断点数量、补丁数量以及脏位图大小，
 * 防止内核内存被单个页面的条目无限消耗。
 *
 *   WXSHADOW_MAX_REG_MODS         - 每个断点最多可修改的寄存器数量（x0~x30 + sp）
 *   WXSHADOW_MAX_BPS_PER_PAGE     - 每个影子页最多可设置的断点数量
 *   WXSHADOW_MAX_PATCHES_PER_PAGE - 每个影子页最多可记录的补丁数量
 *   WXSHADOW_MAX_ACTIVE_MODS_PER_PAGE - 断点 + 补丁的总上限（用于序列号溢出检查）
 *   WXSHADOW_DIRTY_WORD_BITS      - 脏位图单个 word 的比特数（等于 unsigned long 位宽）
 *   WXSHADOW_DIRTY_BITMAP_WORDS   - 覆盖整个页面所需的 word 数量
 *                                   （用于 bp_dirty / patch_dirty 位图，每比特对应页内一个指令槽）
 */
/* Maximum register modifications per breakpoint */
#define WXSHADOW_MAX_REG_MODS       4

/* Maximum breakpoints per page */
#define WXSHADOW_MAX_BPS_PER_PAGE   128
#define WXSHADOW_MAX_PATCHES_PER_PAGE 128
#define WXSHADOW_MAX_ACTIVE_MODS_PER_PAGE \
    (WXSHADOW_MAX_BPS_PER_PAGE + WXSHADOW_MAX_PATCHES_PER_PAGE)
#define WXSHADOW_DIRTY_WORD_BITS    (sizeof(unsigned long) * 8)
#define WXSHADOW_DIRTY_BITMAP_WORDS \
    ((PAGE_SIZE + WXSHADOW_DIRTY_WORD_BITS - 1) / WXSHADOW_DIRTY_WORD_BITS)

/*
 * 寄存器修改条目 wxshadow_reg_mod
 *
 * 位置：嵌套在 wxshadow_bp 中，每个断点最多有 WXSHADOW_MAX_REG_MODS 个条目。
 * 用途：断点被触发（BRK 处理）后，在将 PC 推进到原始指令之前，
 *       按照此结构中的描述修改目标进程的通用寄存器，从而实现无侵入的参数拦截/篡改。
 * 实现：BRK 处理函数遍历所有 enabled=true 的条目，
 *       直接写入 pt_regs 对应字段，随后切换到 STEPPING 状态执行原始指令。
 */
/* Register modification entry */
struct wxshadow_reg_mod {
    u8 reg_idx;             /* 目标寄存器编号：0~30 对应 x0~x30，31 表示 sp */
    bool enabled;           /* 是否启用本条修改；false 表示该槽位空闲 */
    u64 value;              /* 断点触发时写入目标寄存器的值 */
};

/*
 * 断点信息结构体 wxshadow_bp
 *
 * 位置：内嵌于 wxshadow_page.bps[] 数组，每个影子页最多 WXSHADOW_MAX_BPS_PER_PAGE 个。
 * 用途：记录单个断点的位置、状态以及触发时的寄存器修改规则。
 *       模块在 BRK 处理路径中通过 addr 查找对应的 wxshadow_bp，
 *       然后依次应用 reg_mods[] 中的寄存器修改。
 * 实现：断点由 PR_WXSHADOW_SET_BP prctl 创建（active=true），
 *       由 PR_WXSHADOW_DEL_BP prctl 禁用（active=false），
 *       serial 用于记录该断点最后一次向影子页写入 BRK 的时序，
 *       避免多条目并发更新时顺序错乱。
 */
/* Per-breakpoint info */
struct wxshadow_bp {
    unsigned long addr;     /* 断点的用户态虚拟地址（4 字节对齐） */
    bool active;            /* 断点是否处于激活状态；false 表示该槽位空闲 */
    u64 serial;             /* 本断点最近一次写入影子页的单调序号，用于冲突检测 */
    struct wxshadow_reg_mod reg_mods[WXSHADOW_MAX_REG_MODS]; /* 寄存器修改条目数组 */
    int nr_reg_mods;        /* 已启用的寄存器修改条目数量 */
};

/*
 * 补丁记录结构体 wxshadow_patch
 *
 * 位置：内嵌于 wxshadow_page.patches[] 数组，每个影子页最多 WXSHADOW_MAX_PATCHES_PER_PAGE 个。
 * 用途：记录通过 PR_WXSHADOW_PATCH prctl 写入影子页的任意字节补丁（非 BRK 断点）。
 *       补丁可用于实现 NOP、跳转、返回值伪造等不依赖断点的静态代码修改。
 * 实现：补丁内容存储在 data 指针指向的 len 字节缓冲区（内核分配），
 *       offset 为页内字节偏移，serial 与 wxshadow_bp.serial 共用单调计数器，
 *       确保多次 patch 操作按顺序应用到影子页。
 *       注意：单次 patch 不能跨越页边界（offset + len <= PAGE_SIZE）。
 */
struct wxshadow_patch {
    u16 offset;             /* 补丁在页内的起始字节偏移（0 ~ PAGE_SIZE-1） */
    u16 len;                /* 补丁数据的字节长度 */
    bool active;            /* 是否为有效补丁记录；false 表示该槽位空闲 */
    u64 serial;             /* 本补丁最近一次写入影子页的单调序号 */
    void *data;             /* 指向补丁字节数据的内核内存指针（长度为 len 字节） */
};

/* Per-page shadow info (dynamically allocated per breakpoint page) */
/* Note: struct list_head is defined in linux/list.h (KP framework) */
/*
 * 核心数据结构 wxshadow_page
 *
 * 位置：模块维护一个全局链表 page_list，每个挂有断点或补丁的用户代码页
 *       对应链表中的一个 wxshadow_page 节点。
 * 用途：集中记录某一用户页面的全部影子状态，包括：
 *       原始页与影子页的物理帧号（PFN）、当前页面状态、所有断点和补丁信息、
 *       以及用于安全并发访问的引用计数和生命周期标志。
 * 实现：
 *   - 结构体在 set_bp/patch 时由 kzalloc 分配，挂入 page_list；
 *   - 所有对链表和状态字段的访问受 global_lock（spinlock）保护；
 *   - PTE 切换操作在锁外进行，由 pte_lock（原子自旋）序列化；
 *   - 通过引用计数（refcount）确保 BRK/step 处理函数持有引用期间结构体不被释放；
 *   - 卸载/释放时通过 dead/release_pending 等标志协调异步清理。
 */
struct wxshadow_page {
    struct list_head list;          /* 链入全局 page_list 的链表节点 */
    void *mm;                       /* 所属进程的 mm_struct 指针（用于 PTE 查找和 TLB 刷新） */
    unsigned long page_addr;        /* 该页的用户态起始地址（PAGE_SIZE 对齐，用于查找） */

    unsigned long pfn_original;     /* 原始代码页的物理帧号（PFN） */
    u64 pte_original;               /* 捕获到影子页之前的原始用户 PTE 快照，用于恢复 */
    unsigned long pfn_shadow;       /* 影子页的物理帧号（PFN） */
    void *shadow_page;              /* 影子页的内核虚拟地址（由 __get_free_pages 分配，用于 free） */
    enum wxshadow_state state;      /* 当前页面状态（见 wxshadow_state 枚举） */
    void *stepping_task;            /* 正在执行单步的任务指针（struct task_struct *），NULL 表示无 */
    int brk_in_flight;              /* 处于 BRK 陷入与进入 STEPPING 之间的处理器数量（多核保护） */

    /*
     * Lifecycle fields (protected by global_lock):
     *   refcount: 1 while in page_list (list's ref); each find_page/find_by_addr
     *             caller increments before releasing the lock and must call
     *             wxshadow_page_put() when done.  Struct is kfree'd when it
     *             reaches 0.
     *   dead:     set to true when the page is removed from page_list.
     *             Handlers that obtained a ref before removal must check this
     *             flag and skip any PTE-switch-to-shadow operations.
     *   release_pending:
     *             set when user/module teardown arrives while a task is in the
     *             STEPPING state.  The page stays in page_list so the step
     *             handler can finalize the teardown after the original
     *             instruction retires.
     *   logical_release_pending:
     *             set when a user-facing release wants to retire the hook
     *             without tearing down the page.  The step handler switches the
     *             page into DORMANT once the original instruction retires.
     *   fork_paused:
     *             set while copy_process is cloning the parent's mm.  The
     *             parent PTE is temporarily restored to the original page so
     *             the child never inherits the shadow PFN; after copy_process
     *             returns, the parent mapping is switched back to shadow.
     */
    /*
     * 生命周期字段（均受 global_lock 保护）：
     *
     *   refcount               - 引用计数。页面在 page_list 中时初始为 1（链表持有一个引用）；
     *                            find_page/find_by_addr（见 wxshadow_internal.h）的调用方
     *                            在释放锁之前必须递增计数，使用完毕后调用
     *                            wxshadow_page_put() 归还引用。
     *                            计数归零时 kfree 本结构体。
     *   dead                   - 当页面从 page_list 移除时置 true。
     *                            已在锁释放前获得引用的处理函数必须检查此标志，
     *                            跳过任何"切回影子页"的 PTE 操作。
     *   release_pending        - 当用户/模块发起拆卸时目标任务正处于 STEPPING 状态时置 true。
     *                            页面保留在 page_list 中，待单步处理函数在原始指令退休后
     *                            完成最终清理。
     *   logical_release_pending - 当用户侧 release 希望退休钩子但不立即销毁页面时置 true。
     *                            单步处理函数在原始指令退休后将页面切换到 DORMANT 状态。
     *   fork_paused            - copy_process 克隆父进程 mm 期间置 true。
     *                            父进程 PTE 临时恢复到原始页，避免子进程继承影子 PFN；
     *                            copy_process 返回后父进程映射切回影子页。
     */
    int  refcount;                /* 引用计数，降为 0 时 kfree 本结构 */
    bool dead;                    /* true 表示已从链表移除，处理函数应跳过切影子 PTE */
    bool release_pending;         /* true 表示拆卸时有任务正在单步，待单步完成后清理 */
    bool logical_release_pending; /* true 表示逻辑 release 待单步完成后切入 DORMANT */
    bool fork_paused;             /* true 表示 fork 克隆期间 PTE 已临时切回原始页 */
    atomic_t pte_lock;            /* 原子自旋锁，序列化对本页 PTE 的并发改写 */

    /* Breakpoint info */
    struct wxshadow_bp bps[WXSHADOW_MAX_BPS_PER_PAGE]; /* 断点信息数组 */
    int nr_bps;                     /* 当前已注册的断点数量（active 条目数） */
    struct wxshadow_patch patches[WXSHADOW_MAX_PATCHES_PER_PAGE]; /* 补丁记录数组 */
    int nr_patches;                 /* 当前已注册的补丁数量（active 条目数） */
    u64 next_mod_serial;            /* 下一次写入影子页时使用的单调递增序号 */
    unsigned long bp_dirty[WXSHADOW_DIRTY_BITMAP_WORDS];    /* 断点位图：标记哪些指令槽写有 BRK */
    unsigned long patch_dirty[WXSHADOW_DIRTY_BITMAP_WORDS]; /* 补丁位图：标记哪些字节槽被补丁覆盖 */
};

/*
 * BRK/单步钩子处理函数的返回值
 *
 * 用途：ARM64 内核的 brk_handler 和 single_step_handler 分发机制
 *       通过返回值判断该异常是否已被某个处理器消费。
 *       模块的钩子函数必须返回以下之一：
 *         DBG_HOOK_HANDLED - 异常已处理，内核无需继续分发给其他处理器；
 *         DBG_HOOK_ERROR   - 本模块不处理该异常，继续向下分发。
 */
/* BRK handler return values */
#define DBG_HOOK_HANDLED    0   /* 异常已被本模块处理，停止分发 */
#define DBG_HOOK_ERROR      1   /* 异常未被处理，继续分发给下一个处理器 */

/*
 * 钩子方法枚举 wx_hook_method
 *
 * 用途：模块可以通过两种方式拦截 BRK 和单步异常处理函数：
 *   1. 直接 hook（DIRECT）：利用 KernelPatch 的 hook_wrap 直接替换
 *      brk_handler / single_step_handler 函数入口，性能最优；
 *   2. 注册 API（REGISTER）：调用内核提供的 register_user_break_hook /
 *      register_user_step_hook 接口，兼容性更好，作为降级备选方案。
 *
 * 模块在初始化时尝试直接 hook；若符号解析失败则自动退化到 REGISTER 方法。
 */
/* Hook method selection */
enum wx_hook_method {
    WX_HOOK_METHOD_NONE = 0,        /* 未初始化或未选择任何钩子方法 */
    WX_HOOK_METHOD_DIRECT,          /* 直接 hook 函数入口（优先，性能最佳） */
    WX_HOOK_METHOD_REGISTER,        /* 通过 register_user_*_hook API 注册（降级备选） */
};

/*
 * struct break_hook - for register_user_break_hook API
 * Must match kernel's struct break_hook layout (arch/arm64/include/asm/debug-monitors.h)
 */
/*
 * BRK 钩子结构体 wx_break_hook
 *
 * 用途：当钩子方法为 WX_HOOK_METHOD_REGISTER 时，模块填充此结构体并调用
 *       register_user_break_hook() 向内核注册 BRK 异常处理器。
 *       内核 brk_handler 遍历已注册的 break_hook 链表，按 imm & mask 匹配
 *       ESR 中的立即数字段，匹配时调用 fn 回调。
 *
 * 注意：本结构体必须与内核 arch/arm64/include/asm/debug-monitors.h 中的
 *       struct break_hook 内存布局完全一致，否则会产生严重的内存错误。
 */
struct wx_break_hook {
    struct list_head node; /* 链入内核 break_hook 链表的节点 */
    int (*fn)(struct pt_regs *regs, unsigned int esr); /* BRK 触发时的回调函数 */
    u16 imm;               /* 需要匹配的 BRK 立即数值（对应 WXSHADOW_BRK_IMM） */
    u16 mask;              /* 立即数匹配掩码（0xffff 表示精确匹配） */
};

/*
 * struct step_hook - for register_user_step_hook API
 * Must match kernel's struct step_hook layout (arch/arm64/include/asm/debug-monitors.h)
 */
/*
 * 单步钩子结构体 wx_step_hook
 *
 * 用途：当钩子方法为 WX_HOOK_METHOD_REGISTER 时，模块填充此结构体并调用
 *       register_user_step_hook() 向内核注册单步异常处理器。
 *       在 STEPPING 状态下原始指令执行完毕后，单步异常触发，
 *       模块的 fn 回调负责将页面切回 WX_STATE_SHADOW_X 状态。
 *
 * 注意：本结构体必须与内核 arch/arm64/include/asm/debug-monitors.h 中的
 *       struct step_hook 内存布局完全一致。
 */
struct wx_step_hook {
    struct list_head node; /* 链入内核 step_hook 链表的节点 */
    int (*fn)(struct pt_regs *regs, unsigned int esr); /* 单步完成时的回调函数 */
};

/*
 * ARM64 页表项（PTE）位定义
 *
 * 用途：模块在切换影子页/原始页时需要手工构造 PTE 值，设置不同的权限位
 *       以实现 --x / r-- / r-x 三种访问权限。
 *       这些宏在标准内核头文件（arch/arm64/include/asm/pgtable.h）中已有定义，
 *       此处使用 #ifndef 保护，仅在编译环境缺少这些定义时才补充，
 *       避免与内核头文件冲突。
 *
 * 各位字段说明（ARMv8-A Stage 1 描述符，4K 粒度）：
 *   PTE_VALID        [0]    - 描述符有效位（1=有效）
 *   PTE_TYPE_PAGE    [1:0]  - 描述符类型（3=页描述符）
 *   PTE_USER         [6]    - EL0（用户态）可访问位（AP[1]）
 *   PTE_RDONLY       [7]    - 只读位（AP[2]，1=只读）
 *   PTE_SHARED       [9:8]  - 共享属性（3=ISH 内部共享）
 *   PTE_AF           [10]   - 访问标志（Access Flag，1=已访问）
 *   PTE_NG           [11]   - 非全局位（1=仅当前 ASID 有效，影响 TLB 刷新）
 *   PTE_UXN          [54]   - 用户态执行禁止（1=禁止 EL0 执行）
 *   PTE_ATTRINDX_NORMAL [4:2] - 内存属性索引（0=Normal Memory，对应 MAIR 槽位 0）
 */
/* PTE bits - use pgtable.h definitions if available */
#ifndef PTE_VALID
#define PTE_VALID           (1UL << 0)   /* 描述符有效位 */
#endif
#ifndef PTE_TYPE_PAGE
#define PTE_TYPE_PAGE       (3UL << 0)   /* 页描述符类型标识（bit[1:0]=11） */
#endif
#ifndef PTE_USER
#define PTE_USER            (1UL << 6)   /* 用户态（EL0）可访问位 AP[1] */
#endif
#ifndef PTE_RDONLY
#define PTE_RDONLY          (1UL << 7)   /* 只读位 AP[2]，置 1 时禁止写入 */
#endif
#ifndef PTE_SHARED
#define PTE_SHARED          (3UL << 8)   /* 内部共享属性（ISH），多核缓存一致性 */
#endif
#ifndef PTE_AF
#define PTE_AF              (1UL << 10)  /* 访问标志，首次访问由硬件或软件置位 */
#endif
#ifndef PTE_NG
#define PTE_NG              (1UL << 11)  /* 非全局位，置 1 时 TLB 条目携带 ASID */
#endif
#ifndef PTE_UXN
#define PTE_UXN             (1UL << 54)  /* 用户态执行禁止位，置 1 时 EL0 不可执行 */
#endif
/* Memory attribute index for normal memory */
#ifndef PTE_ATTRINDX_NORMAL
#define PTE_ATTRINDX_NORMAL (0UL << 2)   /* MAIR 内存属性索引 0（Normal Memory） */
#endif

#endif /* _KPM_WXSHADOW_H_ */
