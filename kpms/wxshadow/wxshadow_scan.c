/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory KPM Module - Symbol Resolution and Offset Scanning
 *
 * Kernel symbol resolution, mm_struct/vma/task_struct offset detection.
 *
 * Copyright (C) 2024
 */

/*
 * 文件概述：wxshadow_scan.c
 *
 * 本文件负责模块启动时所有必要的内核符号解析与运行时偏移量探测，是
 * wxshadow 模块正常工作的基础。主要包含以下功能：
 *
 *  1. 安全符号查找 (lookup_name_safe)
 *     仅遍历 vmlinux 符号表，规避 module_kallsyms_lookup_name 在某些内核
 *     上遍历模块链表时可能发生的死锁。
 *
 *  2. 内核符号批量解析 (resolve_symbols)
 *     按 14 个分组解析内存管理、页分配、地址转换、页表操作、缓存维护、
 *     单步调试、BRK/单步 hook、RCU、内存分配等所需函数指针；
 *     同时通过 TCR_EL1 确定页表配置（page_shift / page_level），
 *     并利用 AT 指令探测 physvirt_offset 偏移。
 *
 *  3. mm_struct 偏移扫描 (scan_mm_struct_offsets)
 *     使用 KP 框架已检测好的 mm_struct_offset.pgd_offset，直接读取即可。
 *
 *  4. vm_area_struct 偏移扫描 (scan_vma_struct_offsets)
 *     在当前进程的 mm 上遍历 VMA，通过比对 mm 指针定位 vm_mm 字段偏移
 *     (VMA_VM_MM_OFFSET)。
 *
 *  5. task_struct 偏移探测 (detect_task_struct_offsets)
 *     沿任务链表查找 tasks_offset；利用框架提供的 active_mm_offset
 *     推导 mm_offset（active_mm - 8）；验证结果完整性。
 *
 *  6. mm->context.id 偏移扫描 (try_scan_mm_context_id_offset)
 *     优先通过 init 进程的 vdso ELF magic 定位 context.id 字段；
 *     若失败则回退到读取 TTBR0_EL1 ASID 进行匹配；
 *     均失败时延迟到首次 prctl 调用时重试。
 *     context.id 用于 TLBI 指令的 ASID 操作数（TLB 刷新回退方案）。
 *
 *  7. 调试辅助 (debug_print_tasks_list)
 *     遍历并打印进程列表，供调试时确认偏移量正确性。
 */

#include "wxshadow_internal.h"

/* 缓存 init 进程 (pid 1) 的 task_struct 指针，供 mm->context.id 扫描等例程复用 */
static void *wx_init_process = NULL;

/*
 * ========== 安全符号查找（仅搜索 vmlinux，不遍历内核模块）==========
 *
 * 背景：kallsyms_lookup_name() 在找不到符号时会继续调用
 *   module_kallsyms_lookup_name()，后者遍历已加载模块的符号表，在部分内核
 *   版本上持有 module_mutex 期间可能产生死锁或长时间阻塞。
 *
 * 解决方案：使用 kallsyms_on_each_symbol() 仅遍历 vmlinux 内置符号，
 *   找到即停，完全跳过模块符号遍历。
 */

/*
 * lookup_data - 符号查找回调的上下文数据
 * @name:  待查找的符号名称字符串
 * @addr:  查找成功后存放符号地址的字段；初始为 0
 */
struct lookup_data {
    const char *name;
    unsigned long addr;
};

/*
 * lookup_callback - kallsyms_on_each_symbol 的迭代回调函数
 *
 * 每次被调用时比较当前符号名与目标名，匹配则保存地址并返回 1 停止迭代。
 * 返回 0 继续遍历，返回非零值终止遍历。
 */
static int lookup_callback(void *data, const char *name, struct module *mod, unsigned long addr)
{
    struct lookup_data *ld = data;
    if (strcmp(name, ld->name) == 0) {
        ld->addr = addr;
        return 1; /* stop iteration */
    }
    return 0;
}

/*
 * lookup_name_safe - 仅在 vmlinux 符号表中查找符号地址
 *
 * 位置：安全符号查找层，被 resolve_symbols() 及所有符号解析调用路径使用。
 * 用途：规避 kallsyms_lookup_name 在符号不存在时触发模块符号遍历造成的
 *       死锁风险；同时也能处理 kallsyms_lookup_name 未导出的内核版本。
 * 实现：通过 kallsyms_on_each_symbol 逐个比较符号名，一旦匹配立即停止，
 *       找不到时返回 0。
 *
 * @name: 目标符号名称（C 字符串）
 * 返回值：符号内核虚拟地址；未找到时返回 0。
 */
static unsigned long lookup_name_safe(const char *name)
{
    struct lookup_data ld = { .name = name, .addr = 0 };

    if (kallsyms_on_each_symbol) {
        kallsyms_on_each_symbol(lookup_callback, &ld);
    }
    return ld.addr;
}

/* ========== 符号解析宏 ========== */

/*
 * RESOLVE_SYMBOL - 解析必要内核符号的宏
 *
 * 通过 lookup_name_safe 查找 vmlinux 符号，并将结果赋值给对应的函数指针
 * kfunc_<name>。若符号不存在则打印错误并让调用函数返回 -1，
 * 表示模块无法正常加载。
 * 所有符号解析均使用 lookup_name_safe 以避免模块遍历死锁。
 */
#define RESOLVE_SYMBOL(name) \
    do { \
        kfunc_##name = (typeof(kfunc_##name))lookup_name_safe(#name); \
        if (!kfunc_##name) { \
            pr_err("wxshadow: failed to find symbol: %s\n", #name); \
            return -1; \
        } \
    } while (0)

/*
 * RESOLVE_SYMBOL_OPTIONAL - 解析可选内核符号的宏
 *
 * 与 RESOLVE_SYMBOL 相同，但符号不存在时不报错、不退出，
 * 允许相应功能在运行时降级（如 THP 分裂、follow_page_pte 等可选路径）。
 */
#define RESOLVE_SYMBOL_OPTIONAL(name) \
    do { \
        kfunc_##name = (typeof(kfunc_##name))lookup_name_safe(#name); \
    } while (0)

/*
 * ========== 内核符号批量解析 ==========
 *
 * 位置：模块初始化阶段，在任何 hook 或页表操作之前调用。
 * 用途：wxshadow 的所有核心功能（hook 安装、shadow 页管理、TLB 刷新、
 *       进程监控等）都依赖于对内核函数的间接调用；本函数集中完成全部
 *       函数指针的解析，使后续代码可直接通过 kfunc_xxx 调用内核函数。
 * 实现：按功能分 14 个小节依次解析符号；对于有多种可能名称的符号（如
 *       icache flush、copy_from_user 等）采用降级策略逐一尝试。
 *       此外还通过读取 TCR_EL1 系统寄存器确定页表层级与页大小，
 *       并分配一个测试页用 AT 指令验证 physvirt_offset。
 *
 * 返回值：0 表示成功；负值表示必要符号缺失，模块拒绝加载。
 */
int resolve_symbols(void)
{
    pr_info("wxshadow: resolving symbols...\n");

    /* ===== 内存管理函数（均为内核导出符号）===== */
    pr_info("wxshadow: [1/12] mm functions...\n");
    RESOLVE_SYMBOL(find_vma);    /* 在 mm 中查找覆盖给定地址的 VMA */
    RESOLVE_SYMBOL(get_task_mm); /* 引用计数递增后获取进程的 mm_struct */
    RESOLVE_SYMBOL(mmput);       /* 释放 get_task_mm 增加的引用计数 */
    /* find_task_by_vpid: use wxfunc(find_task_by_vpid) */

    /* exit_mmap - required, for proper cleanup on process exit */
    kfunc_exit_mmap = (void *)lookup_name_safe("exit_mmap");
    if (kfunc_exit_mmap) {
        pr_info("wxshadow: exit_mmap found at %px\n", kfunc_exit_mmap);
    } else {
        pr_err("wxshadow: exit_mmap not found, refusing to load without exit cleanup\n");
        return -ESRCH;
    }

    /* ===== 物理页分配与释放 ===== */
    pr_info("wxshadow: [2/12] page alloc...\n");
    kfunc___get_free_pages = (typeof(kfunc___get_free_pages))
        lookup_name_safe("__get_free_pages"); /* 分配 2^order 个物理页并返回内核虚拟地址 */
    if (!kfunc___get_free_pages) {
        pr_err("wxshadow: __get_free_pages not found\n");
        return -1;
    }

    pr_info("wxshadow: [3/12] page free...\n");
    kfunc_free_pages = (typeof(kfunc_free_pages))lookup_name_safe("free_pages"); /* 释放 __get_free_pages 分配的页 */
    if (!kfunc_free_pages) {
        pr_err("wxshadow: free_pages not found\n");
        return -1;
    }

    /* ===== 地址转换：memstart_addr / physvirt_offset / PAGE_OFFSET ===== */
    pr_info("wxshadow: [5/12] address translation...\n");
    kvar_memstart_addr = (s64 *)lookup_name_safe("memstart_addr"); /* 物理内存起始地址，用于 phys↔virt 转换 */
    if (!kvar_memstart_addr) {
        pr_err("wxshadow: memstart_addr not found\n");
        return -1;
    }
    pr_info("wxshadow: memstart_addr=%px, value=0x%llx\n",
            kvar_memstart_addr, *kvar_memstart_addr);

    kvar_physvirt_offset = (s64 *)lookup_name_safe("physvirt_offset"); /* KASLR 模式下的物理-虚拟偏移量，非 KASLR 内核可能不存在 */
    if (kvar_physvirt_offset) {
        pr_info("wxshadow: physvirt_offset=%px, value=0x%llx (KASLR mode)\n",
                kvar_physvirt_offset, *kvar_physvirt_offset);
    } else {
        pr_info("wxshadow: physvirt_offset not found, using traditional memstart_addr mode\n");
    }

    /* 根据 TCR_EL1.T1SZ 确定内核地址空间的 PAGE_OFFSET */
    {
        u64 tcr_el1_tmp;
        u64 t1sz_tmp, va_bits_tmp;
        unsigned long page_offset_mask;

        asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1_tmp)); /* 读取内核地址翻译控制寄存器 */
        t1sz_tmp = (tcr_el1_tmp >> 16) & 0x3f;  /* T1SZ: 内核地址空间大小字段，决定 VA 位数 */
        va_bits_tmp = 64 - t1sz_tmp;             /* 内核虚拟地址有效位数 */

        page_offset_base = ~0UL << (va_bits_tmp - 1); /* 内核线性映射基地址（PAGE_OFFSET 初始估算） */

        {
            unsigned long kaddr = (unsigned long)lookup_name_safe("_stext"); /* 内核文本段起始地址，用于交叉验证 PAGE_OFFSET */
            if (kaddr) {
                page_offset_mask = ~0UL << (va_bits_tmp - 1);
                if ((kaddr & page_offset_mask) != page_offset_base) {
                    pr_warn("wxshadow: PAGE_OFFSET mismatch! calculated=0x%lx, from _stext=0x%lx\n",
                            page_offset_base, kaddr & page_offset_mask);
                    page_offset_base = kaddr & page_offset_mask;
                }
                pr_info("wxshadow: PAGE_OFFSET=0x%lx (va_bits=%lld, _stext=0x%lx)\n",
                        page_offset_base, va_bits_tmp, kaddr);
            } else {
                pr_info("wxshadow: PAGE_OFFSET=0x%lx (va_bits=%lld, calculated)\n",
                        page_offset_base, va_bits_tmp);
            }
        }
    }

    /* 使用 AT S1E1R 指令探测真实 physvirt_offset（比读取符号更可靠）*/
    {
        unsigned long test_vaddr = kfunc___get_free_pages(0xcc0, 0); /* 分配一个测试物理页 */
        if (test_vaddr) {
            unsigned long real_paddr = vaddr_to_paddr_at(test_vaddr); /* 通过 AT 指令将内核 VA 翻译为 PA */
            if (real_paddr) {
                detected_physvirt_offset = (s64)test_vaddr - (s64)real_paddr; /* 计算运行时 physvirt 偏移 */
                physvirt_offset_valid = 1; /* 标记偏移已通过 AT 指令验证，可信 */
                pr_info("wxshadow: AT translation: vaddr=%lx -> paddr=%lx\n",
                        test_vaddr, real_paddr);
                pr_info("wxshadow: detected physvirt_offset = 0x%llx\n",
                        detected_physvirt_offset);

                unsigned long test_vaddr2 = phys_to_virt_safe(real_paddr);
                pr_info("wxshadow: round-trip test: paddr=%lx -> vaddr=%lx (match=%d)\n",
                        real_paddr, test_vaddr2, test_vaddr == test_vaddr2);
            } else {
                pr_err("wxshadow: AT instruction failed for vaddr=%lx\n", test_vaddr);
            }
            kfunc_free_pages(test_vaddr, 0);
        }
    }

    /* ===== 页表配置：从 TCR_EL1 读取页大小（TG1）和翻译层数 ===== */
    pr_info("wxshadow: [6/12] page table ops...\n");

    {
        u64 tcr_el1;
        u64 t1sz, tg1, va_bits;
        asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1)); /* 读取翻译控制寄存器 EL1 */

        t1sz = (tcr_el1 >> 16) & 0x3f;  /* 内核地址空间大小控制字段 */
        va_bits = 64 - t1sz;             /* 内核 VA 有效位数 */

        tg1 = (tcr_el1 >> 30) & 0x3;    /* TG1: 内核侧页粒度，0x1=16KB, 0x2=4KB, 0x3=64KB */
        wx_page_shift = 12;              /* 默认 4KB 页（2^12） */
        if (tg1 == 1) {
            wx_page_shift = 14;          /* 16KB 页（2^14） */
        } else if (tg1 == 3) {
            wx_page_shift = 16;          /* 64KB 页（2^16） */
        }

        /* 根据 VA 位数与页粒度计算页表层数（用于确定 PGD/PUD/PMD/PTE 层级）*/
        wx_page_level = (va_bits - 4) / (wx_page_shift - 3);

        pr_info("wxshadow: TCR_EL1=0x%llx, va_bits=%lld, page_shift=%d, page_level=%d\n",
                tcr_el1, va_bits, wx_page_shift, wx_page_level);
    }

    /* Spinlock and task functions - using lookup_name_safe */
    wx__raw_spin_lock = (typeof(wx__raw_spin_lock))lookup_name_safe("_raw_spin_lock");     /* 原始自旋锁加锁 */
    wx__raw_spin_unlock = (typeof(wx__raw_spin_unlock))lookup_name_safe("_raw_spin_unlock"); /* 原始自旋锁解锁 */
    wx_find_task_by_vpid = (typeof(wx_find_task_by_vpid))lookup_name_safe("find_task_by_vpid"); /* 按虚拟 PID 查找 task_struct */
    wx___task_pid_nr_ns = (typeof(wx___task_pid_nr_ns))lookup_name_safe("__task_pid_nr_ns");   /* 获取进程在指定 ns 的 PID/TGID */
    if (!wxfunc(_raw_spin_lock) || !wxfunc(_raw_spin_unlock) ||
        !wxfunc(find_task_by_vpid) || !wxfunc(__task_pid_nr_ns)) {
        pr_err("wxshadow: required kernel functions not found\n");
        return -1;
    }

    /* init_task - 通过 lookup_name_safe 获取（框架未直接导出该地址） */
    wx_init_task = (struct task_struct *)lookup_name_safe("init_task");
    if (!wx_init_task) {
        pr_err("wxshadow: init_task not found\n");
        return -1;
    }
    pr_info("wxshadow: wx_init_task at %px\n", wx_init_task);

    /* TLB 刷新函数解析：优先 flush_tlb_page，降级 __flush_tlb_range，最终回退到 TLBI 汇编指令 */
    kfunc_flush_tlb_page = (typeof(kfunc_flush_tlb_page))
        lookup_name_safe("flush_tlb_page"); /* 按页粒度刷新 TLB（首选） */
    if (kfunc_flush_tlb_page) {
        pr_info("wxshadow: flush_tlb_page at %px\n", kfunc_flush_tlb_page);
    } else {
        /* flush_tlb_page is inline on some kernels, try __flush_tlb_range */
        kfunc___flush_tlb_range = (typeof(kfunc___flush_tlb_range))
            lookup_name_safe("__flush_tlb_range"); /* 按地址范围刷新 TLB（第二选择） */
        if (kfunc___flush_tlb_range) {
            pr_info("wxshadow: using __flush_tlb_range at %px (fallback)\n", kfunc___flush_tlb_range);
        } else {
            /* Neither found - will use TLBI instruction fallback */
            pr_warn("wxshadow: neither flush_tlb_page nor __flush_tlb_range found\n");
            pr_info("wxshadow: will use TLBI instruction fallback (requires mm->context.id detection)\n");
        }
    }

    /* ===== 透明大页（THP）拆分，可选 ===== */
    kfunc___split_huge_pmd = (typeof(kfunc___split_huge_pmd))
        lookup_name_safe("__split_huge_pmd"); /* 将巨页 PMD 拆分为普通页，操作前需确保非大页 */
    if (kfunc___split_huge_pmd) {
        pr_info("wxshadow: __split_huge_pmd at %px\n", kfunc___split_huge_pmd);
    } else {
        pr_info("wxshadow: __split_huge_pmd not found (THP disabled or inlined)\n");
    }

    /* ===== 缓存一致性操作 ===== */
    pr_info("wxshadow: [7/12] cache ops...\n");
    RESOLVE_SYMBOL(flush_dcache_page); /* 将 D-Cache 中修改的页刷新到内存，写入 shadow 内容后必须调用 */

    /* icache 刷新：尝试多个可能的符号名，各内核版本不同 */
    kfunc___flush_icache_range = (typeof(kfunc___flush_icache_range))
        lookup_name_safe("__flush_icache_range"); /* 首选：刷新指令缓存区间 */
    if (!kfunc___flush_icache_range) {
        kfunc___flush_icache_range = (typeof(kfunc___flush_icache_range))
            lookup_name_safe("flush_icache_range"); /* 第二候选 */
    }
    if (!kfunc___flush_icache_range) {
        kfunc___flush_icache_range = (typeof(kfunc___flush_icache_range))
            lookup_name_safe("__flush_cache_user_range"); /* 第三候选（用户空间缓存刷新） */
    }
    if (!kfunc___flush_icache_range) {
        kfunc___flush_icache_range = (typeof(kfunc___flush_icache_range))
            lookup_name_safe("invalidate_icache_range"); /* 第四候选（某些 vendor 内核使用此名） */
    }
    if (kfunc___flush_icache_range) {
        pr_info("wxshadow: using kernel icache flush at %px\n", kfunc___flush_icache_range);
    } else {
        pr_info("wxshadow: using built-in icache flush (dc cvau + ic ialluis)\n");
    }

    /* ===== 单步调试支持函数 ===== */
    pr_info("wxshadow: [8/12] debug/single-step...\n");
    kfunc_user_enable_single_step = (typeof(kfunc_user_enable_single_step))
        lookup_name_safe("user_enable_single_step");  /* 在断点触发后为目标线程开启单步模式 */
    kfunc_user_disable_single_step = (typeof(kfunc_user_disable_single_step))
        lookup_name_safe("user_disable_single_step"); /* 单步执行完原始指令后关闭单步模式 */
    if (!kfunc_user_enable_single_step || !kfunc_user_disable_single_step) {
        pr_err("wxshadow: single step functions not found\n");
        return -1;
    }

    /* ===== BRK / 单步 Hook 目标函数 =====
     *
     * 提供两种实现方式供 wxshadow_init 按优先级选择：
     *   方式 A（直接 hook）：hook brk_handler / single_step_handler 函数入口
     *   方式 B（注册 API）：调用 register_user_break_hook / register_user_step_hook
     *
     * 两种方式至少需要一种可用，否则无法捕获断点事件。
     */
    pr_info("wxshadow: [9/12] BRK/step hooks...\n");

    /* Resolve all symbols - let wxshadow_init decide priority */
    /* Direct hook symbols */
    kfunc_brk_handler = (void *)lookup_name_safe("brk_handler");             /* BRK 异常处理函数（直接 hook 目标） */
    kfunc_single_step_handler = (void *)lookup_name_safe("single_step_handler"); /* 单步异常处理函数（直接 hook 目标） */
    pr_info("wxshadow: brk_handler = %px\n", kfunc_brk_handler);
    pr_info("wxshadow: single_step_handler = %px\n", kfunc_single_step_handler);

    /* Register API symbols */
    kfunc_register_user_break_hook = (typeof(kfunc_register_user_break_hook))
        lookup_name_safe("register_user_break_hook"); /* 注册用户态 BRK hook（注册 API 方式） */
    kfunc_register_user_step_hook = (typeof(kfunc_register_user_step_hook))
        lookup_name_safe("register_user_step_hook");  /* 注册用户态单步 hook（注册 API 方式） */

    pr_info("wxshadow: register_user_break_hook = %px\n", kfunc_register_user_break_hook);
    pr_info("wxshadow: register_user_step_hook = %px\n", kfunc_register_user_step_hook);

    /* debug_hook_lock for safe manual unregister */
    kptr_debug_hook_lock = (spinlock_t *)lookup_name_safe("debug_hook_lock"); /* 卸载时手动从链表摘除 hook 节点时需要持有此锁 */
    pr_info("wxshadow: debug_hook_lock = %px\n", kptr_debug_hook_lock);

    /* Check if at least one method is available */
    if (!(kfunc_brk_handler && kfunc_single_step_handler) &&
        !(kfunc_register_user_break_hook && kfunc_register_user_step_hook)) {
        pr_err("wxshadow: neither direct hook nor register API available\n");
        return -1;
    }
    pr_info("wxshadow: [9/12] done\n");

    /* ===== 锁（说明：wxshadow 采用无锁页表操作，此节跳过）===== */
    /* NOTE: mmap_lock and page_table_lock are NOT used - we operate locklessly */
    pr_info("wxshadow: [10/12] locking... (skipped - lockless operation)\n");

    /* ===== RCU：用于安全访问进程 mm 和 VMA 链表 ===== */
    pr_info("wxshadow: [11/12] RCU...\n");
    kfunc_rcu_read_lock = (typeof(kfunc_rcu_read_lock))
        lookup_name_safe("__rcu_read_lock");   /* RCU 读锁（保护进程列表和 mm 访问） */
    kfunc_rcu_read_unlock = (typeof(kfunc_rcu_read_unlock))
        lookup_name_safe("__rcu_read_unlock"); /* RCU 读锁释放 */
    kfunc_synchronize_rcu = (typeof(kfunc_synchronize_rcu))
        lookup_name_safe("synchronize_rcu");   /* 等待所有 RCU 读者退出，用于安全释放资源 */
    kfunc_kick_all_cpus_sync = (typeof(kfunc_kick_all_cpus_sync))
        lookup_name_safe("kick_all_cpus_sync"); /* 同步所有 CPU，确保页表修改对所有核可见 */
    if (!kfunc_rcu_read_lock || !kfunc_rcu_read_unlock) {
        pr_err("wxshadow: RCU functions not found\n");
        return -1;
    }
    if (!kfunc_kick_all_cpus_sync) {
        pr_err("wxshadow: kick_all_cpus_sync not found, refusing to load\n");
        return -ESRCH;
    }
    pr_info("wxshadow: synchronize_rcu = %px\n", kfunc_synchronize_rcu);
    pr_info("wxshadow: kick_all_cpus_sync = %px\n", kfunc_kick_all_cpus_sync);

    /* ===== 内核堆内存分配：kzalloc / kcalloc / kfree ===== */
    pr_info("wxshadow: [12/12] memory alloc...\n");
    /* kzalloc 多候选：各内核版本导出名称不同 */
    kfunc_kzalloc = (typeof(kfunc_kzalloc))lookup_name_safe("kzalloc");           /* 首选 */
    if (!kfunc_kzalloc)
        kfunc_kzalloc = (typeof(kfunc_kzalloc))lookup_name_safe("__kmalloc");     /* 低版本内核 */
    if (!kfunc_kzalloc)
        kfunc_kzalloc = (typeof(kfunc_kzalloc))lookup_name_safe("__kmalloc_node"); /* NUMA 变体 */
    if (!kfunc_kzalloc)
        kfunc_kzalloc = (typeof(kfunc_kzalloc))lookup_name_safe("kmalloc_trace"); /* 新版内核追踪变体 */
    if (!kfunc_kzalloc) {
        pr_err("wxshadow: kzalloc/__kmalloc not found\n");
        return -1;
    }
    pr_info("wxshadow: kzalloc resolved to %px\n", kfunc_kzalloc);

    /* Use lookup_name_safe to avoid module traversal hang */
    kfunc_kcalloc = (typeof(kfunc_kcalloc))lookup_name_safe("kcalloc");           /* 分配并清零数组 */
    if (!kfunc_kcalloc)
        kfunc_kcalloc = (typeof(kfunc_kcalloc))lookup_name_safe("kmalloc_array"); /* 备用：新内核使用此名 */
    if (!kfunc_kcalloc) {
        pr_warn("wxshadow: kcalloc/kmalloc_array not found, will use kzalloc wrapper\n");
    } else {
        pr_info("wxshadow: kcalloc resolved to %px\n", kfunc_kcalloc);
    }

    kfunc_kfree = (typeof(kfunc_kfree))lookup_name_safe("kfree"); /* 释放内核堆内存 */
    if (!kfunc_kfree) {
        pr_err("wxshadow: kfree not found\n");
        return -1;
    }
    pr_info("wxshadow: kfree resolved to %px\n", kfunc_kfree);

    /* 安全内存读取：优先 copy_from_kernel_nofault（不触发 panic），
     * 回退到旧接口 probe_kernel_read */
    kfunc_copy_from_kernel_nofault = (typeof(kfunc_copy_from_kernel_nofault))
        lookup_name_safe("copy_from_kernel_nofault"); /* 首选：5.8+ 内核 */
    if (!kfunc_copy_from_kernel_nofault) {
        kfunc_copy_from_kernel_nofault = (typeof(kfunc_copy_from_kernel_nofault))
            lookup_name_safe("probe_kernel_read"); /* 备用：旧内核接口 */
    }
    if (kfunc_copy_from_kernel_nofault) {
        pr_info("wxshadow: safe memory access available at %px\n", kfunc_copy_from_kernel_nofault);
    } else {
        pr_warn("wxshadow: copy_from_kernel_nofault not found, using direct access (less safe)\n");
    }

    /* copy_from_user removed: PATCH uses PTE walk instead (see copy_from_user_via_pte) */

    /* ===== 缺页异常处理函数（可选，用于隐藏 shadow 页的读取）===== */
    /*
     * Use lookup_name_safe() to avoid module traversal hang.
     * kallsyms_lookup_name() calls module_kallsyms_lookup_name() when
     * symbol is not found in vmlinux, which can hang on some kernels.
     */
    pr_info("wxshadow: [13/14] page fault handler (safe lookup)...\n");
    kfunc_do_page_fault = (void *)lookup_name_safe("do_page_fault"); /* 5.x 内核缺页处理入口 */
    if (!kfunc_do_page_fault) {
        /* Try alternative names used in different kernel versions */
        kfunc_do_page_fault = (void *)lookup_name_safe("__do_page_fault"); /* 4.x 内核入口 */
    }
    if (!kfunc_do_page_fault) {
        kfunc_do_page_fault = (void *)lookup_name_safe("do_mem_abort"); /* ARM64 通用内存异常处理 */
    }
    if (!kfunc_do_page_fault) {
        pr_warn("wxshadow: page fault handler not found, read hiding disabled\n");
    } else {
        pr_info("wxshadow: page fault handler found at %px\n", kfunc_do_page_fault);
    }

    /* follow_page_pte for GUP hiding (/proc/pid/mem, process_vm_readv, ptrace) */
    pr_info("wxshadow: [14/14] follow_page_pte (GUP hiding)...\n");
    kfunc_follow_page_pte = (void *)lookup_name_safe("follow_page_pte"); /* GUP 路径中读取 PTE 的核心函数，hook 后可隐藏 shadow 页 */
    if (kfunc_follow_page_pte) {
        pr_info("wxshadow: follow_page_pte found at %px\n", kfunc_follow_page_pte);
    } else {
        pr_warn("wxshadow: follow_page_pte not found, GUP hiding disabled\n");
    }

    /* dup_mmap for precise fork protection (real mm duplication only) */
    kfunc_dup_mmap = (void *)lookup_name_safe("dup_mmap"); /* fork 时复制 VMA 的内核函数，hook 后处理 shadow 继承 */
    if (kfunc_dup_mmap) {
        pr_info("wxshadow: dup_mmap found at %px\n", kfunc_dup_mmap);
    } else {
        pr_warn("wxshadow: dup_mmap not found, trying uprobe_dup_mmap\n");
    }

    kfunc_uprobe_dup_mmap = (void *)lookup_name_safe("uprobe_dup_mmap"); /* uprobe 子系统的 mmap 复制钩子，可作为 dup_mmap hook 的替代 */
    if (kfunc_uprobe_dup_mmap) {
        pr_info("wxshadow: uprobe_dup_mmap found at %px\n", kfunc_uprobe_dup_mmap);
    } else {
        pr_warn("wxshadow: uprobe_dup_mmap not found\n");
    }

    /* init_task already resolved above via kallsyms */

    pr_info("wxshadow: all symbols resolved successfully\n");
    return 0;
}

/*
 * ========== mm_struct 偏移量扫描 ==========
 *
 * 位置：模块初始化链的第二步，在 resolve_symbols() 之后调用。
 * 用途：确认 mm_struct.pgd 字段的偏移量，用于后续页表遍历时定位 PGD 基地址。
 * 实现：直接读取 KP 框架在启动时已检测好的 mm_struct_offset.pgd_offset，
 *       无需手动扫描；若框架未检测到则报错返回 -1。
 */

/* 检查内核地址是否有效可读（读取失败返回 false）*/
static inline bool is_valid_kptr(unsigned long addr)
{
    u64 tmp;
    return safe_read_u64(addr, &tmp);
}

/*
 * safe_read_str - 安全地从内核地址读取字符串（最多 maxlen 字节）
 *
 * 用途：在偏移量扫描阶段读取 task_struct.comm 等字符串字段，
 *       避免因访问未映射地址导致内核崩溃。
 * 实现：优先使用 copy_from_kernel_nofault（容错读取），
 *       若不可用则直接逐字节拷贝（风险较高，仅作兜底）。
 *       读取后强制末尾置 '\0'。
 */
static inline bool safe_read_str(unsigned long addr, char *buf, size_t maxlen)
{
    if (!is_kva(addr) || maxlen == 0)
        return false;

    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(buf, (const void *)addr, maxlen) != 0)
            return false;
    } else {
        /* Fallback: byte-by-byte copy */
        size_t i;
        for (i = 0; i < maxlen; i++) {
            buf[i] = ((char *)addr)[i]; /* 直接访问，若地址无效可能触发 oops */
        }
    }
    buf[maxlen - 1] = '\0'; /* 保证字符串以 null 结尾 */
    return true;
}

int scan_mm_struct_offsets(void)
{
    /*
     * Use KP framework's mm_struct_offset.pgd_offset (linux/mm_types.h)
     * Framework detects this in resolve_mm_struct_offset() at boot time.
     */
    pr_info("wxshadow: using KP framework mm_struct_offset.pgd_offset = 0x%x\n",
            mm_struct_offset.pgd_offset);

    if (mm_struct_offset.pgd_offset < 0) {
        pr_err("wxshadow: KP framework did not detect pgd_offset!\n");
        return -1;
    }

    return 0;
}

/*
 * ========== vm_area_struct 偏移量扫描 ==========
 *
 * 位置：模块初始化链的第三步（scan_mm_struct_offsets 之后）。
 * 用途：确定 vm_area_struct.vm_mm 字段在结构体内的偏移（VMA_VM_MM_OFFSET），
 *       后续在 shadow 页管理和缺页处理中通过此偏移从 VMA 反向找到 mm_struct。
 * 实现：获取当前进程的 mm，读取第一个 VMA；在 VMA 的 [0x10, 0x80) 范围内
 *       搜索值等于 mm 地址的字段，即为 vm_mm 偏移；搜索失败则使用默认值 0x40。
 */
int scan_vma_struct_offsets(void)
{
    void *mm;
    void *vma;
    int i;
    int found = 0; /* 是否已找到 vm_mm 偏移的标志 */

    pr_info("wxshadow: scanning vm_area_struct offsets...\n");

    /*
     * Use current task's mm to find vma offset.
     * If current has no mm (kernel thread), use default.
     */
    mm = kfunc_get_task_mm(current);
    if (!mm) {
        pr_warn("wxshadow: current task has no mm, using default vma offset\n");
        goto use_default;
    }

    /* First field of mm_struct is mmap (first VMA) */
    if (!safe_read_ptr((unsigned long)mm, &vma) || !vma) {
        pr_warn("wxshadow: no VMA in current mm, using default offset\n");
        kfunc_mmput(mm);
        goto use_default;
    }

    pr_info("wxshadow: scanning VMA at %px for mm pointer %px\n", vma, mm);

    /* Search for vm_mm field in vma_struct */
    for (i = 0x10; i < 0x80; i += 8) { /* vm_mm 不会位于结构体最开头（vm_start/vm_end 在前） */
        u64 val;
        if (!safe_read_u64((unsigned long)vma + i, &val))
            continue;
        if (val == (u64)mm) { /* 找到值与 mm 指针相等的字段即为 vm_mm */
            vma_vm_mm_offset = i;
            found = 1;
            pr_info("wxshadow: vm_area_struct.vm_mm offset: 0x%x\n",
                    vma_vm_mm_offset);
            break;
        }
    }

    kfunc_mmput(mm);

    if (!found) {
        pr_warn("wxshadow: vm_mm offset not found by search\n");
        goto use_default;
    }

    return 0;

use_default:
    vma_vm_mm_offset = 0x40; /* 默认偏移 0x40，适用于大多数主流内核版本 */
    pr_info("wxshadow: using default vm_mm offset: 0x%x\n", vma_vm_mm_offset);
    return 0;
}

/*
 * ========== task_struct 偏移量探测 ==========
 *
 * 本节包含两个函数：
 *   find_comm_offset()          - 在 init_task（swapper）中定位 comm 字段偏移
 *   detect_task_struct_offsets() - 探测 tasks_offset 和 mm_offset
 */

#define TASK_COMM_LEN 16        /* task_struct.comm 字段最大长度（含 null 终止符）*/
#define TASK_STRUCT_MAX_SIZE 0x1800 /* task_struct 最大扫描范围（约 6KB）*/

/*
 * find_comm_offset - 在 task_struct 中定位 comm（进程名）字段的偏移量
 *
 * 位置：detect_task_struct_offsets() 内部辅助函数。
 * 用途：comm 偏移是后续通过进程名验证偏移量正确性的基础。
 * 实现：从偏移 0x400 起每 4 字节扫描，查找 "swapper" 或 "swapper/0"
 *       字符串（init_task 的进程名），找到即返回偏移量；未找到返回 -1。
 */
static int find_comm_offset(void *task)
{
    int i;
    char buf[16];

    for (i = 0x400; i < TASK_STRUCT_MAX_SIZE; i += 4) { /* comm 通常在 task_struct 中后半部分 */
        /* Safely read potential comm string */
        if (!safe_read_str((unsigned long)task + i, buf, sizeof(buf)))
            continue;

        /* Check for "swapper" or "swapper/0" */
        if (buf[0] == 's' && buf[1] == 'w' && buf[2] == 'a' &&
            buf[3] == 'p' && buf[4] == 'p' && buf[5] == 'e' && buf[6] == 'r') {
            /* Verify it's null-terminated or followed by "/" */
            if (buf[7] == '\0' || (buf[7] == '/' && buf[8] == '0')) { /* 精确匹配，排除误判 */
                pr_info("wxshadow: found comm at offset 0x%x: \"%.16s\"\n", i, buf);
                return i;
            }
        }
    }

    return -1;
}

/*
 * detect_task_struct_offsets - 探测 task_struct 的关键字段偏移量
 *
 * 位置：模块初始化链，在 scan_vma_struct_offsets() 之后调用。
 * 用途：wxshadow 需要遍历进程链表（tasks）、读取进程 mm（mm_offset）
 *       以及通过 comm 识别进程身份；这些操作都依赖正确的字段偏移量。
 * 实现：
 *   1. 若框架未提供 comm_offset，则通过 find_comm_offset() 在 init_task 中扫描。
 *   2. tasks_offset：在 active_mm_offset 之前的范围内寻找一个合法的
 *      list_head（next/prev 均为内核地址，且 next->prev == self），
 *      并验证 next 指向的任务 comm 为 "init"（pid 1）。
 *   3. mm_offset：由 KP 框架提供的 active_mm_offset - 8 直接计算得到
 *      （mm 和 active_mm 在 task_struct 中相邻，mm 在前）。
 *
 * 返回值：0 成功；-1 表示偏移量探测失败。
 */
int detect_task_struct_offsets(void)
{
    int search_start, search_end; /* tasks_offset 的搜索范围边界 */
    int i;
    int16_t comm_offset;     /* task_struct.comm 字段偏移 */
    int16_t active_mm_off;   /* task_struct.active_mm 字段偏移（框架提供）*/

    pr_info("wxshadow: detecting task_struct offsets...\n");

    if (!wx_init_task) {
        pr_err("wxshadow: wx_init_task is NULL\n");
        return -1;
    }

    /* First, scan for comm_offset if not already set by framework */
    comm_offset = task_struct_offset.comm_offset; /* 框架可能已在启动时自动检测 */
    if (comm_offset <= 0) {
        comm_offset = find_comm_offset(wx_init_task);
        if (comm_offset > 0) {
            task_struct_offset.comm_offset = comm_offset;
            pr_info("wxshadow: comm_offset = 0x%x (scanned)\n", comm_offset);
        } else {
            pr_err("wxshadow: failed to find comm_offset\n");
            return -1;
        }
    } else {
        pr_info("wxshadow: comm_offset = 0x%x (from framework)\n", comm_offset);
    }

    /* Get active_mm_offset from framework */
    active_mm_off = task_struct_offset.active_mm_offset; /* KP 框架通过扫描内核结构体自动检测 */

    /*
     * Detect tasks_offset based on active_mm_offset
     *
     * In Linux kernel task_struct layout, tasks (struct list_head) is
     * typically located before mm and active_mm fields:
     *   struct task_struct {
     *       ...
     *       struct list_head tasks;    <- tasks_offset
     *       ...
     *       struct mm_struct *mm;      <- mm_offset (active_mm - 8)
     *       struct mm_struct *active_mm; <- active_mm_offset
     *       ...
     *   }
     *
     * Search range: [active_mm_offset - 0x200, active_mm_offset)
     */
    if (active_mm_off > 0) {
        /* tasks 链表头通常在 active_mm 之前约 0x100~0x200 字节处 */
        search_start = active_mm_off > 0x200 ? active_mm_off - 0x200 : 0x100;
        search_end = active_mm_off; /* 不超过 active_mm 位置 */
        pr_info("wxshadow: scanning tasks_offset based on active_mm_offset=0x%x, range=[0x%x, 0x%x)\n",
                active_mm_off, search_start, search_end);
    } else {
        /* Fallback: use comm_offset as upper bound */
        search_start = 0x100;
        search_end = comm_offset < 0x600 ? comm_offset : 0x600;
        pr_info("wxshadow: active_mm_offset not available, fallback range=[0x%x, 0x%x)\n",
                search_start, search_end);
    }

    /* 遍历候选偏移，寻找满足 list_head 不变量的 tasks 字段 */
    for (i = search_start; i < search_end; i += sizeof(u64)) {
        unsigned long list_addr = (unsigned long)wx_init_task + i; /* 候选 list_head 地址 */
        u64 next_va, prev_va; /* list_head.next 和 list_head.prev */

        /* Safely read list_head.next and list_head.prev */
        if (!safe_read_u64(list_addr, &next_va))
            continue;
        if (!safe_read_u64(list_addr + 8, &prev_va))
            continue;

        if (!is_kva(next_va) || !is_kva(prev_va)) /* next/prev 必须是内核虚拟地址 */
            continue;

        if (next_va == prev_va) /* 跳过 init_task 之外只有一个节点的链表（next==prev==self 指向自身）*/
            continue;

        /* Verify next->prev == self */
        {
            u64 next_prev; /* 验证 list_head 双向链表不变量：next->prev 应指回当前节点 */
            if (!safe_read_u64(next_va + 8, &next_prev))
                continue;
            if (next_prev != list_addr)
                continue;
        }

        /* Verify the candidate task has comm == "init" */
        {
            void *candidate = (void *)(next_va - i); /* 根据偏移反推候选任务的 task_struct 指针 */
            char comm_buf[8];

            if (!safe_read_str((unsigned long)candidate + comm_offset, comm_buf, sizeof(comm_buf)))
                continue;

            if (comm_buf[0] == 'i' && comm_buf[1] == 'n' &&
                comm_buf[2] == 'i' && comm_buf[3] == 't') { /* 确认是 pid 1 的 "init" 进程 */
                task_struct_offset.tasks_offset = i;
                wx_init_process = candidate; /* 缓存 init 进程指针供后续扫描使用 */
                pr_info("wxshadow: tasks_offset = 0x%x (based on active_mm_offset=0x%x)\n",
                        i, active_mm_off);
                break;
            }
        }
    }

    if (task_struct_offset.tasks_offset < 0) {
        pr_err("wxshadow: tasks_offset not found\n");
        return -1;
    }

    /*
     * Detect mm_offset using active_mm_offset from framework
     *
     * mm is always 8 bytes before active_mm in task_struct:
     *   struct mm_struct *mm;        <- mm_offset
     *   struct mm_struct *active_mm; <- active_mm_offset
     */
    if (task_struct_offset.active_mm_offset > 0) {
        task_struct_offset.mm_offset = task_struct_offset.active_mm_offset - 8;
        pr_info("wxshadow: mm_offset = 0x%x (active_mm_offset - 8)\n",
                task_struct_offset.mm_offset);
    } else {
        pr_err("wxshadow: active_mm_offset not available from framework\n");
        return -1;
    }

    /* pid/tgid: use wxfunc(__task_pid_nr_ns) */

    pr_info("wxshadow: task_struct offsets: tasks=0x%x, mm=0x%x, comm=0x%x\n",
            task_struct_offset.tasks_offset, task_struct_offset.mm_offset,
            task_struct_offset.comm_offset);
    pr_info("wxshadow: pid/tgid: using wxfunc(__task_pid_nr_ns)\n");

    return 0;
}

/*
 * ========== mm->context.id 偏移量扫描 ==========
 *
 * 背景：ARM64 TLBI 指令需要提供 ASID（地址空间标识符）作为操作数，
 *       ASID 存储在 mm_struct 内嵌的 mm_context_t.id 字段中。
 *       由于 mm_context_t 结构体在不同内核版本中布局差异较大，
 *       需要在运行时动态扫描其在 mm_struct 中的偏移量。
 *
 * 扫描策略（优先级从高到低）：
 *   方法 1（vdso ELF magic）：mm_context_t 中 vdso 指针紧跟在 id 之后，
 *     通过找到 vdso 地址并验证其指向 ELF magic 来定位 context.id。
 *     可在任意上下文（包括内核线程）中工作。
 *   方法 2（TTBR0_EL1 ASID 匹配）：读取当前 TTBR0_EL1 寄存器中的 ASID，
 *     在 mm_struct 中搜索值等于该 ASID 的 64 位字段。
 *     仅在用户进程上下文中有效（内核线程 ASID=0 导致误匹配）。
 *   若两种方法均失败，延迟到首次 prctl 调用时在用户进程上下文中重试。
 */

/* ELF magic bytes */
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

/*
 * walk_pgtable_uaddr - 通过软件遍历页表将用户虚拟地址转换为物理地址
 *
 * 位置：mm->context.id 扫描的辅助函数，也供 ELF magic 验证使用。
 * 用途：在内核不提供 follow_page / get_user_pages 等接口的情况下，
 *       直接读取 mm->pgd 并逐级遍历页表项得到物理地址，
 *       用于验证某个用户地址处是否存在 ELF magic（vdso 起始标志）。
 * 实现：从 TCR_EL1 读取 T0SZ 和 TG0 计算 VA 位数、页粒度和翻译层数；
 *       每级使用 safe_read_u64 安全读取描述符，检查有效位和类型位；
 *       最终在叶子描述符（block 或 page）处提取物理地址。
 *
 * @mm:    目标进程的 mm_struct 指针（内核虚拟地址）
 * @uaddr: 要翻译的用户虚拟地址
 * 返回值：对应物理地址；翻译失败返回 0。
 */
static unsigned long walk_pgtable_uaddr(void *mm, unsigned long uaddr)
{
    u64 *table;  /* 当前页表级别的基地址（内核虚拟地址）*/
    u64 desc;    /* 当前页表描述符 */
    int level;   /* 当前翻译层级（1~3，ARM64 最多 4 级）*/
    u64 tcr;     /* TCR_EL1 寄存器值 */
    int t0sz, tg0;              /* TCR_EL1 字段：用户地址空间大小和页粒度 */
    int granule_shift, stride;  /* 页大小对应的 shift 值和每级页表索引位数 */
    int va_bits, levels, start_level; /* VA 有效位数、页表层数和起始层级 */

    /* Get PGD from mm - it's already a kernel virtual address */
    table = (u64 *)mm_pgd(mm); /* 从 mm_struct.pgd 字段获取顶级页表基地址 */
    if (!table || !is_kva((unsigned long)table))
        return 0;

    /* Read TCR_EL1 to get T0SZ and TG0 */
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr)); /* 读取用户地址翻译控制配置 */

    t0sz = tcr & 0x3f;        /* T0SZ: 用户地址空间大小字段 */
    tg0 = (tcr >> 14) & 0x3;  /* TG0: 用户地址翻译页粒度（低 2 位）*/

    /* Decode TG0: 0=4KB, 1=64KB, 2=16KB */
    switch (tg0) {
    case 0:  /* 4KB */
        granule_shift = 12;
        stride = 9;
        break;
    case 1:  /* 64KB */
        granule_shift = 16;
        stride = 13;
        break;
    case 2:  /* 16KB */
        granule_shift = 14;
        stride = 11;
        break;
    default:
        granule_shift = 12;
        stride = 9;
    }

    va_bits = 64 - t0sz; /* 用户 VA 有效位数 */
    levels = (va_bits - granule_shift + stride - 1) / stride; /* 实际页表层数（向上取整）*/
    start_level = 4 - levels; /* 从哪一级开始遍历（ARM64 最多 4 级：0~3）*/

    for (level = start_level; level <= 3; level++) {
        int shift = granule_shift + stride * (3 - level); /* 本级地址索引的起始 bit 位置 */
        int idx = (uaddr >> shift) & ((1 << stride) - 1); /* 本级页表索引 */

        /* Read descriptor directly (table is KVA) */
        if (!safe_read_u64((unsigned long)&table[idx], &desc))
            return 0;

        /* Check valid bit */
        if (!(desc & 1)) /* 描述符有效位（bit 0），0 表示无映射 */
            return 0;

        unsigned long next_pa = desc & 0x0000FFFFFFFFF000UL; /* 提取下一级页表或页帧的物理地址 */

        /* Check if table or block/page entry */
        if (level < 3 && (desc & 2)) { /* bit 1=1 且非最后一级：Table 描述符 */
            /* Table descriptor - convert PA to KVA for next level */
            table = (u64 *)phys_to_virt_safe(next_pa); /* 物理地址转内核虚拟地址以便继续读取 */
            if (!is_kva((unsigned long)table))
                return 0;
        } else {
            /* Block or page entry - translation complete */
            unsigned long offset_mask = (1UL << shift) - 1; /* 页内偏移掩码 */
            return next_pa | (uaddr & offset_mask); /* 物理页帧地址 + 页内偏移 */
        }
    }

    return 0;
}

/*
 * check_elf_magic_at_uaddr - 验证用户地址处是否存在 ELF 魔数
 *
 * 位置：scan_by_vdso_elf_magic() 的内部辅助函数。
 * 用途：通过页表遍历读取用户地址处的前 4 字节，检查是否为 ELF magic
 *       (\x7fELF)，用于确认某个用户指针是否指向 vdso（进程加载的虚拟 DSO）。
 * 实现：调用 walk_pgtable_uaddr 将用户 VA 转 PA，再转内核 VA 后读取 4 字节
 *       并与 ELF magic 比较。全程使用安全读取接口，不会触发缺页异常。
 *
 * @mm:        进程 mm_struct 指针
 * @uaddr:     待检查的用户虚拟地址（必须为非内核地址）
 * @mm_offset: 日志中显示的字段偏移（仅用于调试输出）
 * 返回值：找到 ELF magic 返回 true，否则返回 false。
 */
static bool check_elf_magic_at_uaddr(void *mm, unsigned long uaddr, int mm_offset)
{
    unsigned long pa, kva;
    unsigned char magic[4] = {0, 0, 0, 0}; /* 存储读取到的前 4 字节 */
    bool found;

    /* Must be a user address (not kernel) */
    if ((uaddr >> 48) != 0) /* ARM64 用户地址高 16 位为 0，内核地址高 16 位为 0xffff */
        return false;

    if (uaddr == 0)
        return false;

    /* Walk mm's page table to translate user VA to PA */
    pa = walk_pgtable_uaddr(mm, uaddr);
    if (pa == 0) {
        pr_info("wxshadow:   [0x%x] uaddr=0x%lx -> PA failed\n", mm_offset, uaddr);
        return false;
    }

    /* Convert PA to kernel VA */
    kva = phys_to_virt_safe(pa);
    if (!is_kva(kva)) {
        pr_info("wxshadow:   [0x%x] uaddr=0x%lx -> pa=0x%lx -> kva invalid\n",
                mm_offset, uaddr, pa);
        return false;
    }

    /* Read the first 4 bytes */
    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(magic, (const void *)kva, 4) != 0) { /* 安全读取，失败不 panic */
            pr_info("wxshadow:   [0x%x] uaddr=0x%lx -> kva=0x%lx read failed\n",
                    mm_offset, uaddr, kva);
            return false;
        }
    } else {
        /* 无安全读取接口时直接访问，依赖 kva 已验证为有效内核虚拟地址 */
        magic[0] = ((unsigned char *)kva)[0];
        magic[1] = ((unsigned char *)kva)[1];
        magic[2] = ((unsigned char *)kva)[2];
        magic[3] = ((unsigned char *)kva)[3];
    }

    /* Check ELF magic */
    found = (magic[0] == ELFMAG0 && magic[1] == ELFMAG1 &&
             magic[2] == ELFMAG2 && magic[3] == ELFMAG3);

    pr_info("wxshadow:   [0x%x] uaddr=0x%lx -> magic=%02x %02x %02x %02x %s\n",
            mm_offset, uaddr, magic[0], magic[1], magic[2], magic[3],
            found ? "** ELF FOUND **" : "");

    return found;
}

/*
 * scan_by_vdso_elf_magic - 通过 vdso ELF magic 定位 mm->context.id 偏移
 *
 * 位置：try_scan_mm_context_id_offset() 的首选扫描方法。
 * 用途：mm_context_t 中 vdso 指针紧跟在 atomic64_t id 之后，
 *       通过找到 vdso 地址（指向 ELF magic）即可推算出 context.id 偏移。
 * 实现：在 mm_struct 的 [pgd_offset+0x100, pgd_offset+0x400) 范围内
 *       遍历所有用户空间指针（高 16 位为 0），
 *       对每个指针调用 check_elf_magic_at_uaddr 验证是否指向 ELF 魔数，
 *       找到 vdso 后返回 vdso_offset - 8（即 context.id 的偏移）。
 *
 * 返回值：context.id 在 mm_struct 中的偏移；未找到返回 -1。
 */
static int scan_by_vdso_elf_magic(struct mm_struct *mm)
{
    int offset;             /* 当前扫描的字段偏移 */
    int pgd_off = mm_struct_offset.pgd_offset; /* pgd 字段偏移，作为扫描起点参考 */
    u64 val;
    int user_ptr_count = 0; /* 遇到的用户地址指针计数，用于调试输出 */

    if (pgd_off < 0) {
        pr_warn("wxshadow: pgd_offset not available\n");
        return -1;
    }

    pr_info("wxshadow: scanning for vdso (ELF magic) in mm=%px, pgd_offset=0x%x\n",
            mm, pgd_off);
    pr_info("wxshadow: search range: [0x%x, 0x%x)\n",
            pgd_off + 0x100, pgd_off + 0x400);

    /* Search for vdso pointer after pgd */
    for (offset = pgd_off + 0x100; offset < pgd_off + 0x400; offset += 8) { /* context 在 pgd 之后 */
        if (!safe_read_u64((unsigned long)mm + offset, &val))
            continue;

        /* Skip NULL and kernel addresses */
        if (val == 0 || (val >> 48) != 0) /* 仅关注用户空间指针（高 16 位为 0） */
            continue;

        /* Found a user-space pointer, check if it points to ELF magic */
        user_ptr_count++;
        if (check_elf_magic_at_uaddr(mm, val, offset)) {
            pr_info("wxshadow: === VDSO FOUND at mm+0x%x, vdso_addr=0x%llx ===\n",
                    offset, val);

            /* context.id is right before vdso (8 bytes) */
            return offset - 8; /* mm_context_t 布局：[id(8B)][vdso(8B)]，所以 id = vdso_offset - 8 */
        }
    }

    pr_warn("wxshadow: vdso not found (checked %d user pointers)\n", user_ptr_count);
    return -1;
}

/*
 * scan_by_ttbr0_asid - 通过读取 TTBR0_EL1 ASID 在 mm_struct 中匹配 context.id
 *
 * 位置：scan_mm_context_id_offset_from_mm() 的具体实现，也是 vdso 方法失败后的备选。
 * 用途：当无法通过 vdso 方法定位 context.id 时，利用 CPU 当前 TTBR0_EL1
 *       寄存器中的 ASID 值与 mm_struct 中的字段进行匹配。
 * 实现：读取 TTBR0_EL1[63:48] 得到 ASID，在 mm[0x100..0x400] 范围内
 *       查找低 16 位等于 ASID 的字段；若不匹配则再尝试高 16 位和中间 16 位。
 * 限制：ASID=0 时（内核线程）无法区分，会有误匹配，返回 -2 提示调用者跳过。
 *
 * 返回值：找到返回偏移量；ASID=0 返回 -2；未找到返回 -1。
 */
static int scan_by_ttbr0_asid(struct mm_struct *mm)
{
    u64 ttbr0_val, asid; /* TTBR0_EL1 寄存器值和提取出的 ASID */
    int offset;

    /* Read TTBR0_EL1 to get ASID */
    asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0_val)); /* 读取当前进程的页表基址寄存器，含 ASID */

    /* ASID is in bits [63:48] (16-bit ASID) or [55:48] (8-bit ASID) */
    asid = (ttbr0_val >> 48) & 0xFFFF; /* 提取 16 位 ASID（8 位 ASID 时高 8 位为 0）*/

    pr_info("wxshadow: TTBR0_EL1=0x%llx, ASID=%llu (0x%llx)\n", ttbr0_val, asid, asid);

    /* ASID=0 is problematic - too many zero fields would match */
    if (asid == 0) { /* 内核线程或某些特殊情况下 ASID 为 0，此时无法可靠匹配 */
        pr_info("wxshadow: ASID=0, cannot use TTBR0 method\n");
        return -2;
    }

    /* Search for context.id in mm_struct */
    for (offset = 0x100; offset < 0x400; offset += 8) { /* context 通常在 mm 后半段 */
        u64 val;
        if (!safe_read_u64((unsigned long)mm + offset, &val))
            continue;

        /* Check if low 16 bits match ASID */
        if ((val & 0xFFFF) == asid) { /* context.id 低 16 位存储当前 ASID */
            pr_info("wxshadow: found mm->context.id at offset 0x%x, val=0x%llx (ASID match)\n",
                    offset, val);
            return offset;
        }
    }

    /* Try alternative: ASID might be in higher bits */
    for (offset = 0x100; offset < 0x400; offset += 8) { /* 部分内核版本 ASID 存在更高位 */
        u64 val;
        if (!safe_read_u64((unsigned long)mm + offset, &val))
            continue;

        if (((val >> 48) & 0xFFFF) == asid ||
            ((val >> 32) & 0xFFFF) == asid) {
            pr_info("wxshadow: found mm->context.id at offset 0x%x (alt), val=0x%llx\n",
                    offset, val);
            return offset;
        }
    }

    pr_warn("wxshadow: TTBR0 method failed (ASID=%llu)\n", asid);
    return -1;
}

/*
 * scan_mm_context_id_offset_from_mm - 从指定 mm_struct 扫描 context.id 偏移
 *
 * 用途：封装 TTBR0 ASID 扫描逻辑，提供统一入口并验证 mm 指针有效性。
 * 实现：仅使用 scan_by_ttbr0_asid（更可靠），vdso 方法由上层直接调用。
 *       要求调用者处于用户进程上下文（非内核线程），否则 ASID 可能为 0。
 *
 * 返回值：偏移量（>=0）成功；-1 失败。
 */
static int scan_mm_context_id_offset_from_mm(struct mm_struct *mm)
{
    int offset;

    /* Validate mm pointer is readable */
    if (!is_valid_kptr((unsigned long)mm)) {
        pr_warn("wxshadow: invalid mm pointer: %px\n", mm);
        return -1;
    }

    /* Use TTBR0 ASID matching - only reliable method */
    pr_info("wxshadow: scanning mm->context.id using TTBR0 ASID method...\n");
    offset = scan_by_ttbr0_asid(mm);
    if (offset >= 0) {
        pr_info("wxshadow: mm_context_id_offset = 0x%x\n", offset);
        return offset;
    }

    pr_warn("wxshadow: TTBR0 ASID method failed (ASID may be 0 in kernel thread context)\n");
    return -1;
}

/*
 * get_init_process_mm - 获取 init 进程（pid 1）的 mm_struct 指针
 *
 * 用途：init 进程始终存活且加载了 vdso，是 vdso ELF magic 扫描方法的
 *       理想目标进程（不依赖当前调用上下文）。
 * 实现：使用 detect_task_struct_offsets() 缓存的 wx_init_process 指针，
 *       通过已知的 mm_offset 直接读取 mm 字段。
 *       注意：不调用 get_task_mm/mmput，调用方无需持有引用。
 */
static struct mm_struct *get_init_process_mm(void)
{
    struct task_struct *init_proc;
    struct mm_struct *mm = NULL;

    /* Use cached init_process from detect_task_struct_offsets */
    init_proc = wx_init_process; /* detect_task_struct_offsets 已将 pid 1 缓存于此 */
    if (!init_proc) {
        pr_warn("wxshadow: init process not found\n");
        return NULL;
    }

    /* Get mm from init process */
    if (task_struct_offset.mm_offset >= 0) {
        safe_read_ptr((unsigned long)init_proc + task_struct_offset.mm_offset, (void **)&mm); /* 通过偏移读取 mm 指针 */
    }

    if (!mm) {
        pr_warn("wxshadow: init process has no mm\n");
        return NULL;
    }

    pr_info("wxshadow: init process mm=%px\n", mm);
    return mm;
}

/*
 * try_scan_mm_context_id_offset - 尝试扫描 mm->context.id 偏移量（对外接口）
 *
 * 位置：模块初始化末段以及 prctl hook 首次触发时调用。
 * 用途：mm_context_id_offset 是 TLBI 指令 TLB 刷新回退路径的必要参数；
 *       若初始化时无法检测，则在首次用户态 prctl 调用时延迟检测。
 * 实现：
 *   方法 1（vdso ELF magic，推荐）：取 init 进程 mm，扫描 vdso 指针，
 *     context.id = vdso_offset - 8。可在任意上下文中运行。
 *   方法 2（TTBR0 ASID 匹配，回退）：读取当前 TTBR0_EL1 ASID，
 *     在当前进程 mm 中匹配对应字段。仅在用户进程上下文中可靠。
 *   两种方法均失败时打印提示并返回 -1（稍后由 prctl 触发重试）。
 *
 * 返回值：0 成功（mm_context_id_offset 已设置）；-1 失败（需延迟重试）。
 */
int try_scan_mm_context_id_offset(void)
{
    struct mm_struct *mm;
    int offset;

    /* Already detected */
    if (mm_context_id_offset >= 0) /* 已经成功检测过，直接返回 */
        return 0;

    pr_info("wxshadow: trying to scan mm->context.id offset...\n");

    /*
     * Method 1: Use init process (pid 1) mm and find vdso by ELF magic.
     * This works regardless of current context (kernel thread or user process).
     */
    mm = get_init_process_mm();
    if (mm) {
        offset = scan_by_vdso_elf_magic(mm);
        if (offset >= 0) {
            pr_info("wxshadow: mm_context_id_offset = 0x%x (vdso method)\n", offset);
            mm_context_id_offset = offset;
            return 0;
        }
    }

    /*
     * Method 2 (fallback): Use current process mm and TTBR0 ASID matching.
     * Only works in user process context.
     */
    if (task_struct_offset.mm_offset < 0) {
        pr_warn("wxshadow: mm_offset not detected\n");
        return -1;
    }

    if (!safe_read_ptr((unsigned long)current + task_struct_offset.mm_offset, (void **)&mm)) {
        pr_warn("wxshadow: failed to read mm from current task\n");
        return -1;
    }

    if (!mm) { /* 内核线程没有用户空间 mm，无法用 TTBR0 方法 */
        pr_info("wxshadow: current is kernel thread, deferring to prctl\n");
        return -1;
    }

    offset = scan_mm_context_id_offset_from_mm(mm);
    if (offset >= 0) {
        mm_context_id_offset = offset;
        return 0;
    }

    /* Will retry at prctl time when in user process context */
    pr_info("wxshadow: context.id scan deferred to first prctl call\n");
    return -1;
}

/*
 * ========== 调试辅助：打印进程列表 ==========
 *
 * 位置：模块初始化完成后，或手动触发调试时调用。
 * 用途：验证 tasks_offset / mm_offset / comm_offset 等偏移量检测结果的
 *       正确性——通过打印进程列表，可直观检查 PID、comm、mm 是否合理。
 * 实现：从 wx_init_task（swapper）出发，通过 wx_next_task() 宏沿
 *       tasks 链表遍历；对每个任务调用 __task_pid_nr_ns 获取 pid/tgid，
 *       调用 get_task_comm 获取进程名，读取 mm 指针。
 *       最多打印 max_count 个进程以防日志过长。
 */
void debug_print_tasks_list(int max_count)
{
    struct task_struct *p;
    int count = 0;

    pr_info("wxshadow: === DEBUG: tasks list (first %d processes) ===\n", max_count);
    pr_info("wxshadow: task_struct_offset addr: %px\n", &task_struct_offset);
    pr_info("wxshadow: task_struct_offset: tasks=0x%x (%d), comm=0x%x (%d), mm=0x%x (%d)\n",
            (unsigned short)task_struct_offset.tasks_offset, task_struct_offset.tasks_offset,
            (unsigned short)task_struct_offset.comm_offset, task_struct_offset.comm_offset,
            (unsigned short)task_struct_offset.mm_offset, task_struct_offset.mm_offset);
    pr_info("wxshadow: pid/tgid: using wxfunc(__task_pid_nr_ns)\n");

    pr_info("wxshadow: wx_init_task = %px\n", wx_init_task);

    if (task_struct_offset.tasks_offset < 0 ||
        task_struct_offset.comm_offset < 0) {
        pr_err("wxshadow: tasks_offset (%d) or comm_offset (%d) not initialized!\n",
               task_struct_offset.tasks_offset, task_struct_offset.comm_offset);
        return;
    }

    if (!wx_init_task) {
        pr_err("wxshadow: wx_init_task is NULL!\n");
        return;
    }

    pr_info("wxshadow: wx_init_task (swapper) at %px\n", wx_init_task);

    /* Iterate using wx_next_task() - fixed implementation in wxshadow_internal.h */
    for (p = wx_init_task; (p = wx_next_task(p)) != wx_init_task && count < max_count; ) {
        pid_t pid = 0;
        pid_t tgid = 0;
        const char *comm;
        void *mm = NULL; /* 用户空间内存描述符（内核线程为 NULL）*/

        /* Use wxfunc(__task_pid_nr_ns) */
        pid = wxfunc(__task_pid_nr_ns)(p, PIDTYPE_PID, NULL);   /* 获取线程 PID */
        tgid = wxfunc(__task_pid_nr_ns)(p, PIDTYPE_TGID, NULL); /* 获取线程组 ID（进程 PID）*/

        /* Use get_task_comm helper from linux/sched.h */
        comm = get_task_comm(p);

        if (task_struct_offset.mm_offset >= 0) {
            safe_read_ptr((unsigned long)p + task_struct_offset.mm_offset, &mm);
        }

        pr_info("wxshadow: [%d] task=%px pid=%d tgid=%d mm=%px comm=\"%.16s\"\n",
                count, p, pid, tgid, mm, comm ? comm : "(null)");

        count++;
    }

    pr_info("wxshadow: === END tasks list (%d processes printed) ===\n", count);
}
