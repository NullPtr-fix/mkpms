/*
 * wxshadow_client - W^X Shadow Memory Client Tool
 *
 * Usage:
 *   wxshadow_client -p <pid> -a <addr>              # Set breakpoint
 *   wxshadow_client -p <pid> -a <addr> -r x0=1     # Set bp with reg mod
 *   wxshadow_client -p <pid> -a <addr> -d          # Delete breakpoint at addr
 *   wxshadow_client -p <pid> -d                    # Delete ALL breakpoints
 *   wxshadow_client -p <pid> -b <lib> -o <offset>  # Use lib+offset
 *   wxshadow_client -p <pid> -m                    # Show maps
 *   wxshadow_client -p <pid> --release             # Release ALL shadows
 *
 * Copyright (C) 2024
 */

/*
 * 文件概述：wxshadow 内核模块的用户态客户端工具
 *
 * 本文件实现了与 wxshadow 内核模块通信的命令行工具。wxshadow 通过
 * shadow 页面技术在用户进程代码段设置隐藏断点：进程读取时看到原始
 * 代码，执行时触发 BRK 异常，从而实现对目标进程的透明插桩。
 *
 * 主要功能：
 *   - 通过 prctl() 系统调用向内核模块发送控制命令
 *   - 解析 /proc/<pid>/maps 定位动态库基址，支持 "库名+偏移" 寻址
 *   - 设置/删除断点，附加寄存器修改，patch shadow 页面，释放 shadow
 *
 * 通信接口：prctl(PR_WXSHADOW_*, pid, addr, arg4, arg5)
 *   内核模块通过 hook prctl 系统调用接收这些命令。
 */

/*
 * 头文件引用
 *
 * 包含标准 C 库、POSIX 接口及 Linux 特定头文件，
 * 提供 I/O、字符串处理、进程控制、选项解析等基础支持。
 */
#include <stdio.h>      /* 标准输入输出：printf/fprintf/fopen/fgets 等 */
#include <stdlib.h>     /* 通用工具：atoi/strtoull/exit 等 */
#include <string.h>     /* 字符串操作：strchr/strstr/strncpy/strerror 等 */
#include <unistd.h>     /* POSIX 接口：getpid/prctl 声明 */
#include <sys/prctl.h>  /* prctl() 系统调用及 PR_* 常量 */
#include <errno.h>      /* 错误码：errno 及 ENODATA 等 */
#include <getopt.h>     /* 长选项解析：getopt_long */
#include <ctype.h>      /* 字符分类：tolower/isdigit 等 */

/*
 * prctl 命令码定义
 *
 * wxshadow 内核模块通过 hook prctl 系统调用接收用户态命令。
 * 这些魔数值以 0x5758（ASCII "WX"）为前缀，避免与标准 prctl 选项冲突。
 * 内核侧在 wxshadow.c 的 prctl hook 处理函数中识别这些命令码。
 */
/* prctl options for wxshadow */
#define PR_WXSHADOW_SET_BP      0x57580001  /* 在指定地址设置隐藏断点 */
#define PR_WXSHADOW_SET_REG     0x57580002  /* 为断点附加寄存器修改规则 */
#define PR_WXSHADOW_DEL_BP      0x57580003  /* 删除断点（addr=0 删除全部）*/
#define PR_WXSHADOW_PATCH       0x57580006  /* 向 shadow 页写入自定义字节 */
#define PR_WXSHADOW_RELEASE     0x57580008  /* 释放 shadow，恢复原始页映射 */

/* 每个断点最多允许附加的寄存器修改条目数，与内核侧 WXSHADOW_MAX_REG_MODS 一致 */
#define MAX_REG_MODS 4

/*
 * 寄存器修改描述符
 *
 * 用于记录断点触发时需要强制修改的寄存器及其目标值。
 * 内核在 BRK 处理函数中读取这些规则并修改 pt_regs，
 * 实现对目标进程执行流或参数的透明篡改。
 */
struct reg_mod {
    int reg_idx;            /* 寄存器索引：0–30 对应 x0–x30，31 对应 sp */
    unsigned long value;    /* 断点触发时将寄存器强制设置为该值 */
};

/*
 * print_usage - 打印命令行帮助信息
 *
 * 位置：工具入口辅助函数
 * 用途：当用户未提供参数或使用 -h/--help 时，展示完整的用法说明，
 *       包括所有选项的含义及典型使用示例，降低上手门槛。
 */
static void print_usage(const char *prog) {
    printf("wxshadow_client - W^X Shadow Memory Client\n\n");
    printf("Usage:\n");
    printf("  %s -p <pid> -a <addr>                 Set breakpoint\n", prog);
    printf("  %s -p <pid> -a <addr> -r x0=<val>     Set bp with register modification\n", prog);
    printf("  %s -p <pid> -a <addr> -d              Delete breakpoint at addr\n", prog);
    printf("  %s -p <pid> -d                        Delete ALL breakpoints\n", prog);
    printf("  %s -p <pid> -b <lib> -o <offset>      Use library + offset\n", prog);
    printf("  %s -p <pid> -m                        Show executable maps\n", prog);
    printf("  %s -p <pid> -a <addr> --patch <hex>   Patch shadow page\n", prog);
    printf("  %s -p <pid> -a <addr> --release       Release modification at addr\n", prog);
    printf("  %s -p <pid> --release                 Release ALL shadows\n", prog);
    printf("\nOptions:\n");
    printf("  -p, --pid <pid>       Target process ID (0 for self)\n");
    printf("  -a, --addr <addr>     Virtual address (hex, optional for -d/--release)\n");
    printf("  -b, --base <lib>      Library name to find base address\n");
    printf("  -o, --offset <off>    Offset from library base (hex)\n");
    printf("  -r, --reg <reg>=<val> Register modification (can use multiple times)\n");
    printf("                        reg: x0-x30 or sp\n");
    printf("  -d, --delete          Delete breakpoint (all if no addr specified)\n");
    printf("  -m, --maps            Show executable memory regions\n");
    printf("  --patch <hex>         Patch shadow page with hex data (e.g. d503201f)\n");
    printf("  --release             Release modification at addr (all if no addr specified)\n");
    printf("  -h, --help            Show this help\n");
    printf("\nExamples:\n");
    printf("  %s -p 1234 -a 0x7b5c001234\n", prog);
    printf("  %s -p 1234 -b libc.so -o 0x12345 -r x0=0\n", prog);
    printf("  %s -p 1234 -a 0x7b5c001234 -r x0=1 -r x1=0x100\n", prog);
    printf("  %s -p 1234 -m\n", prog);
    printf("  %s -p 1234 -a 0x7b5c001234 --patch d503201f\n", prog);
    printf("  %s -p 1234 -a 0x7b5c001234 --release\n", prog);
    printf("  %s -p 1234 -d                          # delete all BPs\n", prog);
    printf("  %s -p 1234 --release                   # release all shadows\n", prog);
}

/*
 * target_pid - 将命令行传入的 pid 转换为实际目标 PID
 *
 * 位置：PID 处理辅助函数
 * 用途：当用户未指定 -p 或传入 0 时，默认作用于本进程自身，
 *       方便调试工具对自身进行插桩测试。
 * 实现：pid 非零时直接返回，否则返回 getpid()。
 */
static pid_t target_pid(pid_t pid)
{
    return pid ? pid : getpid(); /* pid=0 时作用于本进程 */
}

/*
 * open_maps_file - 打开目标进程的 /proc/<pid>/maps 文件
 *
 * 位置：/proc 文件系统访问辅助函数
 * 用途：maps 文件包含进程的完整虚拟内存布局（地址范围、权限、映射名称），
 *       是定位动态库基址和列出可执行区域的数据来源。
 * 实现：pid=0 时使用 /proc/self/maps 访问本进程，否则构造 /proc/<pid>/maps。
 */
static FILE *open_maps_file(pid_t pid)
{
    char path[256]; /* maps 文件路径缓冲区 */

    if (pid == 0)
        snprintf(path, sizeof(path), "/proc/self/maps"); /* 操作本进程 */
    else
        snprintf(path, sizeof(path), "/proc/%d/maps", pid); /* 操作目标进程 */

    return fopen(path, "r");
}

/*
 * run_wxshadow_prctl - 执行 wxshadow prctl 命令的统一封装
 *
 * 位置：内核通信核心接口
 * 用途：所有与内核模块的交互均通过此函数路由，统一处理错误打印，
 *       避免每个操作函数重复编写 errno 检查和错误输出逻辑。
 * 实现：调用 prctl(option, pid, addr, arg4, arg5)；失败时打印
 *       命令名称、错误描述和 errno 值，返回 -1 供调用方判断。
 *
 * @name:   命令名称字符串，仅用于错误信息（如 "SET_BP"）
 * @option: PR_WXSHADOW_* 命令码
 * @pid:    目标进程 PID（0 表示本进程）
 * @addr:   目标虚拟地址
 * @arg4:   第四个参数，语义因命令不同而异
 * @arg5:   第五个参数，语义因命令不同而异
 */
static int run_wxshadow_prctl(const char *name, int option, pid_t pid,
                              unsigned long addr, unsigned long arg4,
                              unsigned long arg5)
{
    int ret = prctl(option, pid, addr, arg4, arg5); /* 向内核模块发送命令 */

    if (ret < 0) {
        fprintf(stderr, "prctl(%s) failed: %s (errno=%d)\n",
                name, strerror(errno), errno);
        return -1;
    }

    return 0;
}

/*
 * parse_reg_name - 将寄存器名称字符串转换为索引
 *
 * 位置：寄存器名称解析辅助函数
 * 用途：用户以 "x0"、"x30"、"sp" 等可读形式指定寄存器，
 *       内核侧使用数字索引访问 pt_regs，需在此完成转换。
 * 实现：
 *   - "sp" → 31（ARM64 ABI 中 sp 对应索引 31）
 *   - "xN" → N（N 范围 0–30）
 *   - 其他输入 → -1（表示解析失败）
 */
/* Parse register name to index */
static int parse_reg_name(const char *name) {
    if (strcasecmp(name, "sp") == 0) /* sp 寄存器特殊处理，索引固定为 31 */
        return 31;

    if (tolower(name[0]) == 'x') {   /* 处理 x0–x30 通用寄存器 */
        int idx = atoi(name + 1);    /* 提取 'x' 后面的数字部分 */
        if (idx >= 0 && idx <= 30)
            return idx;
    }

    return -1; /* 无法识别的寄存器名称 */
}

/*
 * parse_reg_mod - 解析 "寄存器=值" 格式的寄存器修改字符串
 *
 * 位置：-r 选项参数解析函数
 * 用途：将用户输入（如 "x0=0x100"、"sp=0"）解析为内核可用的
 *       reg_mod 结构，供后续 PR_WXSHADOW_SET_REG 调用使用。
 * 实现：
 *   1. 定位 '=' 分隔符，提取左侧寄存器名和右侧数值
 *   2. 调用 parse_reg_name() 获取寄存器索引
 *   3. 用 strtoull() 解析数值（支持十六进制前缀 0x）
 *   返回 0 成功，-1 格式错误。
 */
/* Parse register modification string like "x0=123" */
static int parse_reg_mod(const char *str, struct reg_mod *mod) {
    char reg_name[16];
    char *eq = strchr(str, '='); /* 定位 '=' 分隔符 */

    if (!eq || eq == str) /* '=' 缺失或寄存器名为空 */
        return -1;

    size_t name_len = eq - str; /* 寄存器名称长度（不含 '='）*/
    if (name_len >= sizeof(reg_name))
        return -1;

    strncpy(reg_name, str, name_len);
    reg_name[name_len] = '\0'; /* 手动添加终止符 */

    mod->reg_idx = parse_reg_name(reg_name); /* 转换为寄存器索引 */
    if (mod->reg_idx < 0)
        return -1;

    mod->value = strtoull(eq + 1, NULL, 0); /* 支持十进制和十六进制 */
    return 0;
}

/*
 * find_lib_base - 在 /proc/<pid>/maps 中查找动态库的加载基址
 *
 * 位置：库地址解析函数（支持 -b lib -o offset 模式）
 * 用途：用户可通过库名+偏移指定断点地址，无需手动查找基址。
 *       此函数扫描目标进程的内存映射，找到与库名匹配的第一个
 *       可读/可执行段，返回其起始地址作为库基址。
 * 实现：
 *   1. 打开 /proc/<pid>/maps，逐行读取
 *   2. 用 strstr() 匹配库名（支持路径中的任意子串匹配）
 *   3. 验证该段具有 r-xp（可执行）或 r--p（只读，.text 前的 ELF 头）权限
 *   4. 返回该段起始地址；未找到返回 0
 *
 * 注意：匹配的是第一个符合权限的段，对于 PIE 可执行文件
 *       和大多数 .so 库，该段起始地址即为加载基址。
 */
/* Find library base address in /proc/pid/maps */
static unsigned long find_lib_base(pid_t pid, const char *lib_name) {
    char line[512];
    FILE *fp;

    fp = open_maps_file(pid);
    if (!fp) {
        perror("fopen maps");
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name)) {          /* 行中包含库名子串 */
            unsigned long start;
            if (sscanf(line, "%lx-", &start) == 1) {
                /* Check if it's executable */
                if (strstr(line, "r-xp") || strstr(line, "r--p")) { /* 只取可读/可执行段 */
                    fclose(fp);
                    return start; /* 返回该段起始地址作为库基址 */
                }
            }
        }
    }

    fclose(fp);
    return 0; /* 未找到匹配的库 */
}

/*
 * show_maps - 列出目标进程的所有可执行内存区域
 *
 * 位置：-m 选项的处理函数
 * 用途：帮助用户了解目标进程的内存布局，找到需要插桩的代码段
 *       及其对应的起始地址，便于配合 -a 或 -b/-o 选项使用。
 * 实现：
 *   1. 读取 /proc/<pid>/maps 的每一行
 *   2. 解析起始地址、结束地址和权限字段
 *   3. 仅打印权限第三位为 'x'（可执行）的段
 *   4. 提取行尾的映射名称（去除换行符后输出）
 */
/* Show executable memory regions */
static void show_maps(pid_t pid) {
    char line[512];
    FILE *fp;

    fp = open_maps_file(pid);
    if (!fp) {
        perror("fopen maps");
        return;
    }

    printf("Executable regions for pid %d:\n", target_pid(pid));
    printf("%-18s %-18s %-5s %s\n", "Start", "End", "Perm", "Name");
    printf("------------------------------------------------------------------\n");

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end;
        char perms[8];  /* 权限字符串，如 "r-xp" */
        char *name;     /* 映射名称（库路径或 [heap]/[stack] 等）*/

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) < 3)
            continue;

        /* Only show executable regions */
        if (perms[2] != 'x') /* 权限字符串第三位：'x' 表示可执行 */
            continue;

        /* Find name (last field) */
        name = strrchr(line, ' '); /* 最后一个空格之后即为映射名称 */
        if (name) {
            name++;
            /* Remove newline */
            char *nl = strchr(name, '\n');
            if (nl) *nl = '\0'; /* 去掉行尾换行符 */
        } else {
            name = ""; /* 匿名映射无名称 */
        }

        printf("0x%016lx 0x%016lx %-5s %s\n", start, end, perms, name);
    }

    fclose(fp);
}

/*
 * set_breakpoint - 在指定地址设置隐藏断点
 *
 * 位置：断点设置核心操作函数
 * 用途：向内核模块发送 SET_BP 命令，触发 shadow 页面的创建：
 *       内核复制目标代码页为 shadow 页，在断点处写入 BRK 指令，
 *       并将 PTE 切换为 --x 权限（仅可执行）。此后进程执行到该地址
 *       会触发 BRK，而读取时将看到原始代码（透明隐藏效果）。
 * 实现：调用 run_wxshadow_prctl(SET_BP)，成功后打印确认信息。
 */
/* Set breakpoint via prctl */
static int set_breakpoint(pid_t pid, unsigned long addr) {
    if (run_wxshadow_prctl("SET_BP", PR_WXSHADOW_SET_BP, pid, addr, 0, 0) < 0)
        return -1;

    printf("Breakpoint set at 0x%lx for pid %d\n", addr, target_pid(pid));
    return 0;
}

/*
 * set_reg_mod - 为断点附加寄存器修改规则
 *
 * 位置：寄存器修改设置函数（-r 选项的执行函数）
 * 用途：在断点触发（BRK 处理）时，内核会查找该地址对应的寄存器
 *       修改规则，并在恢复执行前修改 pt_regs 中的目标寄存器。
 *       此功能可用于强制修改函数参数、返回值或控制流。
 * 实现：
 *   - prctl(SET_REG, pid, addr, reg_idx, value)
 *   - arg4=reg_idx（寄存器索引），arg5=value（目标值）
 *   - 成功后打印寄存器名称和目标值（sp 单独处理显示名称）
 */
/* Set register modification via prctl */
static int set_reg_mod(pid_t pid, unsigned long addr, int reg_idx, unsigned long value) {
    if (run_wxshadow_prctl("SET_REG", PR_WXSHADOW_SET_REG, pid, addr,
                           reg_idx, value) < 0) {
        return -1;
    }

    if (reg_idx == 31) /* 索引 31 对应 sp 寄存器，单独处理打印名称 */
        printf("Register modification set: sp = 0x%lx\n", value);
    else
        printf("Register modification set: x%d = 0x%lx\n", reg_idx, value);

    return 0;
}

/*
 * del_breakpoint - 删除断点及其关联的寄存器修改规则
 *
 * 位置：断点删除操作函数（-d 选项的执行函数）
 * 用途：通知内核模块移除断点元数据，但不释放 shadow 页面映射
 *       （shadow 页仍存在，只是不再写入 BRK）。若需同时还原页面
 *       映射，应使用 release_shadow()。
 * 实现：
 *   - addr=0：删除目标进程所有断点（批量清理）
 *   - addr≠0：仅删除指定地址的断点
 */
/* Delete breakpoint via prctl (addr=0 means delete all) */
static int del_breakpoint(pid_t pid, unsigned long addr) {
    if (run_wxshadow_prctl("DEL_BP", PR_WXSHADOW_DEL_BP, pid, addr, 0, 0) < 0)
        return -1;

    if (addr == 0)
        printf("All breakpoints deleted for pid %d\n", target_pid(pid));
    else
        printf("Breakpoint deleted at 0x%lx for pid %d\n", addr, target_pid(pid));
    return 0;
}

/*
 * parse_hex_string - 将十六进制字符串解析为二进制字节数组
 *
 * 位置：--patch 选项的数据解析辅助函数
 * 用途：用户以十六进制字符串形式（如 "d503201f" = NOP 指令）
 *       输入 patch 数据，此函数将其转换为实际字节序列，
 *       以便通过 prctl(PATCH) 写入 shadow 页面。
 * 实现：
 *   1. 验证字符串长度为偶数（每字节对应两个十六进制字符）
 *   2. 验证输出长度不超过缓冲区上限
 *   3. 逐对字符调用 sscanf("%2x") 转换为字节
 *   返回解析的字节数，失败返回 -1。
 *
 * 注意：输入字节序为用户指定顺序，不做字节序转换。
 *       ARM64 小端：写入 "e0030091" 对应 add x0, sp, #0。
 */
/* Parse hex string to binary data. Returns number of bytes, or -1 on error */
static int parse_hex_string(const char *hex, unsigned char *out, int max_len) {
    int len = strlen(hex);
    int i, out_len;

    if (len % 2 != 0) { /* 十六进制字符串必须为偶数长度 */
        fprintf(stderr, "Hex string must have even length\n");
        return -1;
    }

    out_len = len / 2; /* 每两个十六进制字符对应一个字节 */
    if (out_len > max_len) {
        fprintf(stderr, "Hex data too long (%d bytes, max %d)\n", out_len, max_len);
        return -1;
    }

    for (i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) { /* 逐字节解析 */
            fprintf(stderr, "Invalid hex at position %d\n", i * 2);
            return -1;
        }
        out[i] = (unsigned char)byte;
    }

    return out_len; /* 返回成功解析的字节数 */
}

/*
 * patch_shadow - 向 shadow 页面写入自定义字节数据
 *
 * 位置：--patch 选项的执行函数
 * 用途：直接修改 shadow 页面的内容（不限于 BRK 指令），
 *       实现任意代码 patch（如 NOP、ret、跳转指令替换等），
 *       而不影响进程通过 /proc/pid/mem 或 ptrace 读取到的原始代码。
 * 实现：
 *   - prctl(PATCH, pid, addr, buf_ptr, data_len)
 *   - 内核通过 copy_from_user 读取用户态缓冲区后写入 shadow VA
 *   - 限制：patch 数据不能跨页（offset + len ≤ PAGE_SIZE）
 *
 * @data:     待写入的二进制数据（已由 parse_hex_string 转换）
 * @data_len: 数据字节数
 */
/* Patch shadow page via prctl */
static int patch_shadow(pid_t pid, unsigned long addr,
                        unsigned char *data, int data_len) {
    if (run_wxshadow_prctl("PATCH", PR_WXSHADOW_PATCH, pid, addr,
                           (unsigned long)data, data_len) < 0) {
        return -1;
    }

    printf("Shadow page patched at 0x%lx (%d bytes) for pid %d\n",
           addr, data_len, target_pid(pid));
    return 0;
}

/*
 * release_shadow - 释放 shadow 页面，恢复原始页面映射
 *
 * 位置：--release 选项的执行函数
 * 用途：完全撤销 wxshadow 对指定地址（或全部地址）的修改：
 *       释放 shadow 物理页，将 PTE 恢复为原始代码页，
 *       使进程恢复正常执行（不再触发 BRK）。
 *       适用于需要临时插桩后干净退出的场景。
 * 实现：
 *   - 直接调用 prctl(RELEASE) 而非通过 run_wxshadow_prctl()，
 *     以便对 ENODATA 错误进行专项处理（addr 不为 0 时提示找不到修改）
 *   - addr=0：释放目标进程所有 shadow 页面
 *   - addr≠0：仅释放指定地址所在页面的修改
 */
/* Release shadow modification via prctl (addr=0 means release all) */
static int release_shadow(pid_t pid, unsigned long addr) {
    int ret = prctl(PR_WXSHADOW_RELEASE, pid, addr, 0, 0);
    if (ret < 0) {
        if (errno == ENODATA && addr != 0) {
            /* 指定地址处没有找到任何 shadow 修改记录 */
            fprintf(stderr, "prctl(RELEASE) failed: no modification found at 0x%lx\n",
                    addr);
            return -1;
        }
        fprintf(stderr, "prctl(RELEASE) failed: %s (errno=%d)\n",
                strerror(errno), errno);
        return -1;
    }
    if (addr == 0)
        printf("All shadow pages released for pid %d\n", target_pid(pid));
    else
        printf("Modification released at 0x%lx for pid %d\n", addr, target_pid(pid));
    return 0;
}

/*
 * main - 程序入口：解析命令行参数并分发执行相应操作
 *
 * 位置：程序主函数
 * 用途：作为用户与 wxshadow 内核模块之间的交互入口，
 *       解析命令行选项，构造操作参数，并按优先级顺序
 *       分发到对应的操作函数（show_maps / release / delete /
 *       patch / set_breakpoint + set_reg_mod）。
 * 实现流程：
 *   1. 定义长选项表（long_options），支持 GNU 风格长选项
 *   2. 用 getopt_long() 循环解析所有选项，填充操作参数
 *   3. 按以下优先级依次检查并执行操作：
 *      a. -m（show maps）：独立模式，执行后立即返回
 *      b. -b/-o（库名+偏移）：将库基址+偏移转换为绝对地址
 *      c. --release：释放 shadow 页面
 *      d. -d（delete）：删除断点
 *      e. --patch：向 shadow 页写入自定义数据
 *      f. 默认：设置断点，附加寄存器修改
 */
int main(int argc, char *argv[]) {
    /*
     * 长选项定义表
     * 每项格式：{长选项名, 是否需要参数, 标志指针, 短选项字符}
     * 与 getopt_long() 的 optstring "p:a:b:o:r:dmh" 对应。
     * 'P' 和 'L' 为仅长选项（--patch/--release），无对应短选项字符。
     */
    static struct option long_options[] = {
        {"pid",     required_argument, 0, 'p'}, /* -p/--pid: 目标进程 PID */
        {"addr",    required_argument, 0, 'a'}, /* -a/--addr: 目标虚拟地址（十六进制）*/
        {"base",    required_argument, 0, 'b'}, /* -b/--base: 动态库名称（用于基址查找）*/
        {"offset",  required_argument, 0, 'o'}, /* -o/--offset: 库内偏移量（十六进制）*/
        {"reg",     required_argument, 0, 'r'}, /* -r/--reg: 寄存器修改，格式 xN=value */
        {"delete",  no_argument,       0, 'd'}, /* -d/--delete: 删除断点标志 */
        {"maps",    no_argument,       0, 'm'}, /* -m/--maps: 显示可执行内存区域 */
        {"patch",   required_argument, 0, 'P'}, /* --patch: shadow 页 patch 数据（十六进制字符串）*/
        {"release", no_argument,       0, 'L'}, /* --release: 释放 shadow 页面 */
        {"help",    no_argument,       0, 'h'}, /* -h/--help: 打印帮助信息 */
        {0, 0, 0, 0}                            /* 选项表终止符 */
    };

    pid_t pid = 0;                      /* 目标进程 PID，0 表示本进程 */
    unsigned long addr = 0;             /* 目标虚拟地址（断点/patch/release 的目标）*/
    unsigned long offset = 0;           /* 库内偏移量（配合 -b 使用）*/
    char *lib_name = NULL;              /* 动态库名称（用于查找基址）*/
    int do_delete = 0;                  /* 是否执行删除断点操作 */
    int do_maps = 0;                    /* 是否执行显示内存映射操作 */
    char *patch_hex = NULL;             /* --patch 的十六进制字符串参数 */
    int do_release = 0;                 /* 是否执行释放 shadow 操作 */
    struct reg_mod reg_mods[MAX_REG_MODS]; /* 寄存器修改规则数组（最多 4 条）*/
    int nr_reg_mods = 0;                /* 已解析的寄存器修改条目数 */

    int opt;           /* getopt_long 返回的当前选项字符 */
    int option_index = 0; /* 长选项在 long_options 中的索引（getopt_long 填充）*/

    if (argc < 2) { /* 未提供任何参数时打印帮助并退出 */
        print_usage(argv[0]);
        return 1;
    }

    /*
     * 命令行选项解析循环
     *
     * getopt_long 每次调用返回一个已匹配的选项字符，
     * 返回 -1 表示所有选项已处理完毕。
     * optarg 指向当前选项的参数字符串（required_argument 时有效）。
     */
    while ((opt = getopt_long(argc, argv, "p:a:b:o:r:dmh",
                              long_options, &option_index)) != -1) {
        switch (opt) {
        case 'p':
            pid = atoi(optarg);              /* 解析目标 PID */
            break;
        case 'a':
            addr = strtoull(optarg, NULL, 0); /* 解析地址，支持 0x 十六进制前缀 */
            break;
        case 'b':
            lib_name = optarg;               /* 记录库名，延迟到参数解析完成后查找基址 */
            break;
        case 'o':
            offset = strtoull(optarg, NULL, 0); /* 解析库内偏移，支持十六进制 */
            break;
        case 'r':
            if (nr_reg_mods >= MAX_REG_MODS) { /* 超出最大寄存器修改数量限制 */
                fprintf(stderr, "Too many register modifications (max %d)\n",
                        MAX_REG_MODS);
                return 1;
            }
            if (parse_reg_mod(optarg, &reg_mods[nr_reg_mods]) < 0) {
                fprintf(stderr, "Invalid register modification: %s\n", optarg);
                fprintf(stderr, "Format: x0=value or sp=value\n");
                return 1;
            }
            nr_reg_mods++; /* 成功解析一条寄存器修改规则 */
            break;
        case 'd':
            do_delete = 1;  /* 标记执行删除断点操作 */
            break;
        case 'm':
            do_maps = 1;    /* 标记执行显示内存映射操作 */
            break;
        case 'P':
            patch_hex = optarg; /* 记录 patch 十六进制字符串 */
            break;
        case 'L':
            do_release = 1; /* 标记执行释放 shadow 操作 */
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Show maps mode */
    if (do_maps) { /* -m 模式：列出可执行区域后立即退出，不执行其他操作 */
        show_maps(pid);
        return 0;
    }

    /* Calculate address from lib+offset if specified */
    if (lib_name) {
        /* 通过库名在 /proc/<pid>/maps 中查找加载基址，计算绝对地址 */
        unsigned long base = find_lib_base(pid, lib_name);
        if (base == 0) {
            fprintf(stderr, "Library '%s' not found in pid %d maps\n",
                    lib_name, pid ? pid : getpid());
            return 1;
        }
        addr = base + offset; /* 绝对地址 = 库基址 + 用户指定偏移 */
        printf("Found %s at base 0x%lx, target addr = 0x%lx\n",
               lib_name, base, addr);
    }

    /* Release mode (addr=0 means release all) */
    if (do_release) { /* --release 模式：addr=0 释放全部，否则释放指定地址 */
        return release_shadow(pid, addr) < 0 ? 1 : 0;
    }

    /* Delete mode (addr=0 means delete all) */
    if (do_delete) { /* -d 模式：addr=0 删除全部断点，否则删除指定地址断点 */
        return del_breakpoint(pid, addr) < 0 ? 1 : 0;
    }

    if (addr == 0 && !do_maps) { /* 需要地址的操作但未指定地址，报错退出 */
        fprintf(stderr, "No address specified. Use -a <addr> or -b <lib> -o <offset>\n");
        return 1;
    }

    /* Patch mode */
    if (patch_hex) {
        /* --patch 模式：解析十六进制字符串为字节数据，写入 shadow 页 */
        unsigned char patch_buf[4096]; /* patch 数据缓冲区，最大 4096 字节（一页）*/
        int patch_len = parse_hex_string(patch_hex, patch_buf, sizeof(patch_buf));
        if (patch_len < 0)
            return 1;
        return patch_shadow(pid, addr, patch_buf, patch_len) < 0 ? 1 : 0;
    }

    /* Set breakpoint */
    if (set_breakpoint(pid, addr) < 0) /* 在指定地址创建 shadow 断点 */
        return 1;

    /* Set register modifications */
    for (int i = 0; i < nr_reg_mods; i++) {
        /* 逐条向内核注册寄存器修改规则，任一条失败则中止 */
        if (set_reg_mod(pid, addr, reg_mods[i].reg_idx, reg_mods[i].value) < 0)
            return 1;
    }

    return 0;
}
