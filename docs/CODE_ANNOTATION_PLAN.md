# mkpms 代码全量注释与分析方案（位置 -> 用途 -> 实现）

> 目标：给仓库内主要 C/C 头文件提供“可执行的全量注释方案”，并给出每个模块的分析路径、关键函数位置、用途和实现摘要。

## 1. 总体架构（先理解再注释）

- `tools/kpatch/kpatch.c`：用户态工具，负责通过 `supercall` 与内核补丁框架交互（加载/卸载/控制 KPM）。
- `kpms/demo-*`：最小 demo（hello、syscallhook、inlinehook），用于演示 KPM 生命周期与 hook 接口调用方式。
- `kpms/anti-detect`：反检测样例，围绕 syscall hook 与目录项过滤实现“隐藏”。
- `kpms/hide-maps`：通过 hook `show_map_vma` 隐藏 maps 可见性。
- `kpms/wxshadow`：核心模块，提供“读原页、执行影子页”的隐蔽断点/patch 基础设施。

## 2. 全量注释执行标准（统一模板）

建议对每个函数都补充如下 5 类注释：

1. **用途**：这个函数为谁服务，解决什么问题。
2. **输入/输出**：关键参数、返回值、错误码语义。
3. **实现要点**：核心算法/状态机/锁语义。
4. **并发与上下文**：进程上下文/中断上下文、是否可睡眠、锁顺序。
5. **风险点**：越界、UAF、竞态、TLB 同步、跨版本符号适配。

推荐注释格式：

```c
/*
 * [用途] ...
 * [输入] ...
 * [输出] ...
 * [实现] ...
 * [并发] ...
 * [风险] ...
 */
```

## 3. 位置 -> 用途 -> 实现（按文件）

> 说明：下面位置来自源码中函数定义/关键宏区域，便于你逐点补注释。`wxshadow` 体量大，已按子模块聚类给出优先级。

### 3.1 tools/kpatch/kpatch.c

| 位置 | 用途 | 实现内容 |
|---|---|---|
| L46 `ver_and_cmd` | 组装 supercall 命令字 | 将主版本和子命令编码到统一参数 |
| L54~L89 `sc_*` | supercall 封装层 | 一组薄封装，直接调用 `syscall(__NR_supercall,...)` |
| L96 `cmd_hello` | 连通性自检 | 调用 hello 接口并打印返回 |
| L113/L123 `cmd_kpm_*` | 模块加载卸载 | 处理 key、模块名与路径参数后调用 supercall |
| L133~L151 `cmd_kpm_*` | 信息查询 | 列举模块数量/列表/信息 |
| L163/L177 `usage*` | 帮助输出 | 输出参数说明与命令用法 |
| L190 `main` | CLI 分发入口 | 参数解析 + 调度具体子命令 |

### 3.2 kpms/demo-hello/hello.c

| 位置 | 用途 | 实现内容 |
|---|---|---|
| L25 `hello_init` | 模块初始化演示 | 打日志、返回状态 |
| L31/L36 `hello_control*` | 控制接口演示 | 响应 `KPM_CTL0/1` |
| L42 `hello_exit` | 模块退出演示 | 释放/记录退出日志 |
| L48~L51 `KPM_*` | 生命周期导出 | 将函数绑定给 KPM 框架 |

### 3.3 kpms/demo-inlinehook/inlinehook.c

| 位置 | 用途 | 实现内容 |
|---|---|---|
| L19 `add` | 被 hook 目标函数 | 便于验证 before/after 效果 |
| L26 `before_add` | 前置 hook | 在原函数前观察/改写参数 |
| L31 `after_add` | 后置 hook | 在原函数后观察/改写返回值 |
| L37 `inline_hook_demo_init` | 安装 inline hook | 注册 hook 点并保存句柄 |
| L56 `inline_hook_control0` | 控制触发 | 用于演示运行态控制 |
| L61 `inline_hook_demo_exit` | 卸载 hook | 解除 hook、清理状态 |

### 3.4 kpms/demo-syscallhook/syscallhook.c

| 位置 | 用途 | 实现内容 |
|---|---|---|
| L37/L62 `before_openat_*` | openat 前置 hook | 拿到路径参数并做过滤/打印 |
| L69 `after_openat_1` | openat 后置 hook | 观察返回 fd/errno |
| L74 `syscall_hook_demo_init` | syscall hook 注册 | 挂接 openat 相关处理 |
| L113 `syscall_hook_control0` | 控制接口 | demo 控制路径 |
| L118 `syscall_hook_demo_exit` | 卸载 hook | 注销 hook，收尾 |

### 3.5 kpms/hide-maps/hidemaps.c

| 位置 | 用途 | 实现内容 |
|---|---|---|
| L31 `show_map_vma_before` | maps 显示前拦截 | 判断当前 VMA 是否需隐藏 |
| L36 `show_map_vma_after` | maps 显示后处理 | 调整输出或统计信息 |
| L67 `hello_init` | 初始化 | 安装 show_map_vma hook |
| L88 `hello_control0` | 运行态控制 | 切换隐藏策略 |
| L95 `hello_exit` | 退出 | 卸载 hook |

### 3.6 kpms/anti-detect/anti-detect-supercall.c

| 位置 | 用途 | 实现内容 |
|---|---|---|
| L36 `supercall_guard_before` | supercall 前置校验 | 对 key / cmd 做访问约束 |
| L55 `supercall_guard_init` | 初始化 guard | 安装 supercall hook |
| L75 `supercall_guard_exit` | 退出 | 卸载 supercall guard |

### 3.7 kpms/anti-detect/anti-detect.c

| 位置 | 用途 | 实现内容 |
|---|---|---|
| L61 `should_hide` | 统一隐藏判定 | 按 UID/路径/关键字判断 |
| L71 `before_stat_syscall` | stat 前置隐藏 | 对文件探测请求做拦截 |
| L88 `getdents_has_hidden` | 目录项扫描 | 判断返回结果中是否有目标项 |
| L108 `after_getdents64` | getdents 后处理 | 重写用户缓冲、移除敏感目录项 |
| L161 `resolve_symbols` | 符号解析 | 适配不同内核符号地址 |
| L217 `anti_detect_init` | 主初始化 | 装载多处 syscall hook |
| L251 `anti_detect_exit` | 主退出 | 卸载所有 hook，清理资源 |

### 3.8 kpms/wxshadow（核心）

#### A) `wxshadow.c`（生命周期、页状态管理、全局控制）

- 关键入口：`wxshadow_init`(L1347) / `wxshadow_exit`(L1593) / `wxshadow_control`(L1702)
- 页面对象：`wxshadow_find_page`(L217)、`wxshadow_create_page`(L239)、`wxshadow_free_page`(L270)
- 脏位图：`wxshadow_bitmap_*`(L340/L359/L378/L392)
- 状态切换：`wxshadow_release_page_*`(L685/L814)、`wxshadow_teardown_*`(L1008/L1147)
- 故障处理：`wxshadow_handle_write_fault`(L1264)

#### B) `wxshadow_bp.c`（断点/patch 写入通路）

- 写上下文：`wxshadow_acquire_write_ctx`(L346) -> `wxshadow_activate_write_ctx`(L390)
- 断点与寄存器修改：`wxshadow_do_set_bp`(L904)、`wxshadow_do_set_reg`(L970)、`wxshadow_do_del_bp`(L1199)
- patch 执行：`wxshadow_do_patch`(L1080)
- release：`wxshadow_do_release`(L1175)
- prctl 入口：`prctl_before`(L1241)

#### C) `wxshadow_handlers.c`（缺页、fork、brk/step 事件）

- 缺页：`do_page_fault_before_impl`(L126)
- GUP 路径：`follow_page_pte_before_impl`(L210)、`follow_page_pte_after_impl`(L259)
- fork 复制：`before_copy_process_wx`(L620)、`after_copy_process_wx`(L643)
- brk/step：`wxshadow_brk_handler_impl`(L805)、`wxshadow_step_handler_impl`(L906)

#### D) `wxshadow_pgtable.c`（页表改写与 TLB）

- PTE 获取/改写：`get_user_pte`(L249)、`wxshadow_set_pte_at_raw`(L330)、`wxshadow_write_pte_raw`(L501)
- 映射切换：`wxshadow_page_switch_mapping_locked`(L531)
- 状态迁移：`wxshadow_page_enter_original`(L604)、`wxshadow_page_resume_shadow`(L646)
- TLB：`wxshadow_tlbi_page`(L368)、`wxshadow_flush_tlb_page`(L423)

#### E) `wxshadow_scan.c`（符号/结构体偏移扫描）

- 动态符号解析：`resolve_symbols`(L66)
- 偏移扫描：`scan_mm_struct_offsets`(L462)、`scan_vma_struct_offsets`(L481)
- 上下文 ID 偏移：`try_scan_mm_context_id_offset`(L1021)

#### F) `wxshadow_client.c`（用户态测试客户端）

- 命令解析：`main`(L312)
- 断点设置：`set_breakpoint`(L216)
- patch 下发：`patch_shadow`(L280)
- release：`release_shadow`(L293)
- maps 查看：`show_maps`(L172)

## 4. 完整分析方案（可落地流程）

### 阶段 1：建立“注释基线”（1 天）

- 为每个 `.c` 文件补充**文件头注释**：模块职责、关键依赖、线程模型。
- 为每个导出入口（`KPM_INIT/KPM_EXIT/KPM_CTL*`）补充“调用时机 + 失败回滚”说明。
- 输出产物：`docs/ANNOTATION_PROGRESS.md`（记录每个文件完成百分比）。

### 阶段 2：函数级全量注释（2~4 天）

- 小模块（demo/anti-detect/hide-maps）先完成 100%。
- `wxshadow` 按 A~F 子模块分批完成，每批至少覆盖：
  - 入口函数
  - 状态迁移函数
  - 与用户态接口直接相关函数

### 阶段 3：数据结构与状态机注释（2 天）

- 对 `wxshadow_internal.h` 内核心结构体补“字段语义 + 生命周期 + 所属锁”。
- 绘制状态机：`ORIGINAL -> SHADOW -> STEPPING -> DORMANT -> TEARDOWN`。

### 阶段 4：验证与回归（1 天）

- 编译检查（至少 `CMake` + 目标模块）。
- 使用 `wxshadow_client` 跑：`set_bp` / `patch` / `release`。
- 对注释中提及的风险点做“可复现步骤”说明。

## 5. 建议优先注释清单（价值最高）

1. `kpms/wxshadow/wxshadow.c` 的 init/exit/control 与 teardown 相关路径。
2. `kpms/wxshadow/wxshadow_bp.c` 的 patch、set_bp、release 主链路。
3. `kpms/wxshadow/wxshadow_handlers.c` 的 page fault + brk/step。
4. `kpms/anti-detect/anti-detect.c` 的 getdents64 后处理逻辑。

## 6. 交付物建议

- `docs/CODE_ANNOTATION_PLAN.md`（本文件）：总方案与点位索引。
- `docs/ANNOTATION_PROGRESS.md`：按文件记录已注释函数数/总函数数。
- 代码内注释增量：每次提交至少完成一个子模块（避免超大 PR）。

