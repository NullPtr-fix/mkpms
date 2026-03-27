# 注释进度追踪

| 文件 | 计划状态 | 备注 |
|---|---|---|
| tools/kpatch/kpatch.c | done | 已补函数级用途注释 |
| kpms/demo-hello/hello.c | done | 已补 KPM 生命周期与控制接口注释 |
| kpms/demo-inlinehook/inlinehook.c | done | 已补 hook 链路注释，并修正 exit 返回值 |
| kpms/demo-syscallhook/syscallhook.c | done | 已补 openat hook 链路注释 |
| kpms/hide-maps/hidemaps.c | done | 已补 show_map_vma 前后回调注释 |
| kpms/anti-detect/anti-detect-supercall.c | done | 已补 supercall guard 注释 |
| kpms/anti-detect/anti-detect.c | done | 已补核心过滤链路注释 |
| kpms/wxshadow/wxshadow.c | in-progress | 已补 init/exit/teardown/dirty-tracking 关键函数注释 |
| kpms/wxshadow/wxshadow_bp.c | in-progress | 已补 set_bp/set_reg/patch/release 主链路注释 |
| kpms/wxshadow/wxshadow_handlers.c | in-progress | 已补 fault/fork/brk/step 主链路函数注释 |
| kpms/wxshadow/wxshadow_pgtable.c | done | 已补页表 walk + 映射切换/TLB/stepping/GUP 注释 |
| kpms/wxshadow/wxshadow_scan.c | done | 已补函数级+关键扫描分支+调试输出语义注释 |
| kpms/wxshadow/wxshadow_client.c | done | 已补 CLI 全链路函数级注释 |
| kpms/wxshadow/wxshadow_internal.h | done | 已补符号分组+内联工具+偏移读取/cache/fault 分类注释 |
| kpms/wxshadow/wxshadow.h | done | 已补状态机/prctl/核心结构体语义注释 |
| kpms/common/kpm_demo_helpers.h | done | 已补 helper 语义与边界注释 |
