# 上下文 ROP 与分阶段 I/O

用于 `getcontext/makecontext/swapcontext/setcontext`、自定义恢复器、SROP 或“本地链正常、远程第二跳断开”。从一次成功的无害 marker 向后扩链，逐阶段确定控制流、参数与返回值。

## 恢复器不是抽象的“加载全部寄存器”

- 以附件 libc、ld 和实际入口的反汇编为准，分别列恢复前后寄存器、栈和内存约束。glibc 包装可能执行 `rt_sigprocmask`、`fldenv/ldmxcsr`，恢复器尾部可能清零 RAX，或 `push rip; ret`；先验证这些路径与 seccomp、有效 fpstate/MXCSR 是否相容。
- `makecontext` 在协程栈上放置的入口、trampoline、`uc_link` 及 RBX 值，要用实际栈转储核对。可写的负索引也许命中 `uc_link` 槽；不得由相邻表的静态偏移直接猜恢复帧。
- 计算第一次 gadget 已经由恢复器跳入还是从 ROP 栈弹出。例如当 `F.rip=chain[0]` 且其已消费入口，`F.rsp` 应指向后续参数；按实际指令推导，不能一概把 rsp 加 8。
- 对自定义 rsp 相对分发器，以**进入时 rsp**为基准给每个 qword 标注角色。`ret/call/jmp` 对 rsp 的影响不同，frame 的偏移、pivot 距离和 landing zone 要统一坐标系。

## marker → 装载 → 系统调用 → 读回

1. 先恢复到已知 `write` 或正常返回，证明审计值/控制流已过；把同连接内第二次调用单独测，不立即加入完整 ORW。
2. 恢复器不宜反复使用时，可尝试一次分发到 `read`，将 rsp 迁至可写 landing zone，读入下一段再由其 ret 接力。一次可用只是当前路径的观测；“第二次 EOF”不证明存在外部审计或一次性限制，先排查栈错位、覆盖、短读、fd 和 seccomp。
3. 检查每个 libc wrapper 的寄存器副作用。`open()` 等变参包装可改 RDX，下一次 read/write 就可能变成零长度；显式重装参数，或在白名单允许且 ABI 核对后用 syscall gadget。`syscall` 也会改 RCX/R11，且返回值仍必须检查。
4. `open` 失败（如 ENOENT）、`read` 返回 0、`write` 发到错误 fd 和进程被杀分别观测。路径经裸 read 输入应明确 NUL、长度与换行，不能把 `sendline` 多出的 `\n` 算作路径终止符。相对路径基于实际 cwd；绝对路径不存在不等于 flag 不存在。
5. 优先把 open 返回 fd 传给 read，并让 write 使用真实读取长度；只有文件表与执行顺序有证据时才固定 fd。输出含 flag 样串后仍保留原始响应与实例信息。

**分段不可靠 sleep 保证**：TCP `sendall(stage)` 不保证一个 read 读满 stage；补齐 0x100 和延迟 0.3 秒也不保证阶段边界。只有在三个前提同时成立时才可用固定等待：处理是单线程按行/定长进行、有回显或长度前缀可做同步、上一阶段没有未消费的残留数据。其余情况先检查目标是否循环读、实际 read 返回值和后继消费者，用受控本地实验确认边界；完整 framing 见 [协议边界](protocols.md)。

来源为 `palimpsest/{writeup.md,exp2.py,debug12.py}` 与 `paroxysm/work/writeup.md`；当前仅复核记录和静态脚本，不继承 WP 的原因推断、固定偏移或远程成功等级。
