# PWN 速查

1. **确认环境**：架构、PIE、canary、NX、RELRO 实际映射、libc、seccomp、进程/连接模型。静态链接先查符号与可写 GOT 两处；fd 编号画账本（监听 fd 是否已关、stdio、会话 socket）而不是套经验值。
2. **定位原语**：输入边界、整数截断、负索引、UAF、类型混淆、释放后复用、校验与使用分离；同一长度在"分配/拷贝/输出"三段是否同源；缓存失效判据用的是槽号/名字还是对象身份。菜单题逐项看 add/show/edit/free。
3. **选最短链**：泄露基址 → 读写/控制流 → ORW 或题目规定终点。先单步验证 leak/写原语；核对 fd、栈对齐和 syscall 白名单。
4. **按族检查**：堆利用核对 glibc/safe-linking/对象布局；VM/JS 查 opcode/tag/GC/JIT 假设；内核/QEMU/驱动查生命周期、回调、DMA/MMIO 和版本补丁；协议题核长度、状态机和"配置/表上传是否被当代码执行"。
5. **重连状态分两层**：地址类（PIE/堆/栈/libc）默认每次重取；密钥、canary、服务端种子先做两次独立探测，确认跨连接同值后才复用。协议题先写编码器/解析器和正常交互回归，再加畸形字段；否则协议错误会伪装成漏洞不稳定。

细分技巧/版本案例见 [`field-notes/pwn.md`](field-notes/pwn.md)。生成器/编译器输出需作为新执行目标分析；完整链前先用良性返回或输出 marker 验证偏移与控制流。EOF、短读、协议无回显时先查 [协议边界](protocols.md) 和 [阻塞诊断](blockers.md)。

只有一比特反馈、要算请求预算、内核 slide 或 JIT 类型漂移，读 [一比特 oracle 与预算](pwn-oracle.md)；别名/缓存键、入口缓存指针、释放后复用与"表即代码"，读 [对象、缓存与析构](pwn-objects.md)。ucontext/SROP、恢复器第二跳断开或 ORW 零长度输出，读 [上下文 ROP 与分阶段 I/O](pwn-runtime.md)。
