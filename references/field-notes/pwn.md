# PWN 打法

## 0. 先归族（决定读哪几段）

| 家族 | 首动作 |
|---|---|
| 用户态堆/栈 | checksec + 菜单/输入点；先找 idx 边界与 free 后清零 |
| VM/字节码/解释器 | 逆指令表；查立即数边界、类型标签、GC 扫描表 |
| JS 引擎 | 版本指纹 + 补丁 diff；看 JIT 优化假设与 GC 写屏障 |
| 内核 | 版本/补丁缺口；对象生命周期（timer、rbtree、fd） |
| QEMU/虚拟化 | 设备模型、MMIO/DMA、reset/timer 生命周期 |
| Windows 驱动 | IOCTL 边界、对象缓存、符号/结构偏移 |
| 浏览器 | 版本+补丁 diff；渲染进程原语与事件循环 |
| 协议/工控 | 抓帧格式；上传表/配置是否被当代码执行 |

## 1. 侦察与初判

```bash
checksec --file=xx && file xx
readelf -lW xx        # GNU_RELRO 覆盖范围、LOAD filesz 与页边界差
seccomp-tools dump ./xx        # 先 dump 再定策略，别假设有 open/write
strings xx | grep -E "GNU C Library|GLIBC_"
```

保护组合 → 打法初判（只是候选方向，必须在实际二进制/运行时确认）：
- 无 canary + 栈溢出 → ret2libc / ret2shellcode（NX 关）
- **不要从 RELRO 标签推断某个 GOT 项可写**：检查 GNU_RELRO 覆盖、页对齐和目标运行时映射权限；常见 Full RELRO 会令 GOT 只读。仅在证实目标槽位仍可写后考虑 GOT 覆写。
- seccomp 先 dump 并结合 fd/启动逻辑确认可用 syscall；read/exit 不代表 flag 一定预先开在 fd 3，先枚举或从题目代码/运行时证据确认文件描述符。
- libc 未知时先找泄露并比对候选版本；用符号偏移回算基址后，只有在对齐和映射证据吻合时才用 ELF magic 复核，别只信 `strings`。
- 远程每连接 ASLR/堆布局可能不同 → 地址类（PIE/堆/栈/libc）默认每个进程/连接重新泄露并计算。密钥、canary、服务端种子是另一层：先做两次独立探测，确认跨连接同值后才复用（fork 服务常共享，rewrite 常重生成）

## 2. 漏洞定位（IDA 里重点看）

- 菜单堆题：show/edit/delete 的 **idx 边界**（负索引读 BSS 指针表自引用项 = 免费泄 PIE）；free 后指针是否清零（UAF/double free）；size 运算有无截断（int16、一字节溢出改下一块 size 高半字节）
- 逻辑题：校验与使用分离（清缓存看 idx、resize 换对象、free 的和写的不是同一个）
- **长度账本**：同一长度在"分配/拷贝/输出"三段是否同源——窄化（int16/uint8/半字节）或减去协商值后用于分配、再以原始长度拷贝，即可改相邻块头而不用先解堆布局；三段始终同源则此点无洞
- **别名与缓存键**：缓存/引用失效的判据是槽号、句柄 id 或名字字符串而不是对象身份时，用两个容器引用同一对象做 A/B（详见 [对象、缓存与析构](../pwn-objects.md)）
- **VM/解释器**：寄存器/槽位/level 立即数是否只靠被裁掉的 ASSERT；wide 前缀是否把 8 位撑到 16 位；对象 type 的 GC 扫描表；空串/长度 0 的特判是否让 size 与 len 不一致
- **JS 引擎**：diff 上游补丁定位被删的检查；JIT 类型假设（loop phi、Smi/对象、COW、无写屏障）；sandbox/cage 与压缩指针
- **内核**：拿 kallsyms 符号名对官方 System.map；按修复 commit 首次出现版本判缺口；看 execve/exit/timer/fd 的释放顺序
- **QEMU/驱动**：reset 是否 timer_del；DMA 目标是否可落到 BAR；缓存命中判据是否含 session 局部索引；池分配粒度是否可预测
- **协议**：帧头/长度字段是否既分配又拷贝；配置/表上传后是否被当可信数据执行；同名覆盖或分块续传是否让"校验对象"与"执行对象"错位；搬运/拷贝表能否改到别的报文的头部字段

## 3. 利用链模板（按手上原语选）

**任意读写**：GOT/代码指针减偏移 → PIE → libc 函数地址 → 目标：
- `setcontext+61`（2.29+，按版本核）栈迁移（rdx 指向可控 ucontext）→ ROP/ORW
- 改 `__free_hook=system`，free("/bin/sh")（glibc<2.34）
- 无 system 可蹭（静态链接/裁剪 libc）→ 全 syscall ROP；注意 fd 编号（socket 常是 4，open 从 3 起）

**堆**：
- tcache 投毒：safe-linking 编码为 `target ^ (存放next字段的地址>>12)`；只有已知 next 为 NULL 时，泄露值才直接给出该字段所在页。左移 12 得到的是页，不保证是 heap 映射起点；与 tcache 的另一个 key 字段区分
- 无溢出时：数据区预置 fake size → 改指针指向 → 造重叠 chunk；unsorted 切割残留 fd/bk 直接 show 泄 libc+heap
- fastbin 对齐：fd 指 `__malloc_hook-0x23` 借 chunk 头（仅旧 glibc 有意义）
- FSOP：house of apple2 的 FILE vtable=`_IO_wfile_jumps`、`_wide_data->_wide_vtable` 指向伪 vtable；2.43 在伪 vtable+0x68 放 `setcontext+0x2d`，经 `__doallocate` 跳，payload 按 `_flags/_wide_data/_mode` 字段重建，不套早期 `"  sh;"` 模板——**按 libc 版本本地验，不背常量**
- 一字节越界只改 size 高半字节时：先枚举 key/低位，用 unsorted 大块叠小 note，再打 `_IO_list_all`

**受限写**（写原语稀缺）："写什么值=改哪几个字节"——清指针尾字节使其落入堆内可控区；对 hook/GOT 邻域"一处清零+一处写低 3 字节"定点拼接；接收循环 while(1) 时可从高向低**倒写** ROP（protobuf 自动补 \x00 正好覆盖脏字节）

**VM/解释器**：
- 对字节码/脚本沙箱，分别审 loader、校验 hook、解释器 opcode 的 tag/边界假设和执行期副作用；“编译器只产合法字节码”若不成立，就用挑战自带编译器生成基线，再单点修改指令并差分验证。确认检查缺口后再把类型混淆升级为读写原语。
- 立即数越界 → env/寄存器相对任意读写；把 tag-9 值指向 array 骗过 `+0x14==-1` 类检查，`ext[slot]={addr,len}` 直接变 memcpy 原语
- GC 不扫描类型（type6）+ 压缩左移 → 死对象压缩后活对象落到旧偏移，被旧容器当子对象读出
- 伪 native wrapper：内联数据不被 GC 搬，析构 deleter 的 data 在 rdx → `mov rsp,rdx`；先用 addrof 确认对象地址跨两次 GC 不变、内联区可写，再依赖它（换长度阈值或引擎会走外部缓冲）
- 地址编码：`String(Smi)` 取 `(n*2+1)>>>0` 还原带 tag 指针；伪 JSArray 头 + dataStart 按 delta 补 u2f
- **状态跨输入块保留**：值栈/寄存器区是全局变量时，可用长度前缀分段投递（GC 触发 → 泄漏 → 读写 → 劫持）；先发两段验证第二段能读到第一段留下的寄存器，每包 reset 则只能单包一次投递
- **合法字节集反推分发表**：逐字节发最小指令，记录"有返回/崩溃/静默"三态；集合外字节被忽略 → 可当数据塞进同一字节流，直接崩溃 → 严格只用合法字节编码整条利用（每次探测用新进程或 fork 隔离）

**内核/虚拟化/驱动**：
- 对象生命周期 UAF：execve/de_thread、POSIX timer、rbtree 节点、fd 表；一次错写即 panic 的题先本地跑通全链
- KASLR：`i<<21` 枚举 slide、auxv/AT_PHDR、seq_operations/内核指针缓存；slide oracle 要绑定"只有正确候选才成立"的密钥派生量，错误候选也通过说明只验了可映射性
- 无符号表内核模块：取同版本官方包还原带符号 vmlinux + 解析 BTF 导出结构偏移 + 反汇编三点核对；三者自洽才算版本匹配
- panic 环境（`oops=panic`、`panic=-1`、`quiet`）看不到崩溃栈：每个写原语执行后立刻读回或查 euid/SID，失败把原值写回再试下一候选，把"哪些偏移可用"变成可累积清单
- 用户态任意读：`/proc/<pid>/auxv` 按定长 tag/value 解析可一次拿 PIE 与加载器基址（需知道 PID 命名空间编号与读 `/proc` 权限），缺项再退回 maps 或运行时泄漏
- QEMU：guest 侧 resource0 mmap + pagemap 取物理地址；一次 MMIO 写就是 4 字节寄存器写；g_malloc0 走 calloc 不进 tcache
- Windows：IOCTL 的 METHOD_BUFFERED 自校验、SipHash 标签当 MAC 伪造机、池粒度 `round_up(req+0x10,0x10)` 定填充、`.kdp` 只读段存密钥/handler；EPROCESS 偏移不套公开表，用"链表往返自证 + 用户态 SID 校验"定位；伪造链表对象后先准备"输出后挂住或恢复链表"的不返回路径
- 多进程/降权守护：先画能力与权限图（谁能读 flag、谁能绑低端口、重启周期），低权进程能绑低端口就让高权进程主动连回来

**Oracle/盲打**（先算"每请求信息量 × 并发 × 时限"，再选形态；见 [一比特 oracle](../pwn-oracle.md)）：
- 连接存活、响应时延或退出码可能提供 1 bit；`cmp al,[rsi-1]` 型 gadget 可构造阻塞/崩溃双态，但需确认进程模型、超时与 fork 行为
- oracle 不一定是 crash：可能是"读到超时且整段以裸写 error 结尾"、exitCode、返回长度差——先观察再假设
- seccomp 只有 read/exit 时：先从题目启动脚本/文件表确认可读 fd；若可读 fd 已知，再考虑用 ROP 读取并通过题目提供的侧信道观察
- TLS/复杂协议中的回调顺序也能造 oracle：先用合法握手记录事件序列，再逐步构造触发路径；以同连接中稳定出现的完整响应次数判定，保存已恢复前缀以便断点续跑。fork 服务可能跨连接复用 canary，但必须用两次独立探测确认

**竞态**：按状态图标清 staging、校验、睡眠、再次读取与使用；先检查可用的 phase/状态接口能否定点同步。先本地或题目独占环境用受控线程/延时验证，有限重试并记录成功率，避免用资源耗尽来拉宽共享远程窗口。

**有限候选地址覆盖**：只有确认题目写原语、有限地址域和请求预算时，才考虑覆盖多候选页代替预测 PRNG；先核对映射与副作用。TCP 短读不能靠大量连发保证读满：按真实 read 循环和协议定长/分阶段同步，见 [协议边界](../protocols.md)。

**gadget 藏身处**：题目自实现的"假 malloc/free"包装里常夹 `xchg ecx,esp; ret`、`sub esp,8; ret` 这类栈迁移件；栈帧**跨函数残留**（上个函数局部缓冲未清零）可当"上一步写、这一步读"的数据通道，配合野调用 `call [ecx+off]` 全可控；i386 cdecl 参数逆序压栈。

## 4. 平台适配

- 大端 MIPS64：确认 ABI、延迟槽和调用约定后再构造链；长度、块头和地址都按目标端序编码。`checksec` 的 Full RELRO 标签不能替代区间检查，逐项确认目标 GOT 是否落在 GNU_RELRO 映射内。旧 uClibc 无 tcache/safe-linking 的结论只适用于核实过的版本，先从随题 libc 或动态行为还原分配器
- Go：IDA 反编译差，IDA+gdb 实测偏移；直接找 `pop rdi/rsi/rdx/rax; syscall` gadget
- 静态 OpenSSL：回调（info_cb/psk/servername）常是入口；alert 事件可带超长 SNI/PSK
- RWX 堆单次写受限：第一段只写 read 跳板，读入第二段完整 shellcode，nop 滑板衔接
- 自定义 VM：先逆指令表组合出任意读写原语（寄存器 2^64 取模，Max-偏移造负地址）
- 浏览器/JS：headless 无手势，走 HTML 解析错误路径；同步 XHR 排空嵌套事件循环制造异步释放

## 5. 常用命令

```bash
one_gadget libc.so.6
ROPgadget --binary xx | grep "pop rdi"
python -c "from pwn import *; print(cyclic(200).decode())"   # 溢出偏移
# exploit 骨架
python3 - <<'EOF'
from pwn import *
r = remote('host', port)   # 本地 process('./xx')
r.sendlineafter(b'> ', b'1')
r.interactive()
EOF
```

## 6. 卡住

**生成器与上下文链**：服务把输入编译为新 ELF 时，分别检查宿主和生成物的段、入口、指令发射模板、栈净变化与继承 seccomp；宿主保护标签不代表生成物保护。立即数可能同时承载数据与可执行字节。`rt_sigreturn`/`setcontext`/`makecontext` 的帧偏移、寄存器恢复、fpstate、栈对齐与最终 ret 必须按实际 libc/内核核对，不复制单题偏移。先 marker 输出证明到达，再接 ORW；close/dup2/open 的顺序会改变 fd，尽可能传递 open 返回值，只有有证据时才固定 fd。

**受限 shellcode**：逐字节校验字符白名单，并仿真真实入口寄存器、栈和权限；用受限前级补丁出 read 跳板时，核对下一条 RIP 落点、覆盖自身后的指令和可写页边界。仿真中的 fake flag 只证明本地模型，不升级为远程成功。

泄露不出 → 试负索引 / unsorted 残留 / 格式化字符串 %p / 未初始化 dump（先释放再复用）；打不通 → 核对 libc 版本（双候选各试一次）/ glibc 版本对应的 hook 是否存在 / Full RELRO 实际覆盖范围；远程与本地行为差异 → 缓冲与对齐（\x00 截断发送、16 字节栈对齐）、每连接地址变化。再卡 → `../stuck.md`
