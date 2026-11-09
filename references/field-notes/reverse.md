# Reverse 打法

## 1. 先做（元数据优先于字符串）

```bash
file xx && strings -n 6 xx | head -80
readelf -hdW xx          # TEXTREL / BIND_NOW / RELASZ/24 与两表条数之和是否一致
readelf -lW xx           # LOAD filesz 与页边界差 = 段尾缝隙
readelf -rW xx | grep -E "COPY|IFUNC"
```
- 三条算术先算完：`RELASZ/24` 减（`.rela.dyn` 条数 + `PLTRELSZ/24`）的差；所有 `r_offset` 是否落进 `R E` 段（TEXTREL 是否真在改代码页）；`p_filesz` 到页尾的缝隙字节能否被 24/32 整除（Elf64_Rela/Sym）
- 查壳：UPX `upx -d`；识别加固（梆梆/自定义）→ 先脱壳；但 **加载期壳常常"无壳可脱"**，见第 7 节；无 upx 时用 Unicorn 执行壳 stub 自 dump（见 [env](../env.md)）
- IDA 打开看 main 与字符串交叉引用；假 flag 前半是常见迷惑，真校验在后面
- 静态扫描真正有价值的常是**自相矛盾的元数据**（TEXTREL + 重定位条数差 + 高熵缝隙），不是明文字符串

## 2. 算法指纹（先认出来再决定逆不动调）

| 特征 | 算法 |
|---|---|
| 一张 256 字节置换（或两张） | S-box/白盒 SPN；单张置换 + 4×4 位矩阵也可能是自定义分组，别只认 SM4 的两数组 |
| delta 常数 0x9E3779B9（32 位）或 0x9e3779b97f4a7c15（64 位） | 只说明借了黄金比例常数，按"自定义 ARX"处理：照实际移位/轮序逆，别套 TEA |
| 常数 0x61707865/0x3320646E | Salsa20 |
| 符号/字符串出现 rc4/arx | 对应算法，密钥常在附近 |
| 轮函数结构对称可逆 | Feistel——交换=寄存器重命名；比较点位置无关，目标态是任意完整中间态时可少推几轮 |
| `Y=F(X)^X` 且 F 分 4 字节可逆 | 令公共中间量 `t` 把多未知压成一维：`g1(U)=t^yL, g2(V)=t, g3(W)=t^yR` 后枚举 t，64 位枚举降到 32 位 |
| 字节表存成 float 数组 | 超越函数编码：按 `round(asin(x)*256)&0xff` 之类公式反算，别猜字节 |

## 3. 按语言/形态

- **Cython/.pyd**：文件名定版本(cp311) → 定位 `__Pyx_CreateStringTabAndInitStrings` → 恢复 mstate 符号 → 搜目标函数名；pyc 用 `pydisasm -F xasm`
- **APK**：jadx 失败/类不全 → 按 zip 解包找非 classes.dex 的加密 dex → .so 里找硬编码密钥解密 → 二次反编译；只有 dex 时可用自写解析器（见 [env](../env.md)）
- **Go**：IDA 反编译差，gdb 实测；**Rust**：定输入动调 dump 中间密钥流（固定种子则密钥一致，跳过静态逆向）
- **JS 快照**：`.snapshot`+charCodeAt → JerryScript，官方工具转 opcode 读常量
- **自定义 VM**：先逆指令表；字节码只依赖常量、无输入/跳转时可静态抄输出序；含输入、状态或跳转就必须真写解释器（十几条 opcode 也要写全），再与原程序对拍
- **非 x86**（C-Sky/RISC-V）：装 IDA 插件/用 qemu 跑；RISC-V 固件用 `qemu-riscv32 -g` + `gdb-multiarch` 断在调用返回点读缓冲区
- **固件/OTA 五件事**：① 描述符按"偏移+长度"分散存放，先搬运拼齐再哈希（对描述符区之后的连续字节直接哈希必错），把"搬完哈希对上"当结构 oracle，偏移/长度互换作反例；② 包尾独立定位：定长 ASCII 标记 + 小端长度字段，验 `标记尾+字段宽+len==文件大小`，端序用"是否越界"一秒判定；③ 自校验摘要（`.selfhash`）只证完整，不是密钥材料；④ 多算法派生链逐级 assert：主程序内置的每条比较常量就是现成 oracle，截断长度（`H(x)[:16]`）与拼接顺序必须与代码一致；⑤ SM4/AES-CTR：密钥截到 16、计数器端序按代码（端序错是整段乱码）、尾块丢弃多余密钥流
- **固件"原地变换"**：先自哈希再就地变换、不落盘；`qemu-riscv32 -g` + `gdb-multiarch` 断在**调用返回点**（不是函数入口）读持有缓冲的寄存器，取用长度看主程序消费参数，不由固件决定

## 4. 动调优先（能 dump 不逆推）

- 自定义 VM/哈希/固件逻辑复杂时，先问能否让原程序在受控输入下吐出中间态：GDB/Frida hook、syscall 写出、Unicorn 承载真实例程都可作为观测手段。只模拟最小状态/接口；若必须重写，再用原程序对多组输入做差分校验，避免“看起来等价”的实现细节毁掉结果。
- 复杂但本质异或：断点 dump 变换后的密钥流，与密文异或直接出结果
- SMC 自修改：一般可在 puts/printf 第二次断下回溯找真实主函数；判据是“输出点相对解密循环的位置”——若循环内没有任何输出，改走“逐条解密→执行→恢复”的轨迹
- **TF 单步 + SIGTRAP**：模拟器四坑——EFLAGS 初值 `0x202`（带 IF）、syscall 返回真实 `-EBADF` 而非 0、TF 下 syscall 后要先执行下一条（如 `mov [r12+0x56],ax`）才进陷阱、RCX/R11 被 syscall 改写；用 Capstone 记 `(地址,指令)`
- **SMC 的 dump 时机**：普通内存 dump 不会同时含所有明文指令，要卡在“已解密、尚未恢复密文”的瞬间；若解密只依赖文件常量（无 PID/时间/环境熵），静态按 stub 公式反向解文件密文段比 dump 更省，也不受反调试干扰
- **加载期壳**：PIE 无绝对地址时用 `页对齐(rip)+动态段偏移` 读 DT_DEBUG 取 r_debug，顺 r_brk/link_map 自定位与反调试；自毁只让“静态看不见”，见第 7 节
- **程序自身作 oracle**：注册机 key=f(machine_id, user_id) 时，把内置机器码 patch 成已知值，输出点断点直接取 key
- **多解候选回灌**：算法只给 N 个候选时不猜，逐个喂原始 ELF 由程序自筛，不 patch 比较点
- Frida hook **native 层**导出函数 onLeave 读返回值（Java 层 hook 非 UTF-8 返回值会崩）
- 父子进程互反调试：Process-Dump 按 PID dump 干活的子进程
- 接口型：每 3 字符返回 4 字节校验 → 分段爆破拼接到全长

## 5. 爆破与锚点

- 末位 `}` / 已知文件头（PNG 89504E47）/ flag{ 前缀 = 锚点，逐位倒推 XOR 链
- 单字符变换 `(c*A)^B+C`：直接反解或 32-128 范围爆破
- strcmp 比 md5 → `\x00` 截断，只配第一个 `\x00` 前内容即可过检
- 变体 base64：码表缺位先补齐；被统一替换的字符位局部爆破试探
- 输入反馈进解密流：错输入不让代码跳失败分支，而把后续指令解成乱码；只能逐字节枚举，且区分“输入约束”与“内部状态约束”
- **线性层**：一连串按位 xor 把 N 字节映到 N 字节时，提 N×N GF(2) 矩阵（每行=参与异或的输入位集合），高斯消元求逆 `Y=M⁻¹·target`；不可逆说明漏行或读错位
- “能反汇编≠候选正确”：随机字节也可能解成合法指令，候选验收要结合目标地址+连续指令结构；多候选一律回灌未修改的原程序终筛

## 6. 卡住

找隐藏入口：反调试 handler 本身藏逻辑（DebugLoop 里 patch/跳转）；字符串表被加密 → 看 init_array / TLS 回调（加载期解密）；执行流对不上 → 在“解密后、恢复前”抓内存，而不是随便 dump 后 diff；导入表/重定位自相矛盾 → 按加载器重定位语义手工还原。再卡 → `../stuck.md`

## 7. 加载期重定位壳（ld.so）

把重定位表当“在加载期写内存的程序”读。三项算术同时出现即高置信：TEXTREL、`RELASZ/24` 与两表条数之和的差、`r_offset` 落进元数据表或越界。

- **段尾缝隙**：`p_filesz` 非页对齐时，页内其后字节仍来自文件、仍可读；若该页属 `R E` 段则同时可执行（跨页不映射）。按 24/32 整除试探 Elf64_Rela/Sym 结构
- **RELASZ 差**：`RELASZ/24 ≠ .rela.dyn 条数 + PLTRELSZ/24` 时，多出的槽位是“会被当成重定位执行”的隐藏数组；差值须能被 24 整除，且能由前一条 COPY 覆盖才闭环
- **COPY = 元数据驱动的 memcpy**：`memcpy(dst=r_offset+base, src=sym.st_value+base, n=min(def.size,ref.size))`，三要素全可由文件算出；一条 COPY 就能整块覆盖任意表。注意 glibc 语义是把 `st_size+addend` 写到 `r_offset`，不是“写 st_value”
- **雕符号表**：`r_offset` 指向 `.dynsym/.gnu_hash/.rela/.dynamic` 内部时，符号表“即变量”：+0 name、+4 info/other、+8 shndx、+0x10 value、+0x18 size；改完字段后引用它的重定位结果可预测
- **IFUNC + SHN_ABS = 加载期执行**：`st_info&0xf==10` 且 `st_shndx==SHN_ABS`（或 `R_X86_64_IRELATIVE=37`）时，ld.so 在 `_start` 前调用 resolver，绕过 init_array；BIND_NOW+Full RELRO 下必早于 `_start`，lazy binding 时可能延后
- **addend 流**：一批同符号同类型的重定位把 addend 按小端铺成 8 字节（`(S+addend)&2^64`），用 capstone/objdump 反汇编；能解出完整函数即证明被当搬运器
- **静态解优先**：自毁/反调试的常见表现是“跳过解密并自毁”——程序照常跑但校验为空，“能跑通”不证明逻辑执行

## 8. 异常驱动解释器（TF/SIGTRAP）

- **指纹**：静态大 ELF、符号少，但 main 在“看似终点”的查表函数后仍继续；出现 `sigaction`、`mprotect`、`pushfq; or qword[rsp],0x100; popfq; jmp` → 逐条单步解释器，几千万次迭代的查表不是终点
- **循环建模**：一轮 = 算下一条地址与 key → 备份原字节 → 原地 XOR 解密 → handler 改返回 RIP → 执行 → 再 trap → 恢复密文。唯一正确观测点是“跳向明文之前”，用 capstone 记 `(地址,指令)`；静态线性反汇编必混入密文垃圾
- **Unicorn 四设项**：EFLAGS 初值 `0x202`；无效 fd 的 `read/close` 返回 `-EBADF` 而非 0；TF 下 `syscall` 的陷阱在下一条用户指令之后（紧随的 `mov [ctx+槽],ax` 必须执行）；同步更新 RCX/R11。任一错都会让 key 状态静默偏掉
- **输入进滚动态**：`xor cl, al; mov [ctx+状态], cx` 型时，错输入的后果是“后续代码变乱码”而非跳失败分支；快照状态后逐字节枚举，用“随机字节也能反汇编”作反例过滤；区分“输入字节约束”与“内部状态约束”
- **GF(2) 线性层**：见第 5 节；提矩阵→消元求逆，不可逆说明漏行
- **可逆轮降维**：`Y=F(X)^X`、F 分 4 字节且 `g_i` 可逆时，用公共中间量 t 把 64 位枚举降到 32 位；解可能不唯一，每个候选拼成完整输入喂**未修改**的原程序终筛
