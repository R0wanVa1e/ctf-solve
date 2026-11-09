# 本地来源与增量维护

本轮更新：2026-11-09，蒸馏强网杯第十届三卷 WP 与最近实战记录，并按结构审计收敛重复表述。21:21 的 `week3_tail_cat` 新增 WP 已按“新 WP 采用闸门”复核：存在题目进度、脚本与文本结论冲突，因此只记录其可验证性缺口，不继承其拿旗链。来源根目录为 `D:/CTF`，技能仍可独立复制使用；下表路径是复核线索，不是运行依赖。这里只记录影响决策的增量，不声称全目录每个二进制或所有 WP 都已重跑。

证据范围：本轮阅读五方向 WP 提取文本（约 400 KB）、MYCTF 18 篇 writeup 与总记忆、tail_cat/laoda/token_dawang 记录，并核对随存的 Tomcat 9.0.30 源码片段；未访问旧靶机、未重交 flag、未运行题目附件或 WP 脚本。WP 的一次成功与本地复现分开记录，新的通用判据不继承历史题目的成功等级。知识库不复制凭据、完整 flag 或动态目标地址。

本轮未重新生成全目录清点，沿用 2026-11-07 的清单（21,210 个文件元数据、12,161 个小文本哈希，读取错误 0，报告在 `_skills_backup/ctf-solve_optimize_20261107_230828/`）；本次只读文本与源码片段，未解包新附件。

| 来源（相对根目录） | 吸收内容 | 记录状态 / 限制 | 落点 |
|---|---|---|---|
| `week3_tail_cat/{writeup_ghostcat.md,PROGRESS.md,ajp.py}` | AJP 请求字段中的 `remote_addr`、标准 include 属性、secret-prefix MD5 长度扩展和重复键覆盖均是待核对的链条节点；WP 采用前应核对其引用求解器与原始 JAR/响应 | `writeup_ghostcat.md`（SHA256 `979441...4326D0`）声称 `solve_ghostcat.py` 与 JAR/远程成功，但目录中无该 solver/JAR；`PROGRESS.md`（SHA256 `33B88E...E19C5`）仍标未解，且赛事/flag 格式陈述冲突。仅 `ajp.py` 的一般帧编码可独立读取，不能据此确认题目利用链或 flag | [证据](evidence.md)、[协议](protocols.md) |
| `wp_extract/pwn_wp.txt`（PWN 卷，17 题） | VM 跨 chunk 状态保留、合法字节集反推分发表、长度三段账本、别名/缓存键、表上传与搬运表、oracle 预算、KASLR slide 绑定、无符号表内核与 panic 自检、Windows EPROCESS 自证 | 阅读全卷（2626 行）；作者单次成功，偏移/规模数字属实例参数 | [一比特 oracle](pwn-oracle.md)、[对象与缓存](pwn-objects.md)、[PWN 打法](field-notes/pwn.md) |
| `wp_extract/web_wp.txt`（Web 卷，8 题） | 批量错位单向 N→N+1 与两层嵌套、hook 名由 status+kind 拼接、写后缓存失效、空 scramble/Basic 换行、provider 文本黑名单、`.htaccess` 仅 Apache、URL 双解析观测点、云元数据编码顺序、帧首 `0x0b` 过闸、`[]` 双语义与下标漂移 | 阅读全卷（2258 行）；多数一次成功、无原始报文，具体主机/端口/种子不吸收 | [内网纵深](field-notes/web-internal.md)、[Web 状态](web-state.md)、[Web 打法](field-notes/web.md) |
| `wp_extract/crypto_wp.txt`（Crypto 卷，5 题） | 谱域布局反推与半格相位、负循环反对称恒等式、重尾噪声分层、RLWE gap→β 与"判 1 需复核"、ARX 有效密钥位与指纹账、Σ 协议承诺来源、部分因子参数推导 | 阅读全卷（1239 行）；β/维数/位长多为单例，WP 内部式子与定义冲突处按代码/原页降级 | [Crypto 打法](field-notes/crypto.md)、[噪声模型](crypto-noise.md) |
| `wp_extract/reverse_wp.txt`（Reverse 卷，3 题） | 加载期重定位壳（TEXTREL/RELASZ 差/COPY/IFUNC/addend 流）、固件 OTA 五件事、TF 单步解释器与 Unicorn 四设项 | 阅读全卷（960 行）；VA/偏移/stub 长度属单题不吸收；"自毁早于 `_start`"依赖 BIND_NOW | [Reverse 打法](field-notes/reverse.md)、[运行时链](reverse-runtime.md) |
| `wp_extract/misc_wp.txt`（Misc 卷，6 题） | 跨帧时间稳定性四步、载体三取法、VNC/kiosk 入口与提权四要素、权重即 PRNG 前缀、白盒 reward hacking 搜索范式、行协议判定 | 阅读全卷（1252 行）；阈值/页长/动作域等单例参数不写成定值 | [Misc 打法](field-notes/misc.md) |
| `MYCTF/**/writeup.md`、`MYCTF/.workbuddy/memory/2026-11-09.md` | 无 gdb/WSL 时 Unicorn 跑静态 ELF 与 UPX 自脱壳、PE 黑盒 BFS oracle、纯 dex 解析与证书 salt、前端资源白盒、登录枚举/角色白名单、Java XXE `file:/`、双扩展名、XOF/HMAC 判据 | 18 篇记录 + 总记忆；E3 封顶、无平台接受；"FLAG 环境变量才是真旗"仅一例，按"该平台动态环境"限定 | [env](env.md)、[Web 打法](field-notes/web.md)、[Crypto 打法](field-notes/crypto.md) |
| `tail_cat/{FINAL_SUMMARY,ANALYSIS,PROGRESS}.md`、`research/ghostcat-guard-research.md`、随存 Tomcat 9.0.30 源码 | Ghostcat include 最小属性集、dispatch 不能二次分发、404 指纹边界、探针无效与守卫/部署的区分 | 未解；研究结论为 E2（源码+矩阵），不升级为"Ghostcat 不可绕" | [协议边界](protocols.md)、[阻塞诊断](blockers.md) |
| `laoda/SOLUTION.md`、`token_dawang/PROGRESS.md` | 前端反射 + 站内 WS 读记忆链、额度聚合的合法前提、bot 未运行的流程阻塞 | E3 单例；JWT 伪造曾有效已失效，只吸收"前提 + 计数定标"部分 | [Web 状态](web-state.md)、[阻塞诊断](blockers.md) |
| `game_of_flags/writeup.md`、`tools/verify_flag.py` | Flutter→JNI→bridge→worker→末端校验全链；Smi 参数约定 | 阅读 WP 和真实例程验证脚本；旧候选被新记录推翻，未重跑 | [运行时链](reverse-runtime.md) |
| `chanTui/writeup.md`、`taixuanjing/writeup.md` | 脱壳文件与运行态不同；SMC 每阶段 patch；首分歧对拍 | WP 声称局部真实机器码接受；部分叙述矛盾不能推广 | [运行时链](reverse-runtime.md) |
| `sword_vm/writeup.md`、`pangbai3/writeup.md`、`millionaire/writeup.md` | 成功输入未必是 flag；Python 版本；JS 字符与字节 | WP 阅读，未重跑 | [运行时链](reverse-runtime.md) |
| `sparse_whisper/writeup.md`、`solve.py` | 少数噪声行，枚举干净子系统并全量回代 | 阅读 solver；脚本会容忍 unpad 失败，不能将其打印等同验收 | [噪声模型](crypto-noise.md) |
| `prime_in_the_noise/writeup.md` | 稀疏秘密 support + 干净行 + RSA 因子整除 | WP 阅读；位长推断依赖生成约束 | [噪声模型](crypto-noise.md) |
| `masked/writeup.md`、`solve.py` | 显式加入掩码未知量，避免左核放大稀疏噪声 | 阅读 solver；乱序消元是候选生成，需完整残差与范围核验 | [噪声模型](crypto-noise.md) |
| `lwe_big_error/writeup.md`、`solve.py` | 小秘密加权嵌入；python-flint；行符号提取 | 阅读发现 last=±c 时直接取负不通用，规则已改为符号归一 | [噪声模型](crypto-noise.md) |
| `pickle_40K/PROGRESS.md`、`s2/{probe7.py,probe8.py,probe9.py,attack_mt.py}` | 分层异常 oracle；必填字段/BUILD；手写 opcode 自检；固定 stride 与留出预测 | 未解；离线证实 probe8 的 bytes、LONG4、FROZENSET 编码错误。容器探针缺 BUILD，旧类型推断需降级；未重测目标 | [对象边界](web-state.md)、[阻塞诊断](blockers.md) |
| `token/PROGRESS.md`、`token_king/{client.py,ctf.py,pow.py,scan.py}` | JWT sub 与服务端 session；bot 身份；OAuth/PoW 新旧协议差异；业务计数基线 | 未解；补读脚本，未验证实际注册/PoW 成功；种子缺失、部署降级及固定字段可复用仍是假设 | [对象与状态](web-state.md) |
| `cat_tail/PROGRESS.md`、`ghostcat/ajp_client.py`、随存 Tomcat `Constants.java/AjpProcessor.java` | AJP 字符串、属性码、body/end 类型、上传 body 状态机；修复后重测旧探针 | 未解；离线证实 ghostcat 客户端缺 NUL，静态核对类型码/属性错误。AB 是标准响应 magic；Filter 与走私均未实证 | [协议](protocols.md) |
| `node-exe/writeup.md`、`web8/PROGRESS.md`、`hanziguard/RETRO.md` | 正常功能失败判部署；目录/文件权限；反序列化触发闸门 | 未解记录；不继承“已穷尽/唯一剩余/autoType 开启”强断言 | [阻塞诊断](blockers.md) |
| `expired_doc/writeup.md`、`cloudview/writeup.md` | Git 历史与漏对象；gopher 编码按层；动态凭证 | WP 声称远程复现，本轮未访问 | [协议](protocols.md) |
| `resume/writeup.md`、`liuyanban_revenge/writeup.md`、`ez_remove/writeup.md`、`upload_real/writeup.md`、`ezzip/writeup.md` | OOXML 元数据 XXE；PHP 析构时机；客户端路径归一化；采样过滤 | WP 阅读；PHP/libxml 版本和配置须重验 | [Web 专题](field-notes/web.md) |
| `elf_master/writeup.md`、`Diplofetch/writeup.md`、`mission_lost_world/writeup.md` | 生成 ELF 是新执行目标；上下文帧；良性 marker；fd 与竞态阶段 | WP 声称远程成功，本轮未重跑 | [PWN 专题](field-notes/pwn.md) |
| `palimpsest/{writeup.md,exp2.py,debug12.py}`、`paroxysm/work/writeup.md` | 上下文尾部/包装器寄存器副作用、栈接力、换行路径、read 边界 | 新 WP 声称远程 ORW 成功，替代旧“待远程”条目；第二次 EOF 的外部审计归因未证实，固定 sleep/fd 不通用 | [上下文 ROP](pwn-runtime.md) |
| `tyr/{writeup.md,solve.py,src/output.txt}` | 截断 LCG 合并噪声降维；已知低位 HNP；全状态回代 | WP 声称本地复跑；脚本 exec 数据且未真正验证 PKCS#7，本轮未运行 solver | [噪声模型](crypto-noise.md) |
| `throne/work/{writeup.md,decrypt_body.py}` | 父进程供数/子进程校验；纯原生例程复用的依赖边界；弱哈希非唯一性 | WP 声称原程序接受；本轮静态阅读，不执行注入或映射原生代码 | [运行时链](reverse-runtime.md) |
| `after_aurora/{SOLVED.md,ft8decode.py}` | FT8 全帧、CRC、重发与点名语义；SOLVED 标题与验收分离 | 阅读 SOLVED 及配套解码入口；CRC/语义结论来自记录，无平台接受证据 | [Misc 专题](field-notes/misc.md) |
| `jinianri_osint/{writeup_overtones.md,solve_overtones.py}` | Agent 数据/控制因果链；标签重算；verify→凭证→flag | WP 声称远程成功；与同目录 OSINT PROGRESS 属于不同题，不能相互覆盖；脚本硬编码节点 ID 未证明跨实例适用 | [Misc 专题](field-notes/misc.md)、[证据](evidence.md) |
| `dantalian/{SOLVED.md,PROGRESS.md}` | 新旧进度冲突、大小写 oracle 的证据与文本分离 | SOLVED 的 flag 文本与“hex 为大写”叙述矛盾，保留冲突；已有 SQL oracle 方法继续保留，不复制最终 flag | [Web 专题](field-notes/web.md) |
| `blutter_build.log`、`run_blutter.bat`、`checkenv.bat` | Dart snapshot/架构/构建标志与 MSVC 环境；复用已完成输出 | 日志显示已生成对象池/汇编；只静态核对，不重建工具 | [环境](env.md)、[运行时链](reverse-runtime.md) |
| `silent_heads/writeup.md`、`fractured_world/writeup.md`、`aurora/work/writeup.md` | 统计群体跨维一致性；EVM 历史重放；FT8 时隙识别 | WP 阅读；主题补字/城市推断不等于唯一证明 | [Misc 专题](field-notes/misc.md) |
| `jinianri_osint/PROGRESS.md`、`zjuam/PROGRESS.md` | 网络阻塞与候选分开；有限搜索失败不能证明仅剩某算法 | 未解，保留待验证部分 | [阻塞诊断](blockers.md) |
| `WP/Bytex@起零衍迹_TCH第二届AK战队_Writeup.md` | GraphQL 字段/对象权限；重复结算/负数数量；缓存文件消费；私有仓库构建信任边界 | 阅读结构与相关段落；第三方 WP 部分步骤缺日志，CVE/提权成功不作本轮复现，旧内网地址不构成范围 | [Web 专题](field-notes/web.md) |
| `ctf-agent/PROGRESS.md` | 曾出现约 30.9 GB Python 虚拟内存峰值，提示资源估算与进程盘点缺口 | 历史进度记录，非本轮内存测量；不修改系统分页文件或 agent 项目 | [环境](env.md) |
| `2026强网杯/wp_extract/`、`ctf-retro/references/`、NSSCTF/创宇杯既有 WP | 原有五方向方法和边界修订 | 已有蒸馏继续保留；本轮不是重新穷尽全部原件 | 五方向 field notes |

## 本轮已核对的修正

- AJP 响应 magic `AB`（0x4142）是标准值：`AjpMessage` 9.0.30 响应写 `0x41 0x42`、按 `0x4142` 校验；据此断言"作者改过 AJP"不成立。
- `ApplicationHttpRequest.getAttribute` 对 include 六个属性不回退（`pos < SPECIALS_FIRST_FORWARD_INDEX` 直接返回自己的 `specialAttributes[pos]`），forward/error 分发带不上 AJP include 属性；DefaultServlet 需 `include.request_uri` + `include.servlet_path`，JspServlet 的 `service()` 只需 `include.servlet_path`。
- Σ 协议反求模数的差式必须带 `y^chal` 因子；旧写法 `gcd(res²-com)` 在 chal=0 时恒为 0。
- 负循环自相关是反对称（`D[k]=-D[N-k]`、`D[N/2]=0`），旧表述"对称"错误。
- 上传条件统一为五条件（可写/可达/被解析/不被路由拦/未被 server 级 deny 覆盖）；PHP session 键名改为"按 handler 前缀实测候选"。

## 下次有新文件时

可先用 [只读清点脚本](../scripts/source_inventory.py) 生成文件元数据与小文本哈希；它不执行题目、不读取文本到报告，也不自动判断题目已解。示例在来源根目录外保存报告，`--exclude` 是相对根目录的完整子目录，可重复传入：

```powershell
python -X utf8 scripts/source_inventory.py D:/CTF --output D:/ctf-inventory-1.json --exclude blutter --exclude ctf-agent
python -X utf8 scripts/source_inventory.py D:/CTF --output D:/ctf-inventory-2.json --previous D:/ctf-inventory-1.json --exclude blutter --exclude ctf-agent
```

命令在技能目录运行；输出只用于本地维护。JSON 的 `delta` 是新增/内容变化/移除的文件路径；有哈希时忽略纯时间戳变化，其余按 size/mtime 标候选变化。`skipped/errors` 必须检查；默认只给大文件和二进制元数据，不能据此断言内容相同。比较时保持来源根目录、排除项与 hash-limit 一致。题目仍在写入的文件若标 unstable，要等稳定后重新取证；维护者仍须核对题目身份与实际脚本。

1. 列出根目录最近修改的题目目录和新增 WP/PROGRESS/solver；时间戳用于定位，内容哈希用于去重。先读最新记录，再读支撑该结论的实际脚本/数据，避免只读题名或旧 `FLAG.txt`。
2. 找一条可迁移决策：识别信号、适用前提、最小测试、成功/失败判据。一次失败只排除实际测试的条件；正常基线、无效测试、真实失败分别记。
3. 通用内容更新对应速查/专题，单题常量与未解路线留在题目目录。本索引补来源、验证方式及冲突；修改现有条目以去重，不无限追加相同套路。
4. 检查引用路径、YAML 与前提；新增脚本用合成样本或已授权本地附件验证。修改技能不自动安装到其他 skills 副本，不修改原题 solver，不把定期监控当作隐含任务。
