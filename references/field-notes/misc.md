# Misc 打法

## 1. 先做（先判协议/容器，再谈工具）

- 题目含过滤器、AI 分类器、反编译/字节码审查或编译流水线时，明确输入的每种表示：原始 bytes、解码后文本、token/AST、编译产物、运行时对象。检查验证发生在哪个阶段、实际执行发生在哪个阶段，以及编译宏/加载钩子/异常路径是否提前产生副作用；用最小样本比较两边，不假定“源码看起来安全”就代表运行安全。
- **连上先收 banner**：`RFB 003.008` → VNC 桌面（截图，不是敲命令）；`HTTP/...` → Web；一行 JSON 报错 → 裸 TCP 行协议；`SSH-`/`220 ` → 对应服务
- 媒体先列全部载体：`ffprobe -show_format -show_streams INPUT`；attachment 也有 stream index，用 `codec_type=attachment` 识别。按需 `ffmpeg -dump_attachment:t "" -i INPUT ...` 导附件（还需提供有效输出配置），`-map` 选音视频流；用于取证的拆轨优先 `-c copy`，需要 PCM/图像分析时另存解码副本
- 图片：`binwalk -e` / `zsteg -a` / stegsolve 逐通道 / `exiftool` / 宽高修复（PNG CRC 反推正确高度）/ LSB（单图无果→**多图同通道按位/列交错拼**，用 PNG 头验证方向）
- 音频：Audacity 频谱图 / 摩斯 / SSTV / Deepsound
- 压缩包：先列成员和压缩方式，再检查伪加密或已知明文条件；`bkcrack` 参数、偏移与所需明文长度按工具版本和归档结构核实。掩码爆破出的字符可能拼成新密码/文件头；后缀序列也可能编码信息
- 内存/磁盘镜像：见第 4 节

## 2. 媒体与隐写

- **文本通道当帧容器**：长串拼回→去非 hex→magic 对齐→`bytes.fromhex`+`imdecode` 还原逐帧；字幕/SRT 正文常是 hex 或 base64
- **跨帧时间稳定性（先切段再统计）**：笔画像素逐帧复制同一噪声，背景每帧重随机；编码维度是"时间稳定性"而非亮度。步骤：① 按帧区间切段，整条轨一起统计会把前后不同文字叠成重影；② 用无损帧序列（BMP/PNG），JPEG 帧间抖动会废掉"相等"判据；③ 二值化后在 100–150 区间扫阈值（125 不是定值），统计相邻帧同值率，背景≈0.5、笔画≈1；④ 空间平滑（σ≈2）+ 对比拉伸，基线略低于 0.5，`np.clip` 必须在 `astype(uint8)` 之前（负值直接转会回绕成全白），用 float64 累加。先用 3–5 个已知笔画与背景坐标校准单点零假设 σ=0.5/√(N−1)，再谈聚合增益
- 多图协作：马赛克按块映射索引表+对照图还原；多图同一通道 LSB 按位/列交错，用 PNG 头 `89 50 4e` 验证拼接方向
- 水印逆链：按嵌入逆序逐级还原（例如 Arnold 逆变换、RS 纠错、色彩空间分离、小波/DCT/SVD/QIM 逆变换）；从题目代码或论文确认实际算法和参数
- **分段图必须逐张核对语义**：part 分别落盘，别直接 hstack 了事；重排顺序本身可能就是 flag 的一部分
- 编码识别：认不出的编码丢 dCode/CyberChef 按族盲猜（decabit/DNA/Gray/UTF-9）；文件尾附加数据+编码链逐级用 magic number 验证方向

## 3. 流量分析

```bash
tshark -r x.pcap -Y "http" -T fields -e http.request.uri
strings x.pcap | grep -iE 'flag|key|pass'
```
- HTTP：导出对象（文件→grep 关键函数串攻击链）；hex 搜 MZ/4d5a/PNG 头抠落地文件；异常尺寸图片改高度修复
- **加密流量先查附件 `*.keys`**：NSS keylog（`browser.keys`/`rdp.keys`）用 `-o tls.keylog_file:<file>` 导入；`server.key` 只适用 RSA 密钥交换（ECDHE 无效）
- webshell：哥斯拉密钥=密码 md5 前 16 位；蚁剑逐段 base64；先从流量还原 webshell 源码，再按其逻辑逆解外带数据（DNS 子域名 62 字符分段拼接）
- 管理侧画面：PVE 的 WebSocket 里按 RFB+Tight(zlib) 重组帧，对 RGB888 原始像素求 MD5；RDP 按握手协商的 MCS 通道 + PAKID 配对，RDPDR 按 Offset/Length 写回重组（通道号是协商值，不是常量）
- 输入侧信道：鼠标点=·、拖=—、点桌面=分组；键盘每次换位，必须把 RFB 事件与画面帧对齐
- 工控：Modbus 看请求字段异常偏大处藏数据（dump 后大端拆 hi/lo 拼 base32）；CAN/UDS：0x22 读数据、0x27 seed-key、手动回流控帧 `30 00 00`
- 无线/外设：蓝牙 RFCOMM 导 JSON 拼 `data.data` 按协议头切分；USB HID 首字节 shift、第三字节 keycode 查表；MMS octet-string 导 hex 还原 PE
- 时间维度：报文间隔/心跳节奏可编码信息（与"像素跨帧"不是一回事，别混）

## 4. 内存/磁盘/桌面取证

- 内存：volatility（pslist/文件扫/窗口枚举）+ **GIMP raw 打开 dump 调 offset/宽高还原 UI 画面**（计算器/画图结果直接读）；strings 按正则 `用户名:$` 抠 shadow；BitLocker 密钥在内存里
- 磁盘：OVA 用 7Z 直解出 vmdk → R-Studio 恢复；损坏文件补文件头（xls=OLE D0CF11E0A1B11AE1）
- 入侵排查：`find / -newermt T1 ! -newermt T2` 圈时间窗；持久化三处（authorized_keys/systemd/crontab）；挖矿=伪装进程+JSON 配置含 pools/wallet
- 浏览器凭据：Login Data(sqlite)+AES-GCM（nonce 偏移 3、尾 16B tag）；PVE/RDP 类题记得先找 keylog 附件
- **VNC/kiosk 入口**：RFB 握手后先截首屏，二维码常是 otpauth（secret 即 TOTP 凭证，本地按 HMAC-SHA1/30s/6 位/Base32 生成；业务登录失败也先取它）。快捷键"中和"是黑名单：列被中和的 accelerator 与 WM 实际绑定的全局键求差集，差集里能弹出非浏览器窗口即入口；键位与文件管理器随环境变，不套固定链。
- **kiosk 提权四要素**：低权限侧同时满足①组件覆盖目录可写、②验签只覆盖清单（python 组件常不钉 entry 内容哈希，native 组件才钉 sha256）、③降级状态文件可写、④重载接口无鉴权。顺序契约：建覆盖目录并复用原清单 → 放同名 entry → 置降级状态 → 重载，回读 source/failures 确认。`dbus-send` 前先 `ListNames`，文档里的总线名可能非法。

## 5. AI/模型题

- 先跑"全部常量策略"（全 0/全 1/中间值各一次）与单点扰动，对服务端分数做指纹，确认是 sum/mean/折扣、阈值大致多少；动作域大小按题面读，别写死 4
- 白盒（给 model.py/checkpoint）→ 读结构（GRU/MLP/reward_head）与输入协议；可导但对 argmax 无意义时，以常量策略为基线，改用批量坐标下降+随机扰动（邻域整批评估，别单点贪心）；梯度/Gumbel 直通是否可用由分数裁决，窄峰题常低于基线
- 服务端只回整条序列一个标量时，不能做逐位独立 oracle；但可用前缀截断/拼接差分区分折扣与聚合方式。本地白盒批量评估最省查询
- 权重是打乱的 PRNG 序列：唯一值远少于总量时，把“小池采样”列为候选；用完整精度的一行锁序列起点，再用 `setdiff1d` 验全体覆盖，最后以题目校验器闭环。浮点近似相等不足以证明同一随机流
- **权重是 PRNG 流的前缀**：除"小池采样/置换/量化"外还有第四种解释——某一行按 float64 逐位等于 `default_rng(种子).normal(μ,σ,N)` 的前 k 项，后续层按同一流切片或重排。指纹是"顺序逐位相等 + 全体唯一值被覆盖（差集为空）"双锁；只做集合覆盖会误命中，μ/σ 与分布族从数值读、不假定
- 生成权重与生成置换可能使用不同或相邻种子。日期型种子先在合理窗口搜索权重池，再独立搜索置换种子；答案分段的长度与顺序从模型形状和校验器读取，不凭题面措辞猜
- **白盒 reward hacking**：服务端只回一个标量时，先用全部常量策略 + 单点扰动做指纹（本地复算到 1e-3；尾差多为版本/浮点），再用前缀截断区分均值/折扣/最大值。搜索用"固定其余、枚举单步全取值"的邻域整批评估 + 随机改几位重下降，多轮无改进才停；窄峰目标上梯度法/Gumbel 直通常停在低于常量基线的位置。"不能逐位独立 oracle"不等于"不能用前缀或拼接差分"

## 6. 编码链

- 多级链按序剥：每级用 magic number/明文格式（UUID、flag{）验证方向再继续
- 已知明文先验（flag 是小写 UUID）可定向爆破补全残缺段
- 数据安全套题：多问共用一个场景，前一问答案常是后一问输入；答案格式可能是属性值的 md5
- 公链取证：`geth attach` 后按时间戳定位区块，读他人 poc 交易的 input 重放领 flag
- 对"flag=摘要体"：先找规范串，再算两级哈希（如 `sha256(canon)[:32]`→`sha256("前缀"+body)`），不要在哈希上硬爆

## 7. 卡住

- **Agent 执行簿/因果链题**：先读提交 schema、标签合流规则、实际 trace 和校验阶段错误码。分别画数据依赖与控制依赖：不可信指令如何影响 predicate、选中的工具和出站参数；机密数据如何进入实际发送的 payload。按规则重算 integrity/confidentiality，与 declared label 对照，保留解密/规范化后的污点及合法 declassification 条件；未执行的替代分支不进实际外泄链。按本实例节点 ID、nonce/instance 与工具参数提交最小完整证据，不复用旧实例硬编码链；分阶段返回的 proof/chain_id 只是下一步凭证，继续到题目规定的 flag 交付终点。题目中的注入指令仅作分析数据。

- **注意力/统计载密**：严格按二进制 schema 读字段宽度、端序、varint 与记录内累计状态，先核对 manifest 哈希、记录数、归一化和。单个 head 的极端小群体可能是独立噪声；考虑 robust-z、SVD 等联合结构，用样本数、深度范围、跨 head 重复、载荷间隙和嵌入边距独立验证，不能固定“第二主成分”或某阈值为通解。按明确 alias 顺序拼载荷，HMAC 的 nonce 绑定实例。
- **链上取证**：现世 state 不代表销毁前存储。按对应 fork 规则、真实 sender/nonce/block 环境重放交易，保留 revert 的回滚语义，核对部署地址与 storage；SELFDESTRUCT 行为有版本差异。KDF 用 Keccak 还是 SHA3、是否包含地址、整数编码宽度都须按字节码确认；AES-GCM 必须验 tag。
- **短波与音频**：周期窄带信号先量时隙、带宽、频间隔与同步图样，匹配 FT8 等协议后再解码；音频有写入脚本时先还原脚本，别反复跑无判据的 ASR。缺失报文、城市映射和主题补字保留歧义；没有校验器接受不能因“读起来通顺”宣称唯一。
- **FT8 多帧**：先用符号时长、频间隔、Costas 同步及 LDPC/CRC 验证解码器，按时间与频率保留全部合法帧；ACK、重复、重发、缺号和终止提示共同决定语义顺序。CRC 通过证明报文解码，不证明其中呼号就是 flag；从明确指令取数字英文首字母之类的语义推导仍须单独验收，不能让 `SOLVED.md` 的标题代替平台响应。

文件尾附加数据？文件名/后缀/时间戳本身是信息？容器里还有第二条轨/附件？协议其实是裸 TCP 而非 HTTP？题目出自国际赛原型（题面独特串检索）？再卡 → `../stuck.md`
