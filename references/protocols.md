# 协议与解析边界

适用于裸 TCP、HTTP 原始路径、AJP、SSRF 下游和流量重组。先让客户端正确表达一条合法请求，再测试解析差异。

## TCP 与帧

- `sendall` 只保证发送完整缓冲，不保证对端一次 `read` 读满；一次 `recv` 也不保证完整帧。实现 `recv_exact(n)`（累计到 n，EOF 立即失败），按长度字段解析并限制长度/总字节数。行协议按终止符累计，保留未消费缓冲。
- 没 banner 不代表 HTTP。若固定字节数后断开，先检查 magic+length 的头长；区分应用拒绝、代理 RST 与读取超时。不要用大规模随机输入代替协议识别。
- **行协议 vs HTTP**：无 banner、静默关闭时先别默认 HTTP。同一 payload 分别用 HTTP 请求行、带 header、裸行+`\n`、裸行+半关闭四种发法对照；裸行+换行得到结构化回复、且错误体把期望格式写全，即行协议（按行读，半关闭不给换行会被当成不完整行）。HTTP 形态的报错正文也可能泄漏正确输入格式。
- 结束条件按协议：AJP END_RESPONSE、HTTP Content-Length/chunked/合法关闭、Redis 对应 RESP 结构。为方便读回显而追加 QUIT 仅适用于已确认的协议/连接用途；不要一概等连接关闭。
- pcap 按方向和四元组重组，处理 TCP 序号、重传去重、重叠与缺口；keep-alive 流内再按 HTTP 边界切多条响应，不能只拼捕获顺序或按首个 `HTTP/1.1` 截断。

## AJP13 校准

| 字段 | 标准表示 | 校验 |
|---|---|---|
| 请求头 | `0x1234 + u16be(payload_len)` | 不含 4 字节头；请求类型与正文结构匹配 |
| 响应头 | 标准 `0x4142`（ASCII `AB`）+ u16be 长度 | `AB` 本身是标准值，不是作者改 magic 的证据 |
| 字符串 | u16be 字节长度 + bytes + NUL | 长度不含末尾 NUL；null string 用 `0xffff`，区分空串 |
| 已知头 | `0xA0xx` 的约定代码 + 值字符串 | 先核对标准头代码表，未知代码可能越界 |
| 自定义头 | 名字字符串 + 值字符串 | 名字前不额外加 `0xA0`；它的首两字节就是长度 |
| query | 请求属性 `0x05` + 字符串 | `req_uri` 与 query 分开；不要把 `?x=y` 当 URI 路径的一部分 |
| 通用属性 | `0x0A` + 名字字符串 + 值字符串 | 属性表以 `0xff` 结束；未被消费与过滤拒绝须区分 |
| 响应分帧 | 4=headers、3=body chunk、5=end | 拼正文时剥离类型与长度；type 5 后结束本次响应，连接可复用 |

实现需对照实际服务版本、正常响应及原始字节，不能从单个 500 推断应用逻辑。标准 include 属性触发 404 仅说明当前请求被拒，不能仅凭黑盒响应证明存在某个 Filter/Valve 或 dispatcher 配置。公开 Ghostcat 条件需逐项验证，不把版本号当完整利用证据。

**复用客户端前的离线检查**：编码 `"A"` 应得到 `00 01 41 00`，空串 `00 00 00`，null `ff ff`；请求头长度与实际 payload 一致。普通自定义属性只能用 `0x0a + name + value`，不能误写成 `0x04 + name + 0x05 + value`（两者各有自己的标准语义）。用合成的 headers/body/end 帧验证解码，并在每个可能字节边界拆包后重组；截断帧、错误 magic、越界长度和缺 NUL 必须显式失败，不能当“空业务响应”。响应 body 为 type 3 的 `u16be(chunk_len)+data+NUL`，type 5 为 END_RESPONSE；不要从旧脚本“新版 Tomcat 改成 type 5/6”的注释推断协议变化。

**按消费端区分两种 body 包**：服务端 type 6 GET_BODY_CHUNK 请求继续上传时，客户端发 `0x1234 + packet_len + u16be(body_len) + body`，请求 body 包没有响应式的 type 3 前缀。按 Content-Length、拉取长度和真实服务状态发送；GET 的空 body 也须与有 body 的完整状态机区分。

**Ghostcat include 属性的最小集**：DefaultServlet 的 include 分支要求 `javax.servlet.include.request_uri` 与 `include.servlet_path` 都非 null（`include.path_info` 可选；缺 servlet_path 会 NPE→500）；JspServlet 的 `service()` 只读 `include.servlet_path`（+可选 path_info）。所以"守卫只查 request_uri"时可试仅 servlet_path + 请求 `/x.jsp`；但属性名大小写/前后缀变体能过 Filter 也不被 Tomcat 识别，`0xffff` null 值会移除属性、使 include 同时失效。

**dispatch 二次分发是死路（Tomcat 9 源码）**：`ApplicationHttpRequest.getAttribute` 对 include 六个属性不回退——`pos < SPECIALS_FIRST_FORWARD_INDEX` 时直接返回自己的 `specialAttributes[pos]`，null 就是 null，只有 forward 组在其值为 null 时才回查被包装请求。forward/error 分发里目标 Servlet 看到的 include 属性恒为 null，`DISPATCHER_TYPE` 也被 special 处理遮蔽。不要用 error-page/forward 去"带上" AJP include 属性。

**黑盒判据的边界**：同一实例标准 404 页的字节数/响应头可作为"守卫拒绝 vs 路由不存在"的指纹，但先取一次真实缺失路径确认基线，不能把自定义 404 本身当漏洞证据。响应 magic `AB`（0x4142）是 AJP13 标准值（`AjpMessage` 9.0.30 响应写 `0x41 0x42` 并按 `0x4142` 校验），不要据此断言作者改了 AJP 或存在连接器层补丁。

## 配置即代码：表上传、封面与搬运表

- 上传接口对表名/长度/校验和有白名单，但同名可重复上传或分块续传时，先发同长度合法封面、再发不同内容覆盖同名文件：第二份仍被激活并按内容执行 → 校验只作用于首包或首次落地。
- 搬运/拷贝表（源标识,源偏移,目标标识,目标偏移,长度）可配置时，让一条目把一字节搬到目标报文的功能码或长度偏移，可得到"改任意报文头"的写原语；前提是搬运在总线层且不校验内容。
- 判据是"校验对象与执行对象是否同一份字节"，不是接口是否返回 200。

## HTTP / SSRF

- 路径 payload 涉及 `/.`、`/../`、反斜杠或百分号时，检查客户端准备后的 request-target；必要时 `curl --path-as-is` 或 socket 发原始请求。保存真实字节与 Host，TCP 入口仍可能承载 HTTP；域名、端口和虚拟主机是不同条件。
- 列 `外层参数 bytes → 框架 URL decode → URL parser → 下游 decode → 协议 bytes`，逐层定编码次数。gopher 没有通用的“只编码一层/必须双编码”；按链路反推，Content-Length 按最终 body 字节计。
- SSRF 的 loopback 别名、userinfo、DNS、重定向因解析库而异；`127.1`、十六进制 IP 等先在同环境验证，不能当通用绕过。元数据凭证还需核对角色、作用域、过期时间和兑换接口。
- 同一请求在边缘/后端响应不同只建立了差异线索，未证明请求走私。要证明各层请求边界/方法/路径的解析发生分歧；验证仅限题目独占连接和已授权端点，记录完整报文。
- `/.git/HEAD` 可读后检查对象和历史完整性；用 `git fsck`、`git show` 定位漏抓 blob，定点补取。已删除文件可能留在历史，但历史密钥能否用于当前实例仍须验证。
