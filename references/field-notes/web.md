# Web 打法

## 1. 侦察

- 仅在题目 host 检查首页、robots.txt 和常见备份名；发现静态目录暴露后再取 `server.js`、`app.js`、`.map`
- **对照客户端契约与服务端消费**：source map、TypeScript 类型、表单/实际请求揭示客户端发送什么；再追服务端 action/controller 是否仍接受隐藏、弃用或开发期字段，以及字段是否影响下游 URL、header 或凭据。客户端不再发送某字段，不等于服务端已拒绝它。
- 指纹（框架/CMS/中间件+版本）→ 查公开公告、补丁和利用链；POC 需核对版本、配置及题目范围后再复现
- 扫目录 + 抓一个正常请求当基线；先判断"鉴权在哪一层"（网关/应用/内网服务各做一半是常态）

## 2. 找入口

- 注入面枚举：参数、Header（X-Forwarded-For/Cookie/Referer）、隐藏路由（JS bundle 里 grep api/url）
- 鉴权面：后缀白名单（`.js/.css/.png`）、路径参数、方法/前缀规则；若观察到后缀鉴权，再比较 `/auth/x.js`、`;.js`、`?a=.js` 等解析差异
- 前端资源白盒：grep 结构注释（`考点/TODO/验收/勿删`）、`window.*` 暴露、`atob/btoa/base64` 常量与 `.map`；控制台调用暴露函数直达下一跳；多段 base64 按数组顺序 `map(atob).join('')` 拼口令，接口响应常再 base64 一层
- 登录枚举与角色：失败提示分两档（用户不存在/密码错）即用户名枚举；管理员名按业务角色试（manager/ops/运维），不要只试 admin/root。爆破前先测限速（连续 20–50 次看时延/锁定），记录命中位次；受限读文件若穿越与伪协议全灭且提示统一，可能是角色白名单而非无洞，用两个角色发同一请求做 diff
- 逻辑面：注册/登录/重置/兑换码——越权（改 id）、重放、条件竞争（burp intruder 并发）
- 报错面：`%00`、坏 JSON、错类型、超长参数各塞一次——报错带原文就等于拿到源码/模板/凭据

## 3. 打法清单

**过滤与解析差异（绕过依赖具体解析器，先用无害输入确认规范化顺序）**：
- 编码转换：对象 encoding 设 ISO-2022-CN-EXT，`fl%80ag` 解码归一成 flag
- 命令：`%0a` 换行断句、反斜杠断词 ``ec\ho``、内嵌 `eval(hex2bin(...))`、base64/chr() 拼接
- 路径：`....//` 双写回旋、分号 `/;/actuator/heapdump` 截断鉴权、`./` 与 `.//` 组合绕缓存 key
- 解析器不一致：URL `\@`、NUL `%00`、垂直制表 `0x0b`、JSON lone-surrogate key、JWT JSON/compact 混格
- **字面量语义层**：应用只翻倍 `'` 而数据库是 PostgreSQL E-string 时，`\` 才是转义符（`\'` → `\'''` 逃出引号）；MySQL 的 `ANSI_QUOTES`/`NO_BACKSLASH_ESCAPES` 同理

**SQLi**：先探过滤再选信道，**不要默认 union 可用**。
- 被词表拦（union/and/or/substr/ascii/pg_sleep）→ 谓词注入 `\'=(<布尔>)--`，用"结果条数 1 vs 45"当布尔信道；逐字 `lpad((SELECT …),k)=$$前缀$$`
- 字符串分支只对数组做整数化时，字符串直接 `implode` → `owner NOT IN (0) AND 1=0 UNION SELECT…`；利用要三条件同时成立（参数未声明 + 经错位送达使用点 + 列数对齐），单看该缺陷不足以打
- 报错/诊断页（`%00`）先拿完整 SQL 模板，确认方言与引号规则再构造
- `sqlmap -r req.txt --tamper=...`；时间盲只在 sleep 未被拦时用；高频请求注意假阴性
- WAF 词表组合拳（对常量先验证可用再上 payload）：`SELECT/**/` 断关键字+空格、比较整体加括号、裸数字改引号 `>'0'`、hex 字面量代字符串、`IS NULL` 被拦用 `IS NOT NULL`/`<=>` 反向、`CHAR(cp USING utf8)` 代高位字节（utf8 列对单 0x80+ 字节比较无效）

**无列名 SQLi（information_schema/mysql.* 被封、列名全改、错误静默时的完整替代链）**：
1. 探列数：注入点追加 `order by N`，yes/no 边界即列数
2. **行构造器逐元素提取**：`(SELECT/**/*/**/FROM/**/t/**/ORDER/**/BY/**/1/**/LIMIT/**/1/**/OFFSET/**/k) > ROW(a,b,…)`——字典序在首个差异元素定胜负，逐位二分即可读出每行每个元素，完全不需要列名
3. **NULL 毒化**：行按字典序比较，若判断需要走到 NULL 位置，结果可能变 UNKNOWN；更早元素已决定结果时仍可判定，不能说含 NULL 就所有比较都失败。需要访问其后列时可尝试 **UNION 探针行 + 派生表排序 oracle**：
   ```sql
   SELECT * FROM ( (SELECT * FROM t ORDER BY 1 LIMIT 1 OFFSET k)
     UNION ALL SELECT <可读标记值>,…,<探针X>,… ) AS d ORDER BY <目标列> LIMIT 1
   ```
   赢家是谁用标记列（如 e1 探针填 999，`> ROW(500,…)` 一测便知）→ "我的 X 与目标值谁小"成为新布尔信道，绕过 NULL
4. **oracle 差一语义先定标**（用已知值/常量校准再量产）：NULL 平局型比较 best=真值−1；排序型（probe 赢 ⇔ probe<目标 且字符串继续使 tie 也赢）best=真值；两种边界混用必错
5. **大小写与编码**：CI 排序下大小写可能等价，改 binary/字节级逐位探针复核；整串比较只约束首个差异点。非 ASCII 输出先分辨码点、UTF-8 字节与二进制值；0x80+ 可能是合法多字节编码的一部分，不能一概视为串尾伪影。用长度、HEX 和已知值校准终止条件
6. 时延信道先验确定性：部分站有非确定触发的防注入延迟（恒定 ~3s 惩罚），会把"列存在性时延探测"变成全假阳性；拥塞并发同样毁时延——时延型探测必须串行且先用"必然命中/必然不命中"双对照定标

**SSRF**：先确认 URL 解析库、允许的 scheme、DNS 解析时机和重定向策略；`file`、`gopher`、`dict`、`redis` 等支持面因库而异，不假设某个 URI 能直接读数据。
- 只有在校验器与请求客户端解析行为不同且已用无害地址证实时，再检查 userinfo、反斜杠、重定向等差异。先找回显"实际连接 host:port"的观测点（页面/日志/错误），用"白名单主机 403 vs 目标 200"做对照；`\ @ : /` 等分界字符一次只改一个，参数含 `@ : /` 时整体 percent 编码（`%5C/%40`）。不要把 `\\@` 绕过当通用结论；纵深利用见 [内网纵深](web-internal.md)
- gopher 打内网原始协议：按真实链路计算解码层数，见 [协议边界](../protocols.md)；RESP 的 `*N` 后必须跟 N 个 `$len`
- 云元数据地址和容器凭据路径取决于云厂商/编排环境；先从题目环境线索确认，按实际编码层逐层解析 Pod 配置
- 凭据 SSRF 后继续追权限边界：确认泄露的是哪类 token、可访问哪些路径/租户/命名空间，再选最小读取目标。宽泛 ACL 可能把单一凭据泄露升级为跨业务数据读取；不要把“拿到 token”直接等同于“能读 flag”。

**业务链/批量接口**：
- 批量执行器"原始 ops、成功绑定项、校验结果各自 append，执行再用原始下标" → 构造前置失败项造成数组错位，把某项参数交给另一 handler。错位是单向 N→N+1，只嵌一层时参数会被中间处理器自己吃掉，通常要两层嵌套才能送到目标 route；用只读接口零写入证明（第一条塞必然解析失败的占位，看第二条是否收到第一条的参数）
- 注入能写业务字段时，让伪造行的 status/kind/stale 触发快照修复 hook：hook 名常由 `status+"_"+kind` 拼接得出，伪造行要占独立缓存键；副作用顺序决定成败——改身份的 hook 必须先于重放请求的 hook
- 写路径不失效读缓存时，先写后读（旧值），再换 zone 不匹配路径或 `./` 与 `.//` 等价族（新值），能观测到"同一逻辑对象、不同字符串 key"才是写生效的必要一步
- 后台模板/皮肤编辑器"名称+内容原样落盘且强制 .php"是比上传点更直接的写入口；内网 `/ops/code` 未授权可把黑盒变白盒

**反序列化**：
- 受限 pickle 黑盒先检查客户端 opcode、构造/BUILD、顶层对象和必填字段，再用异常类型区分处理阶段，见 [对象边界](../web-state.md)；普通 `pickle.loads` 的 RCE 模板不能直接外推到精确 find_class 白名单。
- 框架原生链优先（Drupal/ThinkPHP/Laravel/Java CC 系）；`phpggc`（注意拼写）/ysoserial 生成
- **先 grep shim**：新版框架常用 `*_shim.php` 重定义 FileCookieJar、让 `FnStream::__wakeup` 抛异常，现成链会失效 → 找 Container::get 这类运行期 unserialize 原生链
- **provider 黑名单是原始文本子串扫描**：全小写、前导 `\`、`C:` 内嵌、只出现在字符串字面量里都被拦时，语法级变形全无效——只能换不含被禁词的原生链；判据是把类名放进一个不会被实例化的字符串字面量字段，看是否同样报黑名单
- 校验失败不等于 gadget 未触发：对象已构造，`__destruct` 仍在请求末尾执行；强类型字段塞不进就挂动态属性（PHP≥8.2 只告警 E_DEPRECATED，低版本可能报错）。成功判据是落盘/副作用，不是响应体
- fast-destruct（数组同键覆盖提前触发 `__destruct`）；JSON 转义环境用 `chr()` 构造；不出网回显：CC4+Tomcat 反射 Request 回写或内存马
- **tar 型 phar polyglot**（ez_phar 的版本案例）：stub 被拦时核对目标是否支持 tar phar、多格式头与 metadata；按实际容器计算校验，不把示例头当通用模板。PHP **8.0 起**打开 phar 的流操作不再自动反序列化 metadata，需要进一步证明显式 `getMetadata()` 等消费者与选项；不能写成只有 8.4+ 受影响。随机上传名用前后列表差集定位，排除并发上传干扰

**XSS/CSP（script-src 'self' 场景）**：
- 内联/外域被 CSP 封死时找**同源 JS 载体**：无过滤反射成 `application/javascript` 的路由（JSONP `?callback=`、调试接口、内容协商）。callback 注入处接 `//` 注释吞掉 API 包裹的尾部即得合法 JS
- 字面量替换型过滤器（只认 `<script`+空白/`>` 这类模式）：`<script/src=…>` 的 `/` 可绕开启标签；闭合标签用 `</script/>` 同理。**Chromium 不执行 EOF 处未闭合的 script**——真机验证 payload 时务必带闭合标签
- 外传可零基础设施：让 bot 执行 `fetch(受保护资源)` 后把结果 `POST` 回站内可读存储接口（发帖/留言），攻方直接看页面归档拿数据——绕开 connect-src 与出网限制，form-action/connect 都在 'self' 内完成
- report 类接口常见"target 必须 `/view/\d+` 且带 query"之类的松校验：query 部分塞任意字符常能放行

**SSTI/沙箱**：`{{7*7}}` 试探；Flask 拼接绕过 `{%set%}`+`'_'*2+'import'`、`[::-1]` 反转；Jinja `|attr("format")`
- 禁 `.` 的表达式求值器：`obj["attr"]` 常仍可用，且下标结果可继续调用 → `1["__class__"]["__base__"]["__subclasses__"]()…` 取 `os.environ`；取 `[i]` 前先按 `["__name__"]` 核对，子类下标随运行时导入顺序漂移，不能写死
- Python 沙箱：REPL `_` 拼接、生成器 f_back、`().__class__.__bases__` 链

**文件/权限**：
- 上传落点五条件（可写/可访问/被解析/不被路由拦/未被 server 级 deny 覆盖）：`.htaccess`/`Require all denied` 只对 Apache 生效，nginx+php-fpm 下目录里的 `.htaccess` 不挡 `files/*.php`。先写只 echo 标记的小文件，再请求它和被 deny 的已知文件，逐项实测
- zip 解压先测条目名规范化（软链接 zip 与 `../` 文件名双变体）；CMS 主题包上传把 themePath 改多级 `../` 打包启用，模板处目录穿越读 `/proc/1/environ`
- LFI 升级 `php://filter` 读源码、pearcmd 包含；Spring heapdump `/;/actuator/heapdump` 分号绕鉴权后**二次挖掘**加密配置/密钥
- SUID wrapper：在题目容器内枚举实际 SUID 程序并检查调用链；shell 是否保留有效 UID、参数如何传递取决于 shell 和 `exec` 用法。`execl("/bin/bash","-c","exec .../%s")` 只过滤 `..` 时，`;` 后的命令不会执行（exec 替换进程），但 `$()/反引号` 在 bash 解析阶段求值、此时 euid 已提升——用 `prog 'x$(id)'` 看报错里是否出现 `euid=0`。独占容器里 `chmod` 比拷贝稳（只改元数据、不移动文件、失败不影响已执行部分）；共享实例或需保持环境完整时用只读方式

**JWT/Session**：算法混淆（RS256→none/HS256 用公钥当密钥）、kid 注入。session 落 Redis 时键名按 `session.save_handler` 前缀实测候选（`PHPREDIS_SESSION:<sid>` 是常见候选、不是定值），SID 须符合 PHP 默认字符集，`use_strict_mode` 开启时未存在的 SID 不被读取；写 session 用 `name|s:len:"…"` 外层格式，应用内层加密不影响外层可加变量。自带会话解析的内网服务写后读不到新值 → 换 zone 不匹配路径逼重扫（细节见 [对象边界](../web-state.md)）

**其它入口**：GraphQL introspection 可枚举 schema，后续注入需按实际后端验证。题目提供高权限 bot 或 CI runner 时，检查其信任边界与可写回接口；这类链依赖专门的隔离环境，不作为普通站点的默认测试项

- GraphQL 已知 schema 时对对象 resolver 与敏感字段分别测权限：本人/他人 ID、父字段/嵌套字段各有闸门，introspection 可用不等于 IDOR 已成立。优惠券/物资类接口先做重复 ID、负数/零数量的单次对照，检查余额和订单守恒，再决定是否存在重复结算或符号错误；不要默认要靠并发。
- 服务返回缓存/导出路径时，跟踪“原文件 → 缓存副本 → 下载路由”的完整消费链；JWT 的 kid/jku/JWKS 路径则区分“选择密钥来源”和“业务授权”，先核对版本、来源限制与真实验签行为。题目提供私有包仓库/构建器时才追解析优先级、版本选择和安装钩子，不能将普通上传等同供应链执行。

## 4. 卡住

- **PHP 析构时机**：完整对象返回后异常退出、解析中失败释放、容器覆盖/引用计数归零是不同路径。用无害 echo marker 做完整对象/截断对象对照，核对 PHP 版本；尾随垃圾可能被忽略，不能等同解析失败。`S:` 转义字符串的长度按解码后字节计算。open_basedir/cwd 技巧依版本与可写目录验证，不当作任意 PHP 的既定能力。
- **OOXML/XXE**：docx/xlsx 是 ZIP，先确认消费者实际解析正文、元数据还是关系部件。最小合法包只改一个 XML，用内部实体验证展开，再核对 DTD/外部实体/回显配置；`no_network=True` 不等于禁止本地 `file://`。HTML 转义次数按捕获响应还原，读到空串不独立证明文件不存在或没有权限。
- **上传到执行**：区分扩展名、MIME magic、采样首尾过滤、落地名、访问路径与最终 include/模板消费。首尾通过只证明采样窗口；中间字节是否被 PHP/模板读取依真实消费者验证。任意写不等于模板可写，目录可写与已有文件可覆盖分别验证。
- **身份与 bot**：JWT、cookie 和前端按钮只提供线索；会话索引、服务端角色和 WS 握手分别观测。重置实例后重新取 session/nonce/凭据，见 [阻塞诊断](../blockers.md)。原始路径/AJP/gopher/Git 历史见 [协议边界](../protocols.md)。

- 验签与使用分离？（验的是清单/字段，用的是另一个来源——两者信息差即入口）
- 鉴权与业务各做一半？（网关看首命令/首跳/后缀，内层 strip 后再判断）
- 302/缓存/CDN 后面藏真实响应？直接 curl 看原始包
- 0day 打不动 → 挖逻辑（越权/重放/并发）；后台拿不到 → 找 hints/备份/调试接口（/debug //actuator /console）
- 再卡 → `../stuck.md`；相似题检索（题面独特字符串/版本号/组件名）
