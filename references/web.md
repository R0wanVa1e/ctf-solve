# Web 速查

1. **建基线**：抓正常请求，枚举可见路由、参数、Header、JS/source map；确认鉴权在哪一层。前端资源就是攻击面：注释里的"验收残留/考点"、调试开关、暴露的 `window.*` 函数、打包常量（base64/atob）都先 grep 一遍。
2. **追数据流**：客户端契约对照服务端实际读取；重点看隐藏/弃用字段、解析器差异、信任边界和下游服务。批量接口要给原始项、绑定结果、校验结果和执行循环分别编号，检查失败项是否造成数组错位（常见单向 N→N+1：第 N 条的参数被第 N+1 条的 handler 消费）。再检查身份、缓存、重放及状态机：写入后读旧值、换 zone 或等价格式才读到新值，说明"同一对象、不同字符串 key"。
3. **按入口最小验证**：注入先定数据库与语法（先看是否有诊断页/完整语句）；SSRF 先定 URL 库、scheme、DNS/重定向，并先找回显"实际连接 host:port"的观测点；上传/LFI 先确定五条件——可写、可达、被解析、不被路由拦、未被 server 级 deny 覆盖（`.htaccess` 只对 Apache 生效）；反序列化先看 shim/gadget 与 provider 黑名单是文本扫描还是解析后比对；SSTI 先确认模板与沙箱。
4. **串影响链**：泄露 token 后查其 ACL/路径/租户；RCE 后找允许的回显；写入后确认谁消费文件/对象。别把“拿到原语”当作“拿到 flag”；有 RCE 时先 `printenv` 与 `/proc/self/environ` 对照，镜像内静态 flag 文件可能是诱饵。
5. **验证绕过前提**：用无害输入确认解码、规范化、缓存、网关和应用的处理顺序；POC 按目标版本复现。

专项案例见 [`field-notes/web.md`](field-notes/web.md)；网关代取、回环维护面、云元数据、同二层与构建链见 [`field-notes/web-internal.md`](field-notes/web-internal.md)。原始 HTTP/AJP、SSRF 编码和 Git 历史查 [协议边界](protocols.md)；JWT 签名已破但权限不变、bot 无回调或正常功能也失败，查 [阻塞诊断](blockers.md)。

受限 pickle 的错误类型 oracle、手写 opcode、OAuth/PoW 前置验证、会话/闸门顺序与多站点业务计数，读 [Web 状态与对象边界](web-state.md)。
