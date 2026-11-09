# Reverse 速查

1. **Triage**：识别文件/架构/壳/运行库；检查入口、导入、段/重定位、TLS/init 回调与字符串交叉引用。先判是否"加载期壳/自毁"（TEXTREL、重定位条数差、段尾缝隙），会自毁时静态解优先于动调。
2. **找到真实校验路径**：跟踪输入如何进入比较/解密；自定义 VM、异常/信号 handler、反调试与加载期解密都可能藏核心逻辑。静态大二进制里对 `sigaction/mprotect/pushfq` 组合保持警觉——那可能是逐条单步解释器。
3. **优先观测原程序**：断点、hook、dump 中间态或用 Unicorn 跑原例程；只重写最小必要部分，并与原程序做多组差分。无 gdb/WSL 时用 Unicorn 按 PT_LOAD 仿真或把程序当黑盒 oracle（见 [环境](env.md)）。模拟系统调用时保留真实错误码、标志寄存器和异常/陷阱时序，不能一律返回成功。
4. **用锚点解密**：已知前缀/文件 magic/长度/CRC 作判据；候选必须经目标程序或独立校验器确认，合法反汇编不等于正确解密。
5. **按语言分流**：Android/APK 查加密 dex 与 native；Go/Rust 结合动态运行；自定义字节码先还原 opcode 和状态转换。

专用调试与算法案例见 [`field-notes/reverse.md`](field-notes/reverse.md)。多语言/多进程、Flutter/JNI、PyInstaller/Electron、SMC 或脱壳后仍不匹配时，读 [完整调用链与运行时真值](reverse-runtime.md)，逐段对拍，不只求末端比较的原像。
