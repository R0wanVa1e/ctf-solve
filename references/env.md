# 环境与工具替身

先判定环境，再决定命令形态。缺工具时先验证替代路径；确需特定运行时而当前不可用时，记录具体依赖缺口，不无限折腾安装。

Linux/macOS 可用 `uname -a`、`python3 --version`、`command -v checksec tshark binwalk nc 7z ffprobe`；Windows/PowerShell 用 `$PSVersionTable`、`python --version` 和 `Get-Command`。逐项检查所需工具即可，不要因一条探测命令缺失而中断。

| 需求 | Linux 常用 | Windows/DSH 替身 |
|---|---|---|
| 文件类型/hex | `file`、`xxd` | `Format-Hex`；Python 读 magic |
| 字符串 | `strings` | `strings.exe`；Python 正则 |
| 文本过滤 | `rg` / `grep` | `rg` / `Select-String` |
| TCP 连接 | `nc` | Python socket（下）；`Test-NetConnection` 只测端口 |
| HTTP | `curl` | `curl.exe`、`Invoke-WebRequest` |
| ELF 头 | `readelf`、`checksec` | pyelftools（下）；或在有 Linux 工具链的环境检查 |
| 反汇编 | `objdump` | `objdump.exe`；capstone |
| 压缩包 | `7z`、`unzip` | `Expand-Archive`；Python zipfile/tarfile |
| 固件嵌套 | `binwalk -e` | Python magic 扫描 + 手工 carve |
| 流量 | `tshark` | 装 Wireshark；或 `pip install scapy` |
| 媒体 | `ffprobe` | `ffmpeg -i`（信息在 stderr） |
| 脱壳 | `upx -d` | 自写 stub 执行器（下节）；`uc`/unicorn 仿真 |
| ELF 仿真 | `gdb`、`qemu` | `unicorn`（pip 装 wheel），按 PT_LOAD 映射 + 桩 libc |
| dex/APK 反编译 | `jadx`、`apktool` | 自写极简 DEX 解析（下节）；`dexdump` 若在 Android SDK 中 |

## Python 替身（按小节依赖标准库或所列常见包）

**ELF 保护**（需 `pip install pyelftools`）：
```python
from elftools.elf.elffile import ELFFile
p='./chall'; e=ELFFile(open(p,'rb')); h=e.header
print('arch',h.e_machine,'ET_DYN',h.e_type=='ET_DYN')  # ET_DYN 也可能是共享库
st=[s for s in e.iter_segments() if s.header.p_type=='PT_GNU_STACK']
print('GNU_STACK executable', bool(st[0].header.p_flags&1) if st else 'unknown')
rel=[s for s in e.iter_segments() if s.header.p_type=='PT_GNU_RELRO']
print('RELRO',bool(rel),hex(rel[0].header.p_vaddr) if rel else '')
names=[]
for n in ('.dynsym','.symtab'):
    s=e.get_section_by_name(n)
    if s: names += [x.name for x in s.iter_symbols()]
print('canary','__stack_chk_fail' in names)
```

**PE 头**（标准库；先确认 DOS 头偏移在文件范围内）：
```python
import struct; d=open('a.exe','rb').read()
if len(d) < 0x40: raise ValueError('truncated DOS header')
o=struct.unpack_from('<I',d,0x3c)[0]
if o+6 > len(d): raise ValueError('invalid PE header offset')
print(d[o:o+4]==b'PE\0\0', hex(struct.unpack_from('<H',d,o+4)[0]))
```

**PNG 宽高/CRC**（先检查长度及 PNG/IHDR signature）：
```python
import struct,zlib; d=open('a.png','rb').read()
assert len(d) >= 33 and d[:8] == b'\x89PNG\r\n\x1a\n'
assert d[8:12] == b'\0\0\0\r' and d[12:16] == b'IHDR'
stored = struct.unpack('>I',d[29:33])[0]
actual = zlib.crc32(d[12:29]) & 0xffffffff
print(struct.unpack('>II',d[16:24]), 'CRC matches', stored == actual)
```

**压缩包清单**（此例仅 ZIP；tar 使用 `tarfile`）：
```python
import zipfile
for i in zipfile.ZipFile('a.zip').infolist():
    print(i.filename,i.file_size,i.compress_type,hex(i.CRC))
```

**裸 TCP 收 banner**（无 banner 时按题面/协议发最小合法探针，不盲发 `help`）：
```python
import socket,sys
with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=5) as s:
    s.settimeout(2)
    try: print('banner',repr(s.recv(4096)))
    except socket.timeout: print('no unsolicited banner')
```

**pcap**（需 `pip install scapy`；不能装就找 Wireshark/tshark）：
```python
from scapy.all import PcapReader, TCP, Raw
with PcapReader('a.pcap') as packets:
    for p in packets:
        if p.haslayer(TCP) and p.haslayer(Raw):
            print(p[TCP].sport,p[TCP].dport,bytes(p[Raw])[:80])
# 只是包级预览；完整重组需序号、重传和应用层边界处理，见 protocols.md
```

## 无原生调试器时的替身

Windows 无 WSL/gdb/docker 时，Unicorn 常比"装环境"更快，但要按原程序的加载语义搭台：

- **静态链接 ELF 端到端仿真**：按 PT_LOAD 映射（`p_vaddr` 起、`p_filesz` 拷入、bss 补零），在栈上放 argv/返回哨兵，从入口或目标函数跑到比较点；把 `fgets/strcmp/memcmp/puts` 等 libc 调用打桩成真实语义并记录参数与返回。反调试函数直接桩成期望返回值，不必实现 ptrace/rdtsc。
- **只跑纯校验函数**：需要一块 TLS/FS 区并 `reg_write(FS_BASE, ...)`；canary 槽置 0 或按默认值填，否则函数末尾 `__stack_chk_fail` 会打断。判据是仿真出的输入/中间缓冲与原始程序的行为一致，只能算该例程局部验证。
- **缺 upx 工具时**：用 Unicorn 执行壳 stub，把 IAT 目标改成假函数地址并 hook（VirtualProtect/LoadLibraryA/GetProcAddress/ExitProcess 等），RIP 落入解压段即 dump 镜像。假 API 所在页必须先 `mem_map`，否则 fetch 阶段报 `UC_ERR_FETCH_UNMAPPED`，hook 不会触发；dump 后用入口反汇编核对 OEP。
- **纯 dex 题无 jadx/apktool**：可写极简 DEX 解析，但 `class_data_item` 里 static/instance fields 每项各占 2 个 uleb，必须先跳过再读 methods，否则 `code_off` 全错。
- **证书/公钥取原始 DER**：`openssl pkcs7 -print_certs -outform DER` 有时仍打印文本，先看文件头 `30 82` 再哈希；salt 用证书 DER 时不要用 PEM 或摘要后的文本。

## 安装优先级

1. 纯标准库替身（上面）——先跑通，不装任何东西
2. 只装当前路径需要的包，例如 `python -m pip install pyelftools capstone`；解释器与 pip 保持一致，`py -0p` 列 Windows 可用版本
3. LLL 可试有 Windows wheel 的 `python-flint`；流量/图像按需选 `scapy pillow opencv-python`；不要为一次文件头检查安装整套工具
4. 仍缺（IDA/Ghidra/volatility/sage）→ 换等价手动路径，或把文件带回有工具的机器，不在赛中断点空等

安装失败先分包功能：Python 新版本缺 Unicorn wheel，不代表 ELF 解析、socket 或 ROP 字节拼装都不可用；只 import 实际需要的模块。必须做原生仿真时再选择有匹配 wheel 的解释器，记录 `python -c` 的 executable/version 与包路径；不为解决一个可选依赖盲目重编整套工具。Flutter/blutter 构建版本匹配见 [运行时链](reverse-runtime.md)。

大矩阵/GF(2)/LLL/音频遍历先估内存：Python 对象、临时副本、消元转置与多进程会远超原始数据大小。先跑可计时的小样本并观察私有提交量；设定工作进程、时间/内存预算，日志带进度且落盘检查点。已知大任务仍运行时不重复启动；不要通过扩大系统分页文件来替代算法降维和任务限额。

> 纪律：装工具/起服务用后台任务；不要为了一个一次性分析写巨型依赖，先用手上的库把最小验证做出来。

宿主工具名按当前会话实际能力选择，不在技能 frontmatter 写入其他助手专用的工具白名单。PowerShell 不使用 Bash heredoc；中文路径用明确编码，例如 `python -X utf8`。当前目录的 `token.py`、`enum.py`、`socket.py` 等可能遮蔽标准库：检查模块 `__file__`；`python -P` 仅移除不安全首路径，不等于隔离 PYTHONPATH，必要时清理任务环境或用 `-I`。Git Bash 会转换 `/flag` 等参数，按需用 `MSYS_NO_PATHCONV=1` 或把目标路径作为脚本内数据。
