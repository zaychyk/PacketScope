# 网络协议分析仪简化版

> 轻量化复刻 Wireshark 核心功能的网络协议分析仪，基于 Python + Scapy + PyQt6 实现

## 功能特性

### 核心功能
- **数据包捕获**：一键实时网卡抓包 + 本地 pcap 文件读取
- **Ethernet 二层分析**：解析源/目的 MAC 地址、上层协议类型
- **IPv4 网络层分析**：解析首部长度、TTL、分片信息、源/目的 IP 地址
- **TCP 传输层分析**：解析端口号、序列号、窗口大小、六位标志位
- **UDP 传输层分析**：解析端口号、报文长度、校验和
- **ICMP 解析**：支持差错与查询报文全字段解析
- **BPF 语法过滤**：支持标准 BPF 过滤表达式（HTTP/HTTPS/DNS/SSH/ICMP/ARP/TCP/UDP 预设）
- **协议流量统计**：协议分布、字节数、占比统计
- **原始数据导出**：十六进制导出、pcap 格式导出

### 界面特性
- 仿 Wireshark 三栏式图形界面（PyQt6，原生 Wayland 支持）
- 报文列表、协议详情树、十六进制视图（暗色主题）
- 可拖动列宽、可调整面板高度
- 清晰易读的字体配置（DejaVu Sans）
- 一键操作，无需命令行

## 安装

### 环境配置
```bash
conda env create -f environment.yml
conda activate net_design
```

### 抓包权限（Linux）
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3.14)
```

### Wayland/Hyprland 用户
```bash
export DISPLAY=:1
```

## 使用方法

### 启动（推荐 - 一键脚本）
```bash
./run.sh
```

### 启动（手动）
```bash
conda activate net_design
export DISPLAY=:1  # Wayland/Hyprland 用户需要
python -m src
```

> **注意**：必须使用 conda 环境中的 Python，系统 Python 没有安装 PyQt6。
> 如果直接运行 `python -m src` 报 `ModuleNotFoundError: No module named 'PyQt6'`，
> 说明没有激活 conda 环境，请使用 `./run.sh` 或先执行 `conda activate net_design`。

### 操作步骤
1. **打开文件**：点击 Open File，选择 pcap 文件
2. **一键抓包**：点击 Start Capture，选择网卡接口
3. **过滤报文**：下拉选择预设或输入 BPF 表达式，点 Apply
4. **查看详情**：点击报文行查看协议详情和十六进制数据
5. **流量统计**：点击 Statistics 查看协议分布
6. **导出数据**：点击 Export 保存报文（txt/hex/pcap）

## 项目结构

```
PacketScope/
├── run.sh                # 一键启动脚本
├── README.md             # 本文件
├── environment.yml       # Conda 环境配置
├── .gitignore
│
└── src/
    ├── main.py           # 主入口 (QApplication)
    ├── __main__.py       # python -m src 入口
    │
    ├── capture/          # 数据包捕获模块
    │   ├── real_time.py  # 实时网卡抓包 (AsyncSniffer)
    │   ├── file_reader.py# pcap 文件读取
    │   └── buffer.py     # 线程安全捕获缓冲区
    │
    ├── parser/           # 协议解析模块
    │   ├── base.py       # 基类与数据结构
    │   ├── ethernet.py   # Ethernet II (MAC, EtherType)
    │   ├── ipv4.py       # IPv4 (TTL, 分片, 校验和)
    │   ├── tcp.py        # TCP (端口, 序列号, 标志位)
    │   ├── udp.py        # UDP (端口, 长度, 校验和)
    │   └── icmp.py       # ICMP (差错与查询报文)
    │
    ├── filter/           # BPF 过滤模块
    │   ── bpf_filter.py # BPF 语法过滤 + 8 种预设
    │
    ├── stats/            # 流量统计模块
    │   └── traffic_stats.py
    │
    ├── export/           # 数据导出模块
    │   └── hex_exporter.py
    │
    └── gui/              # PyQt6 图形界面
        ├── main_window.py    # QMainWindow + QSplitter 三栏布局
        ├── toolbar.py        # 工具栏按钮
        ├── filter_bar.py     # BPF 过滤栏
        ├── packet_list.py    # 报文列表 (QTableWidget)
        ├── detail_view.py    # 协议详情树 (QTreeWidget)
        ├── hex_view.py       # 十六进制视图 (暗色主题)
        ├── file_dialog.py    # 文件对话框 (QFileDialog)
        └── fonts.py          # 字体配置
```

## 技术架构

### 协议解析层次
1. **数据链路层**: Ethernet II 帧 → MAC 地址、EtherType
2. **网络层**: IPv4 → 首部字段、TTL、分片、校验和
3. **传输层**: TCP（端口/序列号/标志位）/ UDP（端口/长度/校验和）
4. **网络控制层**: ICMP → 差错与查询报文

### 技术栈
| 组件 | 技术 |
|------|------|
| 语言 | Python 3.14 |
| 抓包 | Scapy 2.7.0 (AsyncSniffer) |
| GUI | PyQt6 6.11 (QMainWindow + QSplitter) |
| 过滤 | BPF 语法 (Scapy packet.matches) |
| 字体 | DejaVu Sans (fontconfig) |

## 参考资料

1. 张建忠，《计算机网络实验指导书》，清华大学出版社
2. 谢希仁，《计算机网络（第8版）》，电子工业出版社
3. [Scapy 官方文档](https://scapy.net/)
4. [PyQt6 官方文档](https://www.riverbankcomputing.com/static/Docs/PyQt6/)

## 许可证

本项目为课程设计作品，仅供学习参考使用。
