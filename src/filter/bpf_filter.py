"""
BPF Filter Module
BPF 语法数据包过滤
"""

import re
from typing import Optional, Callable
from scapy.packet import Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP


class BPFFilter:
    """
    BPF 过滤器

    支持常用 BPF 过滤语法：
    - "tcp" / "udp" / "icmp" / "arp"
    - "tcp port 80" / "udp port 53"
    - "port 80" (TCP 或 UDP)
    - "host 192.168.1.1"
    """

    # 常用过滤器预设
    PRESETS = {
        "http": "tcp port 80",
        "https": "tcp port 443",
        "dns": "udp port 53",
        "ssh": "tcp port 22",
        "icmp": "icmp",
        "tcp": "tcp",
        "udp": "udp",
    }

    def __init__(self, filter_expr: str = ""):
        """
        初始化过滤器
        :param filter_expr: BPF 过滤表达式
        """
        self.filter_expr = filter_expr
        self._is_valid = True
        self._error_msg = ""
        self._matcher: Optional[Callable[[Packet], bool]] = None

        if filter_expr:
            self._compile()

    def _compile(self) -> None:
        """编译过滤器表达式为匹配函数"""
        expr = self.filter_expr.strip().lower()

        if not expr:
            self._matcher = None
            return

        try:
            self._matcher = self._build_matcher(expr)
            self._is_valid = True
            self._error_msg = ""
        except Exception as e:
            self._is_valid = False
            self._error_msg = str(e)
            self._matcher = None

    def _build_matcher(self, expr: str) -> Callable[[Packet], bool]:
        """构建匹配函数"""
        # tcp port X
        m = re.match(r'^tcp\s+port\s+(\d+)$', expr)
        if m:
            port = int(m.group(1))
            return lambda p: p.haslayer(TCP) and (p[TCP].sport == port or p[TCP].dport == port)

        # udp port X
        m = re.match(r'^udp\s+port\s+(\d+)$', expr)
        if m:
            port = int(m.group(1))
            return lambda p: p.haslayer(UDP) and (p[UDP].sport == port or p[UDP].dport == port)

        # port X (TCP or UDP)
        m = re.match(r'^port\s+(\d+)$', expr)
        if m:
            port = int(m.group(1))
            return lambda p: (
                (p.haslayer(TCP) and (p[TCP].sport == port or p[TCP].dport == port)) or
                (p.haslayer(UDP) and (p[UDP].sport == port or p[UDP].dport == port))
            )

        # host X.X.X.X
        m = re.match(r'^host\s+([\d.]+)$', expr)
        if m:
            host = m.group(1)
            return lambda p: p.haslayer(IP) and (p[IP].src == host or p[IP].dst == host)

        # Simple protocol names
        if expr == "tcp":
            return lambda p: p.haslayer(TCP)
        if expr == "udp":
            return lambda p: p.haslayer(UDP)
        if expr == "icmp":
            return lambda p: p.haslayer(ICMP)
        if expr == "arp":
            return lambda p: p.haslayer(ARP)
        if expr == "ip" or expr == "ipv4":
            return lambda p: p.haslayer(IP)
        if expr == "ether" or expr == "ethernet":
            return lambda p: p.haslayer(Ether)

        raise ValueError(f"Unsupported filter expression: {expr}")

    def validate(self) -> bool:
        """
        验证 BPF 过滤器语法
        :return: 是否有效
        """
        return self._is_valid

    def compile(self) -> bool:
        """
        编译 BPF 过滤器
        :return: 是否编译成功
        """
        self._compile()
        return self._is_valid

    def match(self, packet: Packet) -> bool:
        """
        检查数据包是否匹配过滤器
        :param packet: 数据包
        :return: 是否匹配
        """
        if not self.filter_expr or not self._is_valid or self._matcher is None:
            return True

        try:
            return self._matcher(packet)
        except Exception:
            return False

    def filter_packets(self, packets: list[Packet]) -> list[Packet]:
        """
        过滤数据包列表
        :param packets: 数据包列表
        :return: 匹配的数据包列表
        """
        if not self.filter_expr or not self._is_valid:
            return packets

        return [pkt for pkt in packets if self.match(pkt)]

    def is_valid(self) -> bool:
        """检查过滤器是否有效"""
        return self._is_valid

    def get_error(self) -> bool:
        """获取编译错误信息"""
        return self._error_msg

    def set_filter(self, filter_expr: str) -> bool:
        """
        设置新的过滤表达式
        :param filter_expr: BPF 过滤表达式
        :return: 是否设置成功
        """
        self.filter_expr = filter_expr
        return self.compile()

    def clear(self) -> None:
        """清除过滤器"""
        self.filter_expr = ""
        self._is_valid = True
        self._error_msg = ""
        self._matcher = None

    @classmethod
    def from_preset(cls, preset_name: str) -> "BPFFilter":
        """
        从预设创建过滤器
        :param preset_name: 预设名称
        :return: BPFFilter 实例
        """
        expr = cls.PRESETS.get(preset_name.lower(), "")
        return cls(expr)

    @classmethod
    def list_presets(cls) -> dict:
        """列出所有预设"""
        return cls.PRESETS.copy()

    @staticmethod
    def build_host_filter(host: str) -> str:
        """构建主机过滤器"""
        return f"host {host}"

    @staticmethod
    def build_port_filter(port: int, protocol: str = "tcp") -> str:
        """构建端口过滤器"""
        return f"{protocol} port {port}"

    @staticmethod
    def build_network_filter(network: str) -> str:
        """构建网络过滤器"""
        return f"net {network}"

    def __str__(self) -> str:
        return self.filter_expr or "(no filter)"

    def __bool__(self) -> bool:
        return bool(self.filter_expr) and self._is_valid
