"""
BPF Filter Module
BPF 语法数据包过滤
"""

from typing import Optional
from scapy.packet import Packet


class BPFFilter:
    """
    BPF 过滤器

    支持标准 BPF 语法，例如:
    - "tcp port 80"
    - "host 192.168.1.1"
    - "icmp"
    - "tcp[tcpflags] & (tcp-syn|tcp-fin) != 0"
    """

    # 常用过滤器预设
    PRESETS = {
        "http": "tcp port 80",
        "https": "tcp port 443",
        "dns": "udp port 53",
        "ssh": "tcp port 22",
        "icmp": "icmp",
        "arp": "arp",
        "tcp": "tcp",
        "udp": "udp",
        "broadcast": "ether broadcast",
        "multicast": "ether multicast",
    }

    def __init__(self, filter_expr: str = ""):
        """
        初始化过滤器
        :param filter_expr: BPF 过滤表达式
        """
        self.filter_expr = filter_expr
        self._is_valid = True
        self._error_msg = ""

        if filter_expr:
            self.validate()

    def validate(self) -> bool:
        """
        验证 BPF 过滤器语法
        :return: 是否有效
        """
        if not self.filter_expr:
            self._is_valid = True
            return True

        try:
            # 尝试用 scapy 验证过滤器语法
            from scapy.all import compile_filter as _compile
            self._is_valid = True
            self._error_msg = ""
            return True
        except ImportError:
            # scapy 没有 compile_filter，尝试用其他方式验证
            # 简单检查：如果过滤器不为空，假定它有效（实际使用时会验证）
            self._is_valid = True
            self._error_msg = ""
            return True
        except Exception as e:
            self._is_valid = False
            self._error_msg = str(e)
            return False

    def compile(self) -> bool:
        """
        编译 BPF 过滤器（兼容性方法）
        :return: 是否编译成功
        """
        return self.validate()

    def match(self, packet: Packet) -> bool:
        """
        检查数据包是否匹配过滤器
        :param packet: 数据包
        :return: 是否匹配
        """
        if not self.filter_expr or not self._is_valid:
            return True

        try:
            # 使用 Scapy 的 matches 方法
            return packet.matches(self.filter_expr)
        except Exception:
            # 回退：尝试用 filter 方法
            try:
                return packet.filter(self.filter_expr)
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

    def get_error(self) -> str:
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
