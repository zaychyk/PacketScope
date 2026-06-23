"""
Base Parser Module
定义协议解析器基类和解析结果数据结构
"""

from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum
import time


class ProtocolType(Enum):
    """协议类型枚举"""
    ETHERNET = "Ethernet"
    IPv4 = "IPv4"
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    UNKNOWN = "Unknown"


@dataclass
class FieldInfo:
    """协议字段信息"""
    name: str           # 字段名称
    value: Any          # 字段值
    description: str    # 字段描述
    size: int = 0       # 字段大小（字节）
    offset: int = 0     # 字段偏移（字节）


@dataclass
class LayerInfo:
    """协议层信息"""
    protocol: ProtocolType
    fields: list[FieldInfo] = field(default_factory=list)
    raw_bytes: bytes = b""

    def add_field(self, name: str, value: Any, description: str = "",
                  size: int = 0, offset: int = 0) -> None:
        """添加字段信息"""
        self.fields.append(FieldInfo(name, value, description, size, offset))

    def get_field(self, name: str) -> Optional[FieldInfo]:
        """获取指定字段"""
        for f in self.fields:
            if f.name == name:
                return f
        return None


@dataclass
class ParsedPacket:
    """解析后的数据包"""
    timestamp: float = field(default_factory=time.time)
    layers: list[LayerInfo] = field(default_factory=list)
    raw_data: bytes = b""
    length: int = 0
    number: int = 0      # 包序号
    comment: str = ""    # 备注

    def add_layer(self, layer: LayerInfo) -> None:
        """添加协议层"""
        self.layers.append(layer)

    def get_layer(self, protocol: ProtocolType) -> Optional[LayerInfo]:
        """获取指定协议层"""
        for layer in self.layers:
            if layer.protocol == protocol:
                return layer
        return None

    def has_layer(self, protocol: ProtocolType) -> bool:
        """检查是否包含指定协议层"""
        return any(layer.protocol == protocol for layer in self.layers)

    def get_summary(self) -> str:
        """获取数据包摘要"""
        protocols = " / ".join(layer.protocol.value for layer in self.layers)
        return f"No.{self.number} [{protocols}] {self.length} bytes"


class BaseParser:
    """协议解析器基类"""

    def __init__(self):
        self.name = "BaseParser"

    @property
    def header_length(self) -> int:
        """协议首部长度（字节）。子类可重写。动态长度（如 IPv4/TCP）设为 0。"""
        return 0

    def get_header_length(self, layer: Optional['LayerInfo'] = None) -> int:
        """
        获取已解析层的实际首部长度。
        对于固定长度协议直接返回 header_length；
        对于动态长度协议（IPv4/TCP）从 layer._header_length 读取。
        """
        if layer is not None and hasattr(layer, '_header_length'):
            return layer._header_length
        return self.header_length

    def get_payload(self, packet_data: bytes, layer: Optional['LayerInfo'] = None) -> bytes:
        """获取有效载荷（去除首部后的数据）"""
        hdr_len = self.get_header_length(layer)
        return packet_data[hdr_len:]

    def parse(self, packet_data: bytes, previous_layer: Optional['LayerInfo'] = None) -> Optional['LayerInfo']:
        """
        解析协议数据
        :param packet_data: 原始字节数据
        :param previous_layer: 上一层协议信息
        :return: 解析后的协议层信息
        """
        raise NotImplementedError("Subclass must implement parse()")

    def can_parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> bool:
        """
        检查是否可以解析该数据
        :param packet_data: 原始字节数据
        :param previous_layer: 上一层协议信息
        :return: 是否可以解析
        """
        return True

    @staticmethod
    def bytes_to_hex(data: bytes, separator: str = " ") -> str:
        """字节转十六进制字符串"""
        return separator.join(f"{b:02x}" for b in data)

    @staticmethod
    def bytes_to_mac(data: bytes) -> str:
        """字节转 MAC 地址格式"""
        return ":".join(f"{b:02x}" for b in data)

    @staticmethod
    def bytes_to_ip(data: bytes) -> str:
        """字节转 IP 地址格式"""
        return ".".join(str(b) for b in data)

    @staticmethod
    def calculate_checksum(data: bytes) -> int:
        """计算校验和（用于验证）"""
        if len(data) % 2:
            data += b'\x00'
        total = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return (~total) & 0xffff
