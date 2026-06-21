"""
ICMP Protocol Parser
ICMP 网络控制报文协议解析器
"""

import struct
from typing import Optional

from .base import BaseParser, LayerInfo, ProtocolType


class ICMPParser(BaseParser):
    """
    ICMP 协议解析器

    报文格式:
    +--------+--------+-------------------+
    | 类型(8b)| 代码(8b)|   校验和 (16b)    |
    +--------+--------+-------------------+
    |        其余部分（随类型/代码变化）      |
    +-------------------------------------+

    常见类型:
    - 0: Echo Reply (回显应答)
    - 3: Destination Unreachable (目的不可达)
    - 8: Echo Request (回显请求)
    - 11: Time Exceeded (超时)
    """

    # ICMP 类型常量
    TYPE_ECHO_REPLY = 0
    TYPE_DEST_UNREACHABLE = 3
    TYPE_SOURCE_QUENCH = 4
    TYPE_REDIRECT = 5
    TYPE_ECHO_REQUEST = 8
    TYPE_TIME_EXCEEDED = 11
    TYPE_PARAMETER_PROBLEM = 12
    TYPE_TIMESTAMP_REQUEST = 13
    TYPE_TIMESTAMP_REPLY = 14
    TYPE_INFO_REQUEST = 15
    TYPE_INFO_REPLY = 16

    # 最小报文长度
    MIN_HEADER_SIZE = 8

    def __init__(self):
        super().__init__()
        self.name = "ICMP"

    def parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> Optional[LayerInfo]:
        """
        解析 ICMP 报文
        :param packet_data: ICMP 报文
        :param previous_layer: 上一层协议信息
        :return: 解析后的 ICMP 层信息
        """
        if not self.can_parse(packet_data, previous_layer):
            return None

        layer = LayerInfo(protocol=ProtocolType.ICMP)
        layer.raw_bytes = packet_data[:self.MIN_HEADER_SIZE]

        # 类型
        icmp_type = packet_data[0]
        type_name = self._get_type_name(icmp_type)
        layer.add_field(
            name="Type",
            value=f"{icmp_type} ({type_name})",
            description="ICMP 报文类型",
            size=8,
            offset=0
        )

        # 代码
        code = packet_data[1]
        code_desc = self._get_code_description(icmp_type, code)
        layer.add_field(
            name="Code",
            value=f"{code} ({code_desc})",
            description="ICMP 代码",
            size=8,
            offset=1
        )

        # 校验和
        checksum = struct.unpack("!H", packet_data[2:4])[0]
        checksum_valid = self._verify_checksum(packet_data)
        layer.add_field(
            name="Checksum",
            value=f"0x{checksum:04x} ({'correct' if checksum_valid else 'incorrect'})",
            description="校验和",
            size=16,
            offset=2
        )

        # 根据类型解析其余字段
        if icmp_type in (self.TYPE_ECHO_REQUEST, self.TYPE_ECHO_REPLY):
            self._parse_echo_fields(packet_data, layer)
        elif icmp_type == self.TYPE_DEST_UNREACHABLE:
            self._parse_unreachable_fields(packet_data, layer)
        elif icmp_type == self.TYPE_TIME_EXCEEDED:
            self._parse_time_exceeded_fields(packet_data, layer)

        # 保存类型供后续使用
        layer._type = icmp_type
        layer._code = code

        return layer

    def can_parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> bool:
        """检查是否可以解析（ICMP 至少 8 字节）"""
        return len(packet_data) >= self.MIN_HEADER_SIZE

    def _parse_echo_fields(self, packet_data: bytes, layer: LayerInfo) -> None:
        """解析 Echo Request/Reply 字段"""
        if len(packet_data) >= 8:
            # Identifier
            identifier = struct.unpack("!H", packet_data[4:6])[0]
            layer.add_field(
                name="Identifier",
                value=f"0x{identifier:04x}",
                description="标识符",
                size=16,
                offset=4
            )

            # Sequence Number
            seq_num = struct.unpack("!H", packet_data[6:8])[0]
            layer.add_field(
                name="Sequence Number",
                value=seq_num,
                description="序列号",
                size=16,
                offset=6
            )

    def _parse_unreachable_fields(self, packet_data: bytes, layer: LayerInfo) -> None:
        """解析 Destination Unreachable 字段"""
        if len(packet_data) >= 8:
            # Unused (4 bytes)
            layer.add_field(
                name="Unused",
                value=packet_data[4:8].hex(),
                description="未使用",
                size=32,
                offset=4
            )

        # 原始 IP 数据报 + 前 8 字节
        if len(packet_data) > 8:
            original_data = packet_data[8:]
            layer.add_field(
                name="Internet Header + 64 bits of Original Data",
                value=original_data.hex() if len(original_data) <= 32 else original_data[:32].hex() + "...",
                description="引发差错的原始 IP 数据报",
                size=len(original_data) * 8,
                offset=8
            )

    def _parse_time_exceeded_fields(self, packet_data: bytes, layer: LayerInfo) -> None:
        """解析 Time Exceeded 字段"""
        if len(packet_data) >= 8:
            layer.add_field(
                name="Unused",
                value=packet_data[4:8].hex(),
                description="未使用",
                size=32,
                offset=4
            )

    def _get_type_name(self, icmp_type: int) -> str:
        """获取 ICMP 类型名称"""
        names = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            9: "Router Advertisement",
            10: "Router Solicitation",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp Request",
            14: "Timestamp Reply",
            15: "Information Request",
            16: "Information Reply",
            17: "Address Mask Request",
            18: "Address Mask Reply",
            30: "Traceroute",
        }
        return names.get(icmp_type, f"Unknown ({icmp_type})")

    def _get_code_description(self, icmp_type: int, code: int) -> str:
        """获取代码描述"""
        descriptions = {
            (3, 0): "Network Unreachable",
            (3, 1): "Host Unreachable",
            (3, 2): "Protocol Unreachable",
            (3, 3): "Port Unreachable",
            (3, 4): "Fragmentation Needed",
            (3, 13): "Communication Administratively Prohibited",
            (11, 0): "TTL exceeded in transit",
            (11, 1): "Fragment reassembly time exceeded",
        }
        return descriptions.get((icmp_type, code), "See type-specific codes")

    def _verify_checksum(self, packet_data: bytes) -> bool:
        """验证 ICMP 校验和"""
        checksum = self.calculate_checksum(packet_data)
        return checksum == 0
