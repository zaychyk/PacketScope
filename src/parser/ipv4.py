"""
IPv4 Protocol Parser
IPv4 网络层协议解析器
"""

import struct
from typing import Optional

from .base import BaseParser, LayerInfo, ProtocolType


class IPv4Parser(BaseParser):
    """
    IPv4 协议解析器

    首部格式 (20-60 bytes):
    +--------+--------+----------------+----------------+
    | 版本(4b)| IHL(4b)| 服务类型(8b)   | 总长度(16b)    |
    +--------+--------+----------------+----------------+
    |        标识(16b)                  | 标志(3b)|片偏移(13b)|
    +-----------------------------------+--------+--------+
    | 生存时间(8b) | 协议(8b)          | 首部校验和(16b)  |
    +--------------+-------------------+------------------+
    |              源 IP 地址 (32b)                       |
    +-----------------------------------------------------+
    |              目的 IP 地址 (32b)                       |
    +-----------------------------------------------------+
    |              选项（可选）                              |
    +-----------------------------------------------------+
    """

    # 协议号常量
    PROTOCOL_ICMP = 1
    PROTOCOL_TCP = 6
    PROTOCOL_UDP = 17
    PROTOCOL_IPV6 = 41

    # 标志位
    FLAG_RESERVED = 0x04  # 保留位
    FLAG_DONT_FRAGMENT = 0x02  # 不分片
    FLAG_MORE_FRAGMENTS = 0x01  # 更多分片

    def __init__(self):
        super().__init__()
        self.name = "IPv4"

    def parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> Optional[LayerInfo]:
        """
        解析 IPv4 数据报
        :param packet_data: IPv4 数据报（包含首部）
        :param previous_layer: 上一层协议信息
        :return: 解析后的 IPv4 层信息
        """
        if not self.can_parse(packet_data, previous_layer):
            return None

        layer = LayerInfo(protocol=ProtocolType.IPv4)

        # 解析首部和长度
        version_ihl = packet_data[0]
        version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F  # 首部长度（4字节为单位）
        header_length = ihl * 4

        if header_length < 20 or len(packet_data) < header_length:
            return None

        # 保存原始首部
        layer.raw_bytes = packet_data[:header_length]

        # 版本
        layer.add_field(
            name="Version",
            value=version,
            description="IP 版本号",
            size=4,
            offset=0
        )

        # 首部长度
        layer.add_field(
            name="Header Length",
            value=f"{header_length} bytes ({ihl} x 4 bytes)",
            description="Internet Header Length",
            size=4,
            offset=0
        )

        # 服务类型 (TOS)
        tos = packet_data[1]
        dscp = (tos >> 2) & 0x3F
        ecn = tos & 0x03
        layer.add_field(
            name="Differentiated Services Field",
            value=f"0x{tos:02x} (DSCP: {dscp}, ECN: {ecn})",
            description="服务类型 / 区分服务",
            size=8,
            offset=1
        )

        # 总长度
        total_length = struct.unpack("!H", packet_data[2:4])[0]
        layer.add_field(
            name="Total Length",
            value=f"{total_length} bytes",
            description="数据报总长度（首部 + 数据）",
            size=16,
            offset=2
        )

        # 标识
        identification = struct.unpack("!H", packet_data[4:6])[0]
        layer.add_field(
            name="Identification",
            value=f"0x{identification:04x}",
            description="标识字段",
            size=16,
            offset=4
        )

        # 标志和片偏移
        flags_offset = struct.unpack("!H", packet_data[6:8])[0]
        flags = (flags_offset >> 13) & 0x07
        fragment_offset = flags_offset & 0x1FFF

        flags_str = self._parse_flags(flags)
        layer.add_field(
            name="Flags",
            value=flags_str,
            description=f"标志位 (0x{flags:01x})",
            size=3,
            offset=6
        )

        layer.add_field(
            name="Fragment Offset",
            value=f"{fragment_offset} (offset = {fragment_offset * 8} bytes)",
            description="片偏移",
            size=13,
            offset=6
        )

        # 生存时间
        ttl = packet_data[8]
        layer.add_field(
            name="Time to Live",
            value=ttl,
            description="生存时间（跳数）",
            size=8,
            offset=8
        )

        # 协议
        protocol = packet_data[9]
        protocol_name = self._get_protocol_name(protocol)
        layer.add_field(
            name="Protocol",
            value=f"{protocol} ({protocol_name})",
            description="上层协议",
            size=8,
            offset=9
        )

        # 首部校验和
        checksum = struct.unpack("!H", packet_data[10:12])[0]
        checksum_valid = self._verify_checksum(packet_data[:header_length])
        layer.add_field(
            name="Header Checksum",
            value=f"0x{checksum:04x} ({'correct' if checksum_valid else 'incorrect'})",
            description="首部校验和",
            size=16,
            offset=10
        )

        # 源 IP
        src_ip = packet_data[12:16]
        layer.add_field(
            name="Source Address",
            value=self.bytes_to_ip(src_ip),
            description="源 IP 地址",
            size=32,
            offset=12
        )

        # 目的 IP
        dst_ip = packet_data[16:20]
        layer.add_field(
            name="Destination Address",
            value=self.bytes_to_ip(dst_ip),
            description="目的 IP 地址",
            size=32,
            offset=16
        )

        # 保存协议号和首部长度供下一层使用
        layer._protocol = protocol
        layer._header_length = header_length
        layer._total_length = total_length

        return layer

    def can_parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> bool:
        """检查是否可以解析（IPv4 首部至少 20 字节）"""
        if len(packet_data) < 20:
            return False
        version = (packet_data[0] >> 4) & 0x0F
        return version == 4

    def get_next_parser_type(self, layer: LayerInfo) -> Optional[ProtocolType]:
        """根据协议号返回下一层解析器类型"""
        protocol = getattr(layer, '_protocol', None)
        if protocol is None:
            return None

        mapping = {
            self.PROTOCOL_TCP: ProtocolType.TCP,
            self.PROTOCOL_UDP: ProtocolType.UDP,
            self.PROTOCOL_ICMP: ProtocolType.ICMP,
        }
        return mapping.get(protocol)

    def get_payload(self, packet_data: bytes, layer: LayerInfo) -> bytes:
        """获取 IPv4 数据报的有效载荷"""
        header_length = getattr(layer, '_header_length', 20)
        return packet_data[header_length:]

    def _parse_flags(self, flags: int) -> str:
        """解析标志位"""
        parts = []
        if flags & self.FLAG_RESERVED:
            parts.append("Reserved")
        if flags & self.FLAG_DONT_FRAGMENT:
            parts.append("Don't Fragment")
        if flags & self.FLAG_MORE_FRAGMENTS:
            parts.append("More Fragments")
        return " | ".join(parts) if parts else "None"

    def _get_protocol_name(self, protocol: int) -> str:
        """获取协议名称"""
        names = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP",
            41: "IPv6",
            47: "GRE",
            50: "ESP",
            51: "AH",
            58: "ICMPv6",
            89: "OSPF",
            132: "SCTP",
        }
        return names.get(protocol, f"Unknown ({protocol})")

    def _verify_checksum(self, header: bytes) -> bool:
        """验证首部校验和"""
        checksum = self.calculate_checksum(header)
        return checksum == 0
