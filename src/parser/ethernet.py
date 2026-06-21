"""
Ethernet Protocol Parser
以太网 II 帧解析器
"""

import struct
from typing import Optional

from .base import BaseParser, LayerInfo, ProtocolType


class EthernetParser(BaseParser):
    """
    以太网 II 帧解析器

    帧格式:
    +------------------+------------------+----------------+------------------+
    | 目的 MAC (6B)    | 源 MAC (6B)      | 类型 (2B)      | 数据 (46-1500B)  |
    +------------------+------------------+----------------+------------------+
    """

    # EtherType 常量
    ETHERTYPE_IP = 0x0800       # IPv4
    ETHERTYPE_ARP = 0x0806      # ARP
    ETHERTYPE_IPV6 = 0x86DD     # IPv6
    ETHERTYPE_VLAN = 0x8100     # 802.1Q VLAN
    ETHERTYPE_IPX = 0x8137      # IPX
    ETHERTYPE_PPP = 0x880B      # PPP

    # 最小帧长度
    MIN_FRAME_SIZE = 14  # 6 + 6 + 2

    def __init__(self):
        super().__init__()
        self.name = "Ethernet"

    def parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> Optional[LayerInfo]:
        """
        解析以太网帧
        :param packet_data: 原始帧数据
        :param previous_layer: 上一层（无）
        :return: 解析后的以太网层信息
        """
        if not self.can_parse(packet_data, previous_layer):
            return None

        layer = LayerInfo(
            protocol=ProtocolType.ETHERNET,
            raw_bytes=packet_data[:self.MIN_FRAME_SIZE]
        )

        # 解析目的 MAC (6 bytes)
        dst_mac = packet_data[0:6]
        layer.add_field(
            name="Destination MAC",
            value=self.bytes_to_mac(dst_mac),
            description="目的 MAC 地址",
            size=6,
            offset=0
        )

        # 解析源 MAC (6 bytes)
        src_mac = packet_data[6:12]
        layer.add_field(
            name="Source MAC",
            value=self.bytes_to_mac(src_mac),
            description="源 MAC 地址",
            size=6,
            offset=6
        )

        # 解析类型字段 (2 bytes)
        ethertype = struct.unpack("!H", packet_data[12:14])[0]
        ethertype_name = self._get_ethertype_name(ethertype)
        layer.add_field(
            name="Type",
            value=f"0x{ethertype:04x} ({ethertype_name})",
            description="上层协议类型",
            size=2,
            offset=12
        )

        # 保存 EtherType 供下一层使用
        layer._ethertype = ethertype

        return layer

    def can_parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> bool:
        """检查是否可以解析（以太网帧至少 14 字节）"""
        return len(packet_data) >= self.MIN_FRAME_SIZE

    def get_next_parser_type(self, layer: LayerInfo) -> Optional[ProtocolType]:
        """根据 EtherType 返回下一层解析器类型"""
        ethertype = getattr(layer, '_ethertype', None)
        if ethertype is None:
            return None

        mapping = {
            self.ETHERTYPE_IP: ProtocolType.IPv4,
            self.ETHERTYPE_IPV6: ProtocolType.IPv6,
            self.ETHERTYPE_ARP: ProtocolType.ARP,
        }
        return mapping.get(ethertype)

    def _get_ethertype_name(self, ethertype: int) -> str:
        """获取 EtherType 名称"""
        names = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8100: "802.1Q VLAN",
            0x8137: "IPX",
            0x880B: "PPP",
            0x88CC: "LLDP",
            0x8809: "Slow Protocols",
            0x9000: "Loopback",
        }
        return names.get(ethertype, f"Unknown (0x{ethertype:04x})")

    def get_payload(self, packet_data: bytes) -> bytes:
        """获取以太网帧的有效载荷（去除帧头）"""
        return packet_data[self.MIN_FRAME_SIZE:]
