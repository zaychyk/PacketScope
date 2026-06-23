"""
Ethernet Protocol Parser
以太网 II 帧解析器
"""

import binascii
import struct
from typing import Optional

from .base import BaseParser, LayerInfo, ProtocolType


class EthernetParser(BaseParser):
    """
    以太网 II 帧解析器

    帧格式:
    +------------------+------------------+----------------+------------------+----------+
    | 目的 MAC (6B)    | 源 MAC (6B)      | 类型 (2B)      | 数据 (46-1500B)  | FCS (4B) |
    +------------------+------------------+----------------+------------------+----------+
    注：FCS (Frame Check Sequence) 通常由 NIC 驱动校验后剥离，
        scapy 抓包获取的帧不含 FCS 尾部。
    """

    # EtherType 常量
    ETHERTYPE_IP = 0x0800       # IPv4
    ETHERTYPE_VLAN = 0x8100     # 802.1Q VLAN
    ETHERTYPE_IPX = 0x8137      # IPX
    ETHERTYPE_PPP = 0x880B      # PPP

    # 帧头长度（不含 FCS）
    HEADER_SIZE = 14  # 6 + 6 + 2
    # FCS 长度
    FCS_SIZE = 4
    # 最小帧长度（含 FCS 的最小以太网帧 = 64B，但去掉前导码/SFD 后为 60B + 4B FCS）
    MIN_FRAME_SIZE = 14

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
            raw_bytes=packet_data[:self.HEADER_SIZE]
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

        # 解析 FCS (Frame Check Sequence) — 帧校验标识
        # FCS 是帧尾 4 字节 CRC-32 校验值
        # scapy 抓包时 NIC 驱动通常会剥离 FCS，因此大多数情况下帧中不含 FCS
        fcs_value, fcs_desc = self._parse_fcs(packet_data)
        layer.add_field(
            name="Frame Check Sequence",
            value=fcs_value,
            description=f"帧校验标识 (FCS) — {fcs_desc}",
            size=self.FCS_SIZE,
            offset=len(packet_data) - self.FCS_SIZE if len(packet_data) >= self.FCS_SIZE else -1
        )

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
        return packet_data[self.HEADER_SIZE:]

    @property
    def header_length(self) -> int:
        """以太网帧头固定长度（不含 FCS）"""
        return self.HEADER_SIZE

    def _parse_fcs(self, packet_data: bytes) -> tuple[str, str]:
        """
        尝试解析帧尾 FCS 字段
        :return: (显示值, 描述) 元组
        """
        # 以太网最小帧 64 字节（含 14B 帧头 + 46B 最小数据 + 4B FCS）
        # 如果帧长度刚好超过帧头 + 最小载荷，末尾 4 字节可能是 FCS
        # 但 scapy 从 pcap / AF_PACKET 读取的帧通常不含 FCS
        if len(packet_data) < self.HEADER_SIZE + self.FCS_SIZE:
            return "N/A", "帧过短，无 FCS"

        # 尝试读取帧尾 4 字节作为 FCS
        tail = packet_data[-self.FCS_SIZE:]
        fcs_hex = "0x" + tail.hex().upper()

        # 验证 CRC-32：对整个帧（含 FCS）计算 CRC-32，结果应为 0xC704DD7B
        try:
            crc_result = binascii.crc32(packet_data)
            if crc_result == 0xC704DD7B:
                return fcs_hex, "CRC-32 校验正确"
            else:
                return fcs_hex, "CRC-32 校验不匹配（可能非 FCS 数据）"
        except Exception:
            return fcs_hex, "CRC-32 校验异常"
