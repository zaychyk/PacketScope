"""
UDP Protocol Parser
UDP 传输层协议解析器
"""

import struct
from typing import Optional

from .base import BaseParser, LayerInfo, ProtocolType


class UDPParser(BaseParser):
    """
    UDP 协议解析器

    首部格式 (8 bytes):
    +-------------------+-------------------+
    |     源端口 (16b)   |    目的端口 (16b)  |
    +-------------------+-------------------+
    |     长度 (16b)     |    校验和 (16b)    |
    +-------------------+-------------------+
    """

    HEADER_SIZE = 8

    def __init__(self):
        super().__init__()
        self.name = "UDP"

    def parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> Optional[LayerInfo]:
        """
        解析 UDP 数据报
        :param packet_data: UDP 数据报（包含首部）
        :param previous_layer: 上一层协议信息
        :return: 解析后的 UDP 层信息
        """
        if not self.can_parse(packet_data, previous_layer):
            return None

        layer = LayerInfo(protocol=ProtocolType.UDP)
        layer.raw_bytes = packet_data[:self.HEADER_SIZE]

        # 源端口
        src_port = struct.unpack("!H", packet_data[0:2])[0]
        layer.add_field(
            name="Source Port",
            value=src_port,
            description="源端口号",
            size=16,
            offset=0
        )

        # 目的端口
        dst_port = struct.unpack("!H", packet_data[2:4])[0]
        layer.add_field(
            name="Destination Port",
            value=dst_port,
            description="目的端口号",
            size=16,
            offset=2
        )

        # 长度
        length = struct.unpack("!H", packet_data[4:6])[0]
        layer.add_field(
            name="Length",
            value=f"{length} bytes",
            description="UDP 报文长度（首部 + 数据）",
            size=16,
            offset=4
        )

        # 校验和
        checksum = struct.unpack("!H", packet_data[6:8])[0]
        checksum_str = f"0x{checksum:04x}"
        if checksum == 0:
            checksum_str += " (not computed)"
        layer.add_field(
            name="Checksum",
            value=checksum_str,
            description="校验和（包含伪首部）",
            size=16,
            offset=6
        )

        # 保存长度供获取有效载荷
        layer._length = length

        return layer

    def can_parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> bool:
        """检查是否可以解析（UDP 首部 8 字节）"""
        return len(packet_data) >= self.HEADER_SIZE

    def get_payload(self, packet_data: bytes, layer: LayerInfo) -> bytes:
        """获取 UDP 数据报的有效载荷"""
        return packet_data[self.HEADER_SIZE:]

    def get_data_length(self, layer: LayerInfo) -> int:
        """获取数据部分长度"""
        length = getattr(layer, '_length', 0)
        return max(0, length - self.HEADER_SIZE)
