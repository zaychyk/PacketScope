"""
TCP Protocol Parser
TCP 传输层协议解析器
"""

import struct
from typing import Optional

from .base import BaseParser, LayerInfo, ProtocolType


class TCPParser(BaseParser):
    """
    TCP 协议解析器

    首部格式 (20-60 bytes):
    +-------------------+-------------------+
    |     源端口 (16b)   |    目的端口 (16b)  |
    +-------------------+-------------------+
    |        序号 (32b)                      |
    +---------------------------------------+
    |        确认号 (32b)                    |
    +---------------------------------------+
    | 数据偏移(4b) | 保留 |URG|ACK|PSH|RST|SYN|FIN|
    +-------------------+-------------------+
    |     窗口大小 (16b)  |   校验和 (16b)    |
    +-------------------+-------------------+
    |    紧急指针 (16b)   |    选项（可选）    |
    +-------------------+-------------------+
    """

    # TCP 标志位
    FLAG_FIN = 0x01
    FLAG_SYN = 0x02
    FLAG_RST = 0x04
    FLAG_PSH = 0x08
    FLAG_ACK = 0x10
    FLAG_URG = 0x20
    FLAG_ECE = 0x40
    FLAG_CWR = 0x80

    def __init__(self):
        super().__init__()
        self.name = "TCP"

    def parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> Optional[LayerInfo]:
        """
        解析 TCP 报文段
        :param packet_data: TCP 报文段（包含首部）
        :param previous_layer: 上一层协议信息
        :return: 解析后的 TCP 层信息
        """
        if not self.can_parse(packet_data, previous_layer):
            return None

        layer = LayerInfo(protocol=ProtocolType.TCP)

        # 解析数据偏移（首部长度）
        data_offset = (packet_data[12] >> 4) & 0x0F
        header_length = data_offset * 4

        if header_length < 20 or len(packet_data) < header_length:
            return None

        # 保存原始首部
        layer.raw_bytes = packet_data[:header_length]

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

        # 序号
        seq_num = struct.unpack("!I", packet_data[4:8])[0]
        layer.add_field(
            name="Sequence Number",
            value=seq_num,
            description="序列号",
            size=32,
            offset=4
        )

        # 确认号
        ack_num = struct.unpack("!I", packet_data[8:12])[0]
        layer.add_field(
            name="Acknowledgment Number",
            value=ack_num,
            description="确认号（ACK 标志置位时有效）",
            size=32,
            offset=8
        )

        # 数据偏移
        layer.add_field(
            name="Data Offset",
            value=f"{header_length} bytes ({data_offset} x 4 bytes)",
            description="首部长度",
            size=4,
            offset=12
        )

        # 标志位
        flags = packet_data[13]
        flags_str = self._parse_flags(flags)
        layer.add_field(
            name="Flags",
            value=flags_str,
            description=f"控制位 (0x{flags:02x})",
            size=8,
            offset=13
        )

        # 窗口大小
        window = struct.unpack("!H", packet_data[14:16])[0]
        layer.add_field(
            name="Window Size",
            value=window,
            description="接收窗口大小",
            size=16,
            offset=14
        )

        # 校验和
        checksum = struct.unpack("!H", packet_data[16:18])[0]
        layer.add_field(
            name="Checksum",
            value=f"0x{checksum:04x}",
            description="校验和（包含伪首部）",
            size=16,
            offset=16
        )

        # 紧急指针
        urgent_ptr = struct.unpack("!H", packet_data[18:20])[0]
        layer.add_field(
            name="Urgent Pointer",
            value=urgent_ptr,
            description="紧急指针（URG 标志置位时有效）",
            size=16,
            offset=18
        )

        # 保存首部长度供获取有效载荷
        layer._header_length = header_length

        return layer

    def can_parse(self, packet_data: bytes, previous_layer: Optional[LayerInfo] = None) -> bool:
        """检查是否可以解析（TCP 首部至少 20 字节）"""
        return len(packet_data) >= 20

    def get_payload(self, packet_data: bytes, layer: LayerInfo) -> bytes:
        """获取 TCP 报文段的有效载荷"""
        header_length = getattr(layer, '_header_length', 20)
        return packet_data[header_length:]

    def _parse_flags(self, flags: int) -> str:
        """解析六位标志位"""
        flag_names = []
        if flags & self.FLAG_FIN:
            flag_names.append("FIN")
        if flags & self.FLAG_SYN:
            flag_names.append("SYN")
        if flags & self.FLAG_RST:
            flag_names.append("RST")
        if flags & self.FLAG_PSH:
            flag_names.append("PSH")
        if flags & self.FLAG_ACK:
            flag_names.append("ACK")
        if flags & self.FLAG_URG:
            flag_names.append("URG")
        if flags & self.FLAG_ECE:
            flag_names.append("ECE")
        if flags & self.FLAG_CWR:
            flag_names.append("CWR")
        return ", ".join(flag_names) if flag_names else "None"

    def get_flag_details(self, flags: int) -> dict:
        """获取标志位详细信息"""
        return {
            "FIN": bool(flags & self.FLAG_FIN),
            "SYN": bool(flags & self.FLAG_SYN),
            "RST": bool(flags & self.FLAG_RST),
            "PSH": bool(flags & self.FLAG_PSH),
            "ACK": bool(flags & self.FLAG_ACK),
            "URG": bool(flags & self.FLAG_URG),
            "ECE": bool(flags & self.FLAG_ECE),
            "CWR": bool(flags & self.FLAG_CWR),
        }
