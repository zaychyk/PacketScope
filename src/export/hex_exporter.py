"""
Hex Export Module
报文原始十六进制导出
"""

from typing import Optional
from pathlib import Path
from scapy.packet import Packet

from ..parser.base import ParsedPacket


class HexExporter:
    """
    十六进制导出器

    支持:
    - 单个数据包导出
    - 批量导出
    - 多种格式（纯文本、C array、Wireshark 格式）
    """

    def __init__(self):
        """初始化导出器"""
        pass

    @staticmethod
    def packet_to_hex(packet: Packet, separator: str = " ") -> str:
        """
        数据包转十六进制字符串
        :param packet: Scapy 数据包
        :param separator: 字节分隔符
        :return: 十六进制字符串
        """
        raw_bytes = bytes(packet)
        return separator.join(f"{b:02x}" for b in raw_bytes)

    @staticmethod
    def packet_to_hex_dump(packet: Packet, width: int = 16) -> str:
        """
        数据包转十六进制转储（Wireshark 风格）
        :param packet: Scapy 数据包
        :param width: 每行字节数
        :return: 格式化的十六进制转储
        """
        raw_bytes = bytes(packet)
        lines = []

        for offset in range(0, len(raw_bytes), width):
            chunk = raw_bytes[offset:offset + width]

            # 偏移地址
            offset_str = f"{offset:08x}"

            # 十六进制部分
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(width * 3 - 1)

            # ASCII 部分
            ascii_part = "".join(
                chr(b) if 32 <= b < 127 else "."
                for b in chunk
            )

            lines.append(f"{offset_str}  {hex_part}  |{ascii_part}|")

        return "\n".join(lines)

    @staticmethod
    def packet_to_c_array(packet: Packet, array_name: str = "packet_data") -> str:
        """
        数据包转 C 语言数组格式
        :param packet: Scapy 数据包
        :param array_name: 数组名称
        :return: C 数组字符串
        """
        raw_bytes = bytes(packet)
        hex_values = ", ".join(f"0x{b:02x}" for b in raw_bytes)
        return f"unsigned char {array_name}[] = {{\n    {hex_values}\n}};"

    @staticmethod
    def parsed_packet_to_hex(parsed: ParsedPacket, separator: str = " ") -> str:
        """
        已解析数据包转十六进制字符串
        :param parsed: 解析后的数据包
        :param separator: 字节分隔符
        :return: 十六进制字符串
        """
        return separator.join(f"{b:02x}" for b in parsed.raw_data)

    @classmethod
    def export_packets(
        cls,
        packets: list[Packet],
        output_file: str,
        format: str = "hex_dump",
        separator: str = " "
    ) -> None:
        """
        批量导出数据包到文件
        :param packets: 数据包列表
        :param output_file: 输出文件路径
        :param format: 输出格式 (hex, hex_dump, c_array)
        :param separator: 字节分隔符
        """
        output_path = Path(output_file)
        lines = []

        for i, packet in enumerate(packets):
            lines.append(f"=== Packet {i + 1} ({len(packet)} bytes) ===")

            if format == "hex":
                lines.append(cls.packet_to_hex(packet, separator))
            elif format == "hex_dump":
                lines.append(cls.packet_to_hex_dump(packet))
            elif format == "c_array":
                lines.append(cls.packet_to_c_array(packet, f"packet_{i + 1}"))
            else:
                lines.append(cls.packet_to_hex(packet, separator))

            lines.append("")

        output_path.write_text("\n".join(lines))

    @classmethod
    def export_single_packet(
        cls,
        packet: Packet,
        output_file: str,
        format: str = "hex_dump"
    ) -> None:
        """
        导出单个数据包到文件
        :param packet: 数据包
        :param output_file: 输出文件路径
        :param format: 输出格式
        """
        output_path = Path(output_file)

        if format == "hex":
            content = cls.packet_to_hex(packet)
        elif format == "c_array":
            content = cls.packet_to_c_array(packet)
        else:
            content = cls.packet_to_hex_dump(packet)

        output_path.write_text(content)

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """
        十六进制字符串转字节
        :param hex_str: 十六进制字符串
        :return: 字节数据
        """
        # 移除常见分隔符
        clean_str = hex_str.replace(" ", "").replace(":", "").replace("-", "")
        return bytes.fromhex(clean_str)
