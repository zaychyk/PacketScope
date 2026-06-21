"""
PCAP File Reader Module
读取本地 pcap/pcapng 抓包文件
"""

from typing import Optional, Iterator
from pathlib import Path

from scapy.all import rdpcap, wrpcap
from scapy.packet import Packet
from scapy.utils import PcapReader


class PcapFileReader:
    """
    pcap 文件读取器

    支持:
    - pcap 格式
    - pcapng 格式（Scapy 2.5+）
    - 大文件流式读取
    """

    def __init__(self, file_path: str):
        """
        初始化文件读取器
        :param file_path: pcap 文件路径
        """
        self.file_path = Path(file_path)
        self.packets: list[Packet] = []
        self.is_loaded = False

        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

    def load(self) -> list[Packet]:
        """
        加载整个文件到内存
        :return: 数据包列表
        """
        try:
            self.packets = rdpcap(str(self.file_path))
            self.is_loaded = True
            return self.packets
        except Exception as e:
            raise IOError(f"Failed to read pcap file: {e}")

    def read_stream(self) -> Iterator[Packet]:
        """
        流式读取文件（适合大文件）
        :return: 数据包迭代器
        """
        try:
            with PcapReader(str(self.file_path)) as reader:
                for packet in reader:
                    yield packet
        except Exception as e:
            raise IOError(f"Failed to stream pcap file: {e}")

    def get_packets(self, start: int = 0, count: Optional[int] = None) -> list[Packet]:
        """
        获取指定范围的数据包
        :param start: 起始索引
        :param count: 数据包数量（None 表示到末尾）
        :return: 数据包列表
        """
        if not self.is_loaded:
            self.load()

        if count is None:
            return self.packets[start:]
        return self.packets[start:start + count]

    def get_packet_count(self) -> int:
        """获取数据包总数"""
        if not self.is_loaded:
            self.load()
        return len(self.packets)

    def get_file_info(self) -> dict:
        """获取文件信息"""
        if not self.is_loaded:
            self.load()

        if not self.packets:
            return {
                "file_path": str(self.file_path),
                "file_size": self.file_path.stat().st_size,
                "packet_count": 0,
                "duration": 0,
                "first_packet_time": None,
                "last_packet_time": None,
            }

        first_time = float(self.packets[0].time)
        last_time = float(self.packets[-1].time)

        return {
            "file_path": str(self.file_path),
            "file_size": self.file_path.stat().st_size,
            "packet_count": len(self.packets),
            "duration": last_time - first_time,
            "first_packet_time": first_time,
            "last_packet_time": last_time,
        }

    @staticmethod
    def save_packets(packets: list[Packet], file_path: str) -> None:
        """
        保存数据包到 pcap 文件
        :param packets: 数据包列表
        :param file_path: 输出文件路径
        """
        try:
            wrpcap(file_path, packets)
        except Exception as e:
            raise IOError(f"Failed to save pcap file: {e}")

    def filter_packets(self, bpf_filter: str) -> list[Packet]:
        """
        使用 BPF 过滤器过滤数据包
        :param bpf_filter: BPF 过滤表达式
        :return: 匹配的数据包列表
        """
        if not self.is_loaded:
            self.load()

        return [pkt for pkt in self.packets if pkt.filter(bpf_filter)]
