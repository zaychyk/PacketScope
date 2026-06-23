"""
Traffic Statistics Module
协议流量占比统计
"""

from typing import Optional
from collections import defaultdict
from scapy.packet import Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP

from ..parser.base import ParsedPacket, ProtocolType


class TrafficStats:
    """
    流量统计类

    统计:
    - 各协议数据包数量
    - 各协议流量占比
    - 字节数统计
    - 时间序列统计
    """

    def __init__(self):
        """初始化统计器"""
        self.reset()

    def reset(self) -> None:
        """重置统计信息"""
        self.packet_counts: dict[str, int] = defaultdict(int)
        self.byte_counts: dict[str, int] = defaultdict(int)
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_hierarchy: dict = defaultdict(lambda: defaultdict(int))

    def add_packet(self, packet: Packet) -> None:
        """
        添加数据包进行统计
        :param packet: Scapy 数据包
        """
        self.total_packets += 1
        packet_len = len(packet)
        self.total_bytes += packet_len

        # 统计各层协议
        protocols = self._extract_protocols(packet)

        for proto in protocols:
            self.packet_counts[proto] += 1
            self.byte_counts[proto] += packet_len

        # 构建协议层次关系
        if len(protocols) >= 2:
            for i in range(len(protocols) - 1):
                self.protocol_hierarchy[protocols[i]][protocols[i + 1]] += 1

    def add_parsed_packet(self, parsed: ParsedPacket) -> None:
        """
        添加已解析的数据包
        :param parsed: 解析后的数据包
        """
        self.total_packets += 1
        self.total_bytes += parsed.length

        protocols = [layer.protocol.value for layer in parsed.layers]

        for proto in protocols:
            self.packet_counts[proto] += 1
            self.byte_counts[proto] += parsed.length

    def _extract_protocols(self, packet: Packet) -> list[str]:
        """从 Scapy 数据包提取协议列表"""
        protocols = []

        if packet.haslayer(Ether):
            protocols.append("Ethernet")
        if packet.haslayer(ARP):
            protocols.append("ARP")
            return protocols  # ARP 帧没有 IP/TCP/UDP 层
        if packet.haslayer(IP):
            protocols.append("IPv4")
        if packet.haslayer(TCP):
            protocols.append("TCP")
        if packet.haslayer(UDP):
            protocols.append("UDP")
        if packet.haslayer(ICMP):
            protocols.append("ICMP")

        # 应用层协议推断
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport == 80 or tcp.sport == 80:
                protocols.append("HTTP")
            elif tcp.dport == 443 or tcp.sport == 443:
                protocols.append("HTTPS")
            elif tcp.dport == 22 or tcp.sport == 22:
                protocols.append("SSH")
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            if udp.dport == 53 or udp.sport == 53:
                protocols.append("DNS")

        # 检查 IPv6（通过 EtherType）
        if not protocols or protocols == ["Ethernet"]:
            if packet.haslayer(Ether):
                eth_type = packet[Ether].type
                if eth_type == 0x86DD:
                    protocols.append("IPv6")

        return protocols if protocols else ["Unknown"]

    def get_protocol_stats(self) -> dict:
        """
        获取协议统计信息
        :return: 统计结果字典
        """
        stats = {}

        for proto in self.packet_counts:
            count = self.packet_counts[proto]
            bytes_count = self.byte_counts[proto]
            stats[proto] = {
                "count": count,
                "bytes": bytes_count,
                "packet_percent": round(count / max(1, self.total_packets) * 100, 2),
                "byte_percent": round(bytes_count / max(1, self.total_bytes) * 100, 2),
            }

        return stats

    def get_summary(self) -> dict:
        """获取统计摘要"""
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "unique_protocols": len(self.packet_counts),
            "protocol_stats": self.get_protocol_stats(),
        }

    def get_top_protocols(self, n: int = 10) -> list[tuple[str, int]]:
        """
        获取前 N 个协议
        :param n: 数量
        :return: [(协议名, 包数), ...]
        """
        sorted_protos = sorted(
            self.packet_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_protos[:n]

    def print_stats(self) -> None:
        """打印统计信息"""
        print("=" * 60)
        print("Traffic Statistics")
        print("=" * 60)
        print(f"Total Packets: {self.total_packets}")
        print(f"Total Bytes: {self.total_bytes}")
        print("-" * 60)
        print(f"{'Protocol':<20} {'Count':<10} {'Bytes':<15} {'Packet%':<10} {'Byte%':<10}")
        print("-" * 60)

        for proto, data in sorted(
            self.get_protocol_stats().items(),
            key=lambda x: x[1]["count"],
            reverse=True
        ):
            print(f"{proto:<20} {data['count']:<10} {data['bytes']:<15} "
                  f"{data['packet_percent']:<10.2f} {data['byte_percent']:<10.2f}")

        print("=" * 60)
