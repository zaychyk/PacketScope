"""
Detail View Panel Module - PyQt6 version
"""

from PyQt6.QtWidgets import (
    QWidget, QTreeWidget, QTreeWidgetItem, QGroupBox, QVBoxLayout
)
from scapy.packet import Packet
from ..parser.ethernet import EthernetParser
from ..parser.ipv4 import IPv4Parser
from ..parser.tcp import TCPParser
from ..parser.udp import UDPParser
from ..parser.icmp import ICMPParser
from .fonts import get_font


class DetailViewPanel(QWidget):
    """Protocol detail panel with tree view"""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        group = QGroupBox("Protocol Details")
        group.setFont(get_font("large", bold=True))
        group_layout = QVBoxLayout(group)

        self.tree = QTreeWidget()
        self.tree.setFont(get_font("large"))
        self.tree.setHeaderHidden(True)
        self.tree.setAlternatingRowColors(True)

        group_layout.addWidget(self.tree)
        layout.addWidget(group)

    def show_packet(self, packet: Packet) -> None:
        self.tree.clear()
        self._parse_and_display(packet)

    def _parse_and_display(self, packet: Packet) -> None:
        raw_data = bytes(packet)
        offset = 0

        if packet.haslayer("Ethernet"):
            eth_layer = EthernetParser().parse(raw_data[offset:])
            if eth_layer:
                self._add_layer_to_tree(eth_layer, "Ethernet II")
                offset = 14

        if packet.haslayer("IP"):
            ip_layer = IPv4Parser().parse(raw_data[offset:])
            if ip_layer:
                self._add_layer_to_tree(ip_layer, "Internet Protocol Version 4")
                ip_header_len = (raw_data[offset] & 0x0F) * 4
                offset += ip_header_len

        if packet.haslayer("TCP"):
            tcp_layer = TCPParser().parse(raw_data[offset:])
            if tcp_layer:
                self._add_layer_to_tree(tcp_layer, "Transmission Control Protocol")
                tcp_header_len = ((raw_data[offset + 12] >> 4) & 0x0F) * 4
                offset += tcp_header_len

        if packet.haslayer("UDP"):
            udp_layer = UDPParser().parse(raw_data[offset:])
            if udp_layer:
                self._add_layer_to_tree(udp_layer, "User Datagram Protocol")

        if packet.haslayer("ICMP"):
            icmp_layer = ICMPParser().parse(raw_data[offset:])
            if icmp_layer:
                self._add_layer_to_tree(icmp_layer, "Internet Control Message Protocol")

    def _add_layer_to_tree(self, layer, layer_name: str) -> None:
        layer_item = QTreeWidgetItem(self.tree)
        layer_item.setText(0, layer_name)
        layer_item.setExpanded(True)

        for field in layer.fields:
            field_item = QTreeWidgetItem(layer_item)
            field_item.setText(0, f"{field.name}: {field.value}")

    def clear(self) -> None:
        self.tree.clear()
