"""
Packet List Panel Module - PyQt6 version
"""

import time
from PyQt6.QtWidgets import (
    QWidget, QTableWidget, QTableWidgetItem, QGroupBox, QVBoxLayout, QHeaderView
)
from PyQt6.QtCore import pyqtSignal, Qt
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from .fonts import get_font


class PacketListPanel(QWidget):
    """Packet list panel showing packet summary"""

    COLUMNS = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    packet_selected = pyqtSignal(int)

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.packets: list[Packet] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        group = QGroupBox("Packet List")
        group.setFont(get_font("large", bold=True))
        group_layout = QVBoxLayout(group)

        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setVerticalHeaderLabels([])  # 隐藏左侧行号
        self.table.verticalHeader().setVisible(False)
        self.table.setFont(get_font("large"))
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.cellClicked.connect(self._on_cell_clicked)

        # Column widths - Protocol/Length 加宽，Info 减小
        col_widths = [60, 100, 170, 170, 100, 80, 200]
        for i, w in enumerate(col_widths):
            self.table.setColumnWidth(i, w)

        # Header - 前6列可拖动，最后一列(Info)自动填充剩余空间
        header = self.table.horizontalHeader()
        for i in range(len(col_widths) - 1):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(len(col_widths) - 1, QHeaderView.ResizeMode.Stretch)
        header.setFont(get_font("large", bold=True))

        group_layout.addWidget(self.table)
        layout.addWidget(group)

    def _on_cell_clicked(self, row: int, column: int) -> None:
        self.packet_selected.emit(row)

    def _extract_info(self, packet: Packet) -> dict:
        info = {"source": "", "destination": "", "protocol": "", "info": ""}

        if packet.haslayer(IP):
            ip = packet[IP]
            info["source"] = ip.src
            info["destination"] = ip.dst

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                info["source"] = f"{ip.src}:{tcp.sport}"
                info["destination"] = f"{ip.dst}:{tcp.dport}"
                info["protocol"] = "TCP"
                flags = []
                if tcp.flags.S: flags.append("SYN")
                if tcp.flags.A: flags.append("ACK")
                if tcp.flags.F: flags.append("FIN")
                if tcp.flags.R: flags.append("RST")
                info["info"] = f"{', '.join(flags)} Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                info["source"] = f"{ip.src}:{udp.sport}"
                info["destination"] = f"{ip.dst}:{udp.dport}"
                info["protocol"] = "UDP"
                info["info"] = f"Len={udp.len}"

            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                info["protocol"] = "ICMP"
                type_names = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
                info["info"] = type_names.get(icmp.type, f"Type={icmp.type}")

        elif packet.haslayer(Ether):
            ether = packet[Ether]
            info["source"] = ether.src
            info["destination"] = ether.dst
            info["protocol"] = "Ethernet"
            info["info"] = f"Type=0x{ether.type:04x}"
        else:
            info["protocol"] = "Unknown"

        return info

    def add_packet(self, packet: Packet, index: int) -> None:
        info = self._extract_info(packet)
        timestamp = time.strftime("%H:%M:%S", time.localtime(float(packet.time)))

        row = self.table.rowCount()
        self.table.insertRow(row)

        values = [
            str(index + 1), timestamp, info["source"], info["destination"],
            info["protocol"], str(len(packet)), info["info"]
        ]

        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, col, item)

    def add_packets(self, packets: list[Packet]) -> None:
        start_index = len(self.packets)
        self.packets.extend(packets)
        self.table.blockSignals(True)
        for i, packet in enumerate(packets):
            self.add_packet(packet, start_index + i)
        self.table.blockSignals(False)

    def clear(self) -> None:
        self.packets.clear()
        self.table.setRowCount(0)

    def get_selected_index(self) -> int:
        row = self.table.currentRow()
        return row if row >= 0 else -1
