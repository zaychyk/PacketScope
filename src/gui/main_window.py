"""
Main Window Module - PyQt6 version
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QSplitter,
    QStatusBar, QLabel, QMessageBox, QDialog,
    QListWidget, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from typing import Optional

from scapy.packet import Packet

from .toolbar import Toolbar
from .filter_bar import FilterBar
from .packet_list import PacketListPanel
from .detail_view import DetailViewPanel
from .hex_view import HexViewPanel
from .file_dialog import open_file, save_file
from .fonts import get_font

from ..capture import RealTimeCapture, PcapFileReader
from ..filter import BPFFilter
from ..stats import TrafficStats
from ..export import HexExporter


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self, title: str = "Network Protocol Analyzer"):
        super().__init__()
        self.setWindowTitle(title)
        self.resize(1600, 1000)
        self.setMinimumSize(1200, 800)

        self.packets: list[Packet] = []
        self.filtered_packets: list[Packet] = []
        self.selected_packet_index: Optional[int] = None
        self.is_capturing = False

        self.capture: Optional[RealTimeCapture] = None
        self.current_filter = BPFFilter("")
        self.stats = TrafficStats()
        self.current_file_path: Optional[str] = None

        self.capture_timer: Optional[QTimer] = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)

        # Toolbar
        self.toolbar = Toolbar(central)
        self.toolbar.action_triggered.connect(self._on_toolbar_action)
        main_layout.addWidget(self.toolbar)

        # Filter bar
        self.filter_bar = FilterBar(central)
        self.filter_bar.filter_applied.connect(self._on_filter_apply)
        main_layout.addWidget(self.filter_bar)

        # Three-pane splitter
        splitter = QSplitter(Qt.Orientation.Vertical)

        self.packet_list = PacketListPanel(splitter)
        self.packet_list.packet_selected.connect(self._on_packet_select)
        splitter.addWidget(self.packet_list)

        self.detail_view = DetailViewPanel(splitter)
        splitter.addWidget(self.detail_view)

        self.hex_view = HexViewPanel(splitter)
        splitter.addWidget(self.hex_view)

        splitter.setSizes([300, 200, 350])

        # 加大分割条，方便拖动
        splitter.setHandleWidth(8)

        main_layout.addWidget(splitter)

        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setFont(get_font("normal"))
        self.packet_count_label = QLabel("Packets: 0")
        self.packet_count_label.setFont(get_font("normal"))
        self.packet_count_label.setAlignment(Qt.AlignmentFlag.AlignRight)

        status_bar = QStatusBar()
        self.setStatusBar(status_bar)
        status_bar.addWidget(self.status_label, 1)
        status_bar.addPermanentWidget(self.packet_count_label)

    def _on_toolbar_action(self, action: str) -> None:
        if action == "open": self._open_file()
        elif action == "start": self._start_capture()
        elif action == "stop": self._stop_capture()
        elif action == "export": self._export_packets()
        elif action == "clear": self._clear_packets()
        elif action == "stats": self._show_stats()

    def _on_filter_apply(self, filter_expr: str) -> None:
        self.current_filter = BPFFilter(filter_expr)

        if filter_expr and not self.current_filter.is_valid():
            QMessageBox.critical(self, "Filter Error", f"Invalid BPF filter: {self.current_filter.get_error()}")
            self.status_label.setText("Filter error")
            return

        self._apply_filter()
        self.status_label.setText(f"Filter: {filter_expr}" if filter_expr else "Ready")

    def _apply_filter(self) -> None:
        if not self.current_filter.filter_expr:
            self.filtered_packets = self.packets.copy()
        else:
            self.filtered_packets = self.current_filter.filter_packets(self.packets)

        self.packet_list.clear()
        self.packet_list.add_packets(self.filtered_packets)
        self._update_packet_count()

    def _on_packet_select(self, index: int) -> None:
        if 0 <= index < len(self.filtered_packets):
            self.selected_packet_index = index
            packet = self.filtered_packets[index]
            self.detail_view.show_packet(packet)
            self.hex_view.show_packet(packet)

    def _open_file(self) -> None:
        if self.is_capturing:
            self._stop_capture()

        file_path = open_file(
            self,
            title="Open Capture File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
        )

        if not file_path:
            return

        try:
            self.status_label.setText(f"Loading {file_path}...")

            reader = PcapFileReader(file_path)
            packets = reader.load()
            file_info = reader.get_file_info()

            self._clear_packets()
            self.current_file_path = file_path
            self.packets = packets
            self.filtered_packets = packets.copy()

            self.packet_list.add_packets(packets)

            self.stats.reset()
            for pkt in packets:
                self.stats.add_packet(pkt)

            filename = file_path.split('/')[-1]
            self.setWindowTitle(f"Network Protocol Analyzer - {filename}")
            self.status_label.setText(
                f"Loaded: {filename} ({file_info['packet_count']} packets, {file_info['duration']:.2f}s)"
            )
            self._update_packet_count()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load file:\n{str(e)}")
            self.status_label.setText("Load failed")

    def _start_capture(self) -> None:
        if self.is_capturing:
            return

        interfaces = RealTimeCapture.list_interfaces()

        if not interfaces:
            QMessageBox.critical(self, "Error", "No network interfaces found.\nPlease run with administrator/root privileges.")
            return

        interface = interfaces[0] if len(interfaces) == 1 else self._select_interface(interfaces)
        if interface is None:
            return

        try:
            self._clear_packets()
            self.current_file_path = None

            self.capture = RealTimeCapture(interface=interface)
            bpf_filter = self.filter_bar.get_filter()

            if not self.capture.start(bpf_filter=bpf_filter):
                QMessageBox.critical(self, "Error", "Failed to start capture.\nPlease check permissions.")
                return

            self.is_capturing = True
            self.toolbar.set_capturing(True)
            self.setWindowTitle("Network Protocol Analyzer - Capturing...")
            self.status_label.setText(f"Capturing on {interface}... (Filter: {bpf_filter or 'None'})")

            # Start capture polling timer
            self.capture_timer = QTimer()
            self.capture_timer.timeout.connect(self._update_capture_display)
            self.capture_timer.start(500)

        except PermissionError:
            QMessageBox.critical(self, "Permission Error", "Permission denied.\nPlease run with administrator/root privileges.")
            self.status_label.setText("Permission denied")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start capture:\n{str(e)}")
            self.status_label.setText("Capture failed")

    def _update_capture_display(self) -> None:
        if not self.is_capturing or self.capture is None:
            return

        new_packets = self.capture.get_packets()
        if len(new_packets) > len(self.packets):
            added = new_packets[len(self.packets):]
            self.packets = new_packets
            self.filtered_packets = self.current_filter.filter_packets(self.packets)

            self.packet_list.clear()
            self.packet_list.add_packets(self.filtered_packets)
            self._update_packet_count()

            for pkt in added:
                self.stats.add_packet(pkt)

            self.status_label.setText(f"Capturing... ({len(self.packets)} packets)")

    def _stop_capture(self) -> None:
        if not self.is_capturing or self.capture is None:
            return

        # Stop the timer first
        if self.capture_timer:
            self.capture_timer.stop()
            self.capture_timer = None

        try:
            final_packets = self.capture.stop()
            self.is_capturing = False
            self.toolbar.set_capturing(False)

            self.packets = final_packets
            self.filtered_packets = self.current_filter.filter_packets(self.packets)

            self.packet_list.clear()
            self.packet_list.add_packets(self.filtered_packets)
            self._update_packet_count()

            self.setWindowTitle(f"Network Protocol Analyzer - {len(self.packets)} packets")
            self.status_label.setText(f"Capture stopped. {len(self.packets)} packets captured.")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error stopping capture:\n{str(e)}")

    def _export_packets(self) -> None:
        packets_to_export = self.filtered_packets or self.packets

        if not packets_to_export:
            QMessageBox.warning(self, "Warning", "No packets to export")
            return

        file_path = save_file(
            self,
            title="Export Packets",
            filetypes=[("Text files", "*.txt"), ("Hex files", "*.hex"), ("PCAP files", "*.pcap"), ("All files", "*.*")],
            defaultextension=".txt",
        )

        if not file_path:
            return

        try:
            self.status_label.setText(f"Exporting to {file_path}...")

            if file_path.endswith('.pcap'):
                PcapFileReader.save_packets(packets_to_export, file_path)
            else:
                export_format = "hex" if file_path.endswith('.hex') else "hex_dump"
                HexExporter.export_packets(packets_to_export, file_path, format=export_format)

            self.status_label.setText(f"Exported {len(packets_to_export)} packets to {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export:\n{str(e)}")
            self.status_label.setText("Export failed")

    def _clear_packets(self) -> None:
        self.packets.clear()
        self.filtered_packets.clear()
        self.packet_list.clear()
        self.detail_view.clear()
        self.hex_view.clear()
        self.stats.reset()
        self.selected_packet_index = None
        self.current_file_path = None
        self.setWindowTitle("Network Protocol Analyzer")
        self.status_label.setText("Cleared")
        self._update_packet_count()

    def _show_stats(self) -> None:
        if not self.packets:
            QMessageBox.information(self, "Statistics", "No packets to analyze")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Traffic Statistics")
        dialog.resize(900, 650)

        from PyQt6.QtWidgets import QVBoxLayout as QVLayout, QHBoxLayout as QHLayout, QGroupBox
        layout = QVLayout(dialog)

        from PyQt6.QtWidgets import QLabel as QLabel2
        title_label = QLabel2("Traffic Statistics")
        title_label.setFont(get_font("title", bold=True))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        summary = self.stats.get_summary()

        # Overview
        overview = QGroupBox("Overview")
        overview.setFont(get_font("large", bold=True))
        ov_layout = QVLayout(overview)
        ov_layout.addWidget(QLabel2(f"Total Packets: {summary['total_packets']}"))
        ov_layout.addWidget(QLabel2(f"Total Bytes: {summary['total_bytes']:,}"))
        ov_layout.addWidget(QLabel2(f"Unique Protocols: {summary['unique_protocols']}"))
        layout.addWidget(overview)

        # Protocol statistics
        stats_group = QGroupBox("Protocol Statistics")
        stats_group.setFont(get_font("large", bold=True))
        stats_layout = QVLayout(stats_group)

        columns = ("Protocol", "Count", "Bytes", "Packet %", "Byte %")
        table = QTableWidget()
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setFont(get_font("large"))
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setStretchLastSection(True)

        protocol_stats = summary['protocol_stats']
        for proto, data in sorted(protocol_stats.items(), key=lambda x: x[1]['count'], reverse=True):
            row = table.rowCount()
            table.insertRow(row)
            values = [
                proto, str(data['count']), f"{data['bytes']:,}",
                f"{data['packet_percent']:.2f}%", f"{data['byte_percent']:.2f}%"
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row, col, item)

        stats_layout.addWidget(table)
        layout.addWidget(stats_group)

        # Close button
        from PyQt6.QtWidgets import QPushButton as QPushButton2
        close_btn = QPushButton2("Close")
        close_btn.setFont(get_font("large"))
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)

        dialog.exec()

    def _select_interface(self, interfaces: list) -> Optional[str]:
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Interface")
        dialog.resize(500, 400)

        from PyQt6.QtWidgets import QVBoxLayout as QVLayout2, QLabel as QLabel3, QPushButton as QPushButton3
        layout = QVLayout2(dialog)

        QLabel3("Select network interface:").setFont(get_font("large"))
        label = QLabel3("Select network interface:")
        label.setFont(get_font("large"))
        layout.addWidget(label)

        listbox = QListWidget()
        listbox.setFont(get_font("large"))
        listbox.addItems(interfaces)
        if interfaces:
            listbox.setCurrentRow(0)
        layout.addWidget(listbox)

        selected = [None]

        def on_ok():
            row = listbox.currentRow()
            if row >= 0:
                selected[0] = interfaces[row]
            dialog.accept()

        btn_layout = __import__("PyQt6.QtWidgets", fromlist=["QHBoxLayout"]).QHBoxLayout()
        btn_ok = QPushButton3("OK")
        btn_ok.setFont(get_font("large"))
        btn_ok.clicked.connect(on_ok)
        btn_cancel = QPushButton3("Cancel")
        btn_cancel.setFont(get_font("large"))
        btn_cancel.clicked.connect(dialog.reject)
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            return selected[0]
        return None

    def _update_packet_count(self) -> None:
        total = len(self.packets)
        displayed = len(self.filtered_packets)

        if total != displayed:
            self.packet_count_label.setText(f"Displayed: {displayed} / Total: {total}")
        else:
            self.packet_count_label.setText(f"Packets: {total}")

    def add_packets(self, packets: list[Packet]) -> None:
        self.packets.extend(packets)
        self.filtered_packets = self.current_filter.filter_packets(self.packets)
        self.packet_list.clear()
        self.packet_list.add_packets(self.filtered_packets)
        self._update_packet_count()

    def run(self) -> None:
        from PyQt6.QtWidgets import QApplication
        # This should be called after QApplication is created
        self.show()

    def closeEvent(self, event) -> None:
        if self.is_capturing and self.capture:
            self.capture.stop()
        event.accept()
