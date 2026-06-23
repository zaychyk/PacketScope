"""
Filter Bar Module - PyQt6 version
"""

from PyQt6.QtWidgets import (
    QWidget, QLabel, QComboBox, QLineEdit, QPushButton, QHBoxLayout
)
from PyQt6.QtCore import pyqtSignal
from .fonts import get_font


class FilterBar(QWidget):
    """BPF filter input bar"""

    filter_applied = pyqtSignal(str)

    PRESETS = {
        "(No Filter)": "",
        "TCP": "tcp",
        "UDP": "udp",
        "ICMP": "icmp",
        "HTTP": "tcp port 80",
        "HTTPS": "tcp port 443",
        "DNS": "udp port 53",
        "SSH": "tcp port 22",
    }

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.current_filter = ""
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        font = get_font("large")

        # Filter label
        filter_label = QLabel("Filter:")
        filter_label.setFont(font)
        layout.addWidget(filter_label)

        # Preset combo box
        self.preset_combo = QComboBox()
        self.preset_combo.setFont(font)
        self.preset_combo.addItems(list(self.PRESETS.keys()))
        self.preset_combo.setCurrentText("(No Filter)")
        self.preset_combo.setMinimumWidth(160)
        self.preset_combo.currentTextChanged.connect(self._on_preset_change)
        layout.addWidget(self.preset_combo)

        # Filter expression entry
        self.filter_entry = QLineEdit()
        self.filter_entry.setFont(font)
        self.filter_entry.setPlaceholderText("Enter BPF filter expression...")
        self.filter_entry.returnPressed.connect(self._on_apply)
        layout.addWidget(self.filter_entry, stretch=1)

        # Apply button
        self.btn_apply = QPushButton("Apply")
        self.btn_apply.setFont(font)
        self.btn_apply.clicked.connect(self._on_apply)
        layout.addWidget(self.btn_apply)

        # Clear button
        self.btn_clear = QPushButton("Clear")
        self.btn_clear.setFont(font)
        self.btn_clear.clicked.connect(self._on_clear)
        layout.addWidget(self.btn_clear)

    def _on_preset_change(self, preset_name: str) -> None:
        filter_expr = self.PRESETS.get(preset_name, "")
        self.filter_entry.setText(filter_expr)
        self._on_apply()

    def _on_apply(self) -> None:
        filter_expr = self.filter_entry.text().strip()
        self.current_filter = filter_expr
        self.filter_applied.emit(filter_expr)

    def _on_clear(self) -> None:
        self.filter_entry.clear()
        self.preset_combo.setCurrentText("(No Filter)")
        self.current_filter = ""
        self.filter_applied.emit("")

    def get_filter(self) -> str:
        return self.current_filter

    def set_filter(self, filter_expr: str) -> None:
        self.filter_entry.setText(filter_expr)
        self.current_filter = filter_expr
