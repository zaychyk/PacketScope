"""
Toolbar Module - PyQt6 version
"""

from PyQt6.QtWidgets import QWidget
from PyQt6.QtCore import pyqtSignal
from .fonts import get_font


class Toolbar(QWidget):
    """Toolbar with action buttons"""

    action_triggered = pyqtSignal(str)

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        from PyQt6.QtWidgets import QHBoxLayout, QPushButton, QFrame

        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(8)

        font = get_font("normal")

        buttons = [
            ("Open File", "open"),
            ("Start Capture", "start"),
            ("Stop Capture", "stop"),
            ("Export", "export"),
            ("Clear", "clear"),
            ("Statistics", "stats"),
        ]

        self.btn_actions = {}

        for i, (text, action) in enumerate(buttons):
            if i == 1 or i == 3 or i == 5:
                separator = QFrame()
                separator.setFrameShape(QFrame.Shape.VLine)
                separator.setFixedWidth(2)
                layout.addWidget(separator)

            btn = QPushButton(text)
            btn.setFont(font)
            btn.clicked.connect(lambda checked, a=action: self.action_triggered.emit(a))
            layout.addWidget(btn)
            self.btn_actions[action] = btn

        # Initially disable Stop Capture
        self.btn_actions["stop"].setEnabled(False)
        self.btn_actions["start"].setEnabled(True)

    def set_capturing(self, is_capturing: bool) -> None:
        self.btn_actions["start"].setEnabled(not is_capturing)
        self.btn_actions["stop"].setEnabled(is_capturing)
