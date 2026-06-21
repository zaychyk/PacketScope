"""
Hex View Panel Module - PyQt6 version
"""

from PyQt6.QtWidgets import (
    QWidget, QPlainTextEdit, QGroupBox, QVBoxLayout
)
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QPalette
from scapy.packet import Packet
from .fonts import get_font, get_mono_font


class HexHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for hex dump view"""

    def __init__(self, parent):
        super().__init__(parent)

        self.offset_format = QTextCharFormat()
        self.offset_format.setForeground(QColor("#858585"))

        self.hex_format = QTextCharFormat()
        self.hex_format.setForeground(QColor("#9cdcfe"))

        self.ascii_format = QTextCharFormat()
        self.ascii_format.setForeground(QColor("#ce9178"))

    def highlightBlock(self, text: str) -> None:
        if not text:
            return

        # Offset: first 8 chars
        self.setFormat(0, min(8, len(text)), self.offset_format)

        # Find the pipe separator
        pipe_pos = text.find("|")
        if pipe_pos > 10:
            # Hex section (from position 10 to pipe)
            self.setFormat(10, pipe_pos - 10 - 2, self.hex_format)
            # ASCII section (between pipes)
            ascii_start = pipe_pos + 1
            ascii_end = text.find("|", ascii_start)
            if ascii_end > ascii_start:
                self.setFormat(ascii_start, ascii_end - ascii_start, self.ascii_format)


class HexViewPanel(QWidget):
    """Raw hex data panel"""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.current_packet: Packet = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        group = QGroupBox("Raw Data (Hex)")
        group.setFont(get_font("large", bold=True))
        group_layout = QVBoxLayout(group)

        self.text_edit = QPlainTextEdit()
        self.text_edit.setFont(get_mono_font("large"))
        self.text_edit.setReadOnly(True)
        self.text_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        # Dark theme
        palette = self.text_edit.palette()
        palette.setColor(QPalette.ColorRole.Base, QColor("#1e1e1e"))
        palette.setColor(QPalette.ColorRole.Text, QColor("#d4d4d4"))
        self.text_edit.setPalette(palette)

        # Apply syntax highlighter
        self.highlighter = HexHighlighter(self.text_edit.document())

        group_layout.addWidget(self.text_edit)
        layout.addWidget(group)

    def show_packet(self, packet: Packet) -> None:
        self.current_packet = packet
        self._display_hex(bytes(packet))

    def _display_hex(self, data: bytes, width: int = 16) -> None:
        lines = []

        for offset in range(0, len(data), width):
            chunk = data[offset:offset + width]
            offset_str = f"{offset:08x}  "

            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(width * 3 - 1)

            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset_str}{hex_part}  |{ascii_part}|")

        self.text_edit.setPlainText("\n".join(lines))

    def clear(self) -> None:
        self.text_edit.clear()
        self.current_packet = None

    def get_hex_string(self) -> str:
        if self.current_packet:
            return " ".join(f"{b:02x}" for b in bytes(self.current_packet))
        return ""
