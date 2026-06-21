"""
File Dialog Module - PyQt6 version
Uses native QFileDialog (Wayland-compatible)
"""

from PyQt6.QtWidgets import QFileDialog
from typing import Optional


def open_file(
    parent,
    title: str = "Open Capture File",
    filetypes: Optional[list[tuple[str, str]]] = None,
    initialdir: Optional[str] = None,
) -> Optional[str]:
    """Show open file dialog, return selected path or None"""
    filters = ";;".join(f"{label} ({pattern})" for label, pattern in (filetypes or [("All files", "*.*")]))
    path, _ = QFileDialog.getOpenFileName(
        parent, title, initialdir or "", filters
    )
    return path if path else None


def save_file(
    parent,
    title: str = "Export Packets",
    filetypes: Optional[list[tuple[str, str]]] = None,
    defaultextension: str = ".txt",
    initialdir: Optional[str] = None,
) -> Optional[str]:
    """Show save file dialog, return selected path or None"""
    filters = ";;".join(f"{label} ({pattern})" for label, pattern in (filetypes or [("All files", "*.*")]))
    path, _ = QFileDialog.getSaveFileName(
        parent, title, initialdir or "", filters, defaultextension
    )
    return path if path else None
