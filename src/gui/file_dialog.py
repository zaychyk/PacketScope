"""
File Dialog Module - PyQt6 version
Uses native QFileDialog (Wayland-compatible)
"""

from PyQt6.QtWidgets import QFileDialog
from typing import Optional
import os


def open_file(
    parent,
    title: str = "Open Capture File",
    filetypes: Optional[list[tuple[str, pattern]]] = None,
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
    defaultextension: str = ".pcap",
    initialdir: Optional[str] = None,
) -> Optional[str]:
    """Show save file dialog, return selected path or None

    Note: QFileDialog doesn't auto-add extensions like tkinter,
    so we manually add the extension if missing.
    """
    filetypes = filetypes or [("All files", "*.*")]
    filters = ";;".join(f"{label} ({pattern})" for label, pattern in filetypes)

    # Set default filter based on defaultextension
    default_filter = ""
    for label, pattern in filetypes:
        if defaultextension in pattern:
            default_filter = f"{label} ({pattern})"
            break

    path, selected_filter = QFileDialog.getSaveFileName(
        parent, title, initialdir or "", filters, default_filter
    )

    if not path:
        return None

    # If path has no extension, add one based on selected filter
    _, ext = os.path.splitext(path)
    if not ext:
        # Extract extension from selected filter pattern
        if selected_filter:
            # Parse pattern like "*.pcap" or "*.txt"
            import re
            match = re.search(r'\*(\.\w+)', selected_filter)
            if match:
                path = path + match.group(1)
            else:
                path = path + defaultextension
        else:
            path = path + defaultextension

    return path
