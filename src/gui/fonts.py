"""
Font Configuration Module
PyQt6 version - returns QFont objects
"""

from PyQt6.QtGui import QFont

# 全局字体设置
FONT_FAMILY = "DejaVu Sans"
FONT_FAMILY_MONO = "DejaVu Sans Mono"

# 字体大小
FONT_SIZE_SMALL = 14
FONT_SIZE_NORMAL = 16
FONT_SIZE_LARGE = 18
FONT_SIZE_TITLE = 20


def get_font(size: str = "normal", bold: bool = False) -> QFont:
    """
    获取字体配置
    :param size: small, normal, large, title
    :param bold: 是否加粗
    :return: QFont 对象
    """
    size_map = {
        "small": FONT_SIZE_SMALL,
        "normal": FONT_SIZE_NORMAL,
        "large": FONT_SIZE_LARGE,
        "title": FONT_SIZE_TITLE,
    }
    actual_size = size_map.get(size, FONT_SIZE_NORMAL)
    font = QFont(FONT_FAMILY, actual_size)
    if bold:
        font.setBold(True)
    return font


def get_mono_font(size: str = "normal") -> QFont:
    """
    获取等宽字体配置
    :param size: small, normal, large
    :return: QFont 对象
    """
    size_map = {
        "small": FONT_SIZE_SMALL,
        "normal": FONT_SIZE_NORMAL,
        "large": FONT_SIZE_LARGE,
    }
    actual_size = size_map.get(size, FONT_SIZE_NORMAL)
    return QFont(FONT_FAMILY_MONO, actual_size)
