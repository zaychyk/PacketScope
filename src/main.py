"""
Network Protocol Analyzer - Main Entry Point
网络协议分析仪主入口

运行方式:
    python -m src
    python src/main.py
"""

import sys
import argparse

# 支持直接运行和模块运行两种方式
try:
    from src.gui.main_window import MainWindow
except ImportError:
    from .gui.main_window import MainWindow


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="Network Protocol Analyzer - 网络协议分析仪简化版"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="0.1.0"
    )
    parser.add_argument(
        "--no-gui",
        action="store_true",
        help="Run in command-line mode (no GUI)"
    )
    parser.add_argument(
        "-i", "--interface",
        type=str,
        help="Network interface to capture from"
    )
    parser.add_argument(
        "-r", "--read",
        type=str,
        help="Read packets from pcap file"
    )
    parser.add_argument(
        "-f", "--filter",
        type=str,
        default="",
        help="BPF filter expression"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited)"
    )

    args = parser.parse_args()

    if args.no_gui:
        # CLI 模式
        print("CLI mode not fully implemented yet.")
        print("Use GUI mode for full functionality.")
        sys.exit(0)

    # GUI 模式 - PyQt6
    try:
        from PyQt6.QtWidgets import QApplication
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
