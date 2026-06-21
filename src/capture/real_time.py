"""
Real-time Packet Capture Module
基于 Scapy 的实时网卡抓包实现
"""

import threading
import time
from typing import Optional, Callable, Generator
from collections import deque

from scapy.all import sniff, conf, AsyncSniffer
from scapy.packet import Packet

from ..parser.base import ParsedPacket


class RealTimeCapture:
    """
    实时网卡抓包类

    支持:
    - 异步抓包（后台线程）
    - BPF 过滤器
    - 缓冲区管理
    - 回调通知
    """

    def __init__(self, interface: Optional[str] = None, buffer_size: int = 10000):
        """
        初始化抓包器
        :param interface: 网卡接口名称（None 表示自动选择）
        :param buffer_size: 缓冲区大小（数据包数量）
        """
        self.interface = interface
        self.buffer_size = buffer_size
        self.buffer: deque[Packet] = deque(maxlen=buffer_size)
        self.sniffer: Optional[AsyncSniffer] = None
        self.is_running = False
        self.packet_count = 0
        self.callbacks: list[Callable[[Packet], None]] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def start(self, bpf_filter: str = "") -> bool:
        """
        开始抓包
        :param bpf_filter: BPF 过滤表达式
        :return: 是否成功启动
        """
        if self.is_running:
            return False

        try:
            def packet_callback(packet: Packet):
                with self._lock:
                    self.buffer.append(packet)
                    self.packet_count += 1
                for cb in self.callbacks:
                    try:
                        cb(packet)
                    except Exception as e:
                        print(f"Callback error: {e}")

            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=packet_callback,
                filter=bpf_filter if bpf_filter else None,
                store=False
            )
            self.sniffer.start()
            self.is_running = True
            return True

        except Exception as e:
            print(f"Failed to start capture: {e}")
            return False

    def stop(self) -> list[Packet]:
        """
        停止抓包
        :return: 抓取到的数据包列表
        """
        if not self.is_running or self.sniffer is None:
            return []

        self.sniffer.stop()
        self.is_running = False
        packets = list(self.buffer)
        return packets

    def get_packets(self, count: Optional[int] = None) -> list[Packet]:
        """
        获取缓冲区中的数据包
        :param count: 获取数量（None 表示全部）
        :return: 数据包列表
        """
        with self._lock:
            if count is None:
                return list(self.buffer)
            return list(self.buffer)[-count:]

    def clear_buffer(self) -> None:
        """清空缓冲区"""
        with self._lock:
            self.buffer.clear()
            self.packet_count = 0

    def add_callback(self, callback: Callable[[Packet], None]) -> None:
        """添加数据包回调函数"""
        self.callbacks.append(callback)

    def remove_callback(self, callback: Callable[[Packet], None]) -> None:
        """移除数据包回调函数"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)

    def get_stats(self) -> dict:
        """获取抓包统计信息"""
        return {
            "is_running": self.is_running,
            "interface": self.interface or "auto",
            "packet_count": self.packet_count,
            "buffer_size": len(self.buffer),
            "max_buffer": self.buffer_size,
        }

    @staticmethod
    def list_interfaces() -> list[str]:
        """列出可用的网卡接口"""
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            return []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False
