"""
Capture Buffer Module
优化实时抓包缓冲区，支持高流量场景
"""

import threading
import time
from collections import deque
from typing import Optional, Iterator
from scapy.packet import Packet


class CaptureBuffer:
    """
    高性能抓包缓冲区

    特性:
    - 线程安全
    - 固定容量（FIFO）
    - 支持批量操作
    - 低内存占用
    """

    def __init__(self, max_size: int = 50000):
        """
        初始化缓冲区
        :param max_size: 最大容量（数据包数量）
        """
        self.max_size = max_size
        self._buffer: deque[Packet] = deque(maxlen=max_size)
        self._lock = threading.RLock()
        self._total_received = 0
        self._total_dropped = 0
        self._start_time: Optional[float] = None

    def add(self, packet: Packet) -> bool:
        """
        添加数据包到缓冲区
        :param packet: 数据包
        :return: 是否成功添加
        """
        with self._lock:
            if self._start_time is None:
                self._start_time = time.time()

            # 检查是否需要丢弃
            if len(self._buffer) >= self.max_size:
                self._total_dropped += 1
                # 移除最旧的数据包
                self._buffer.popleft()

            self._buffer.append(packet)
            self._total_received += 1
            return True

    def add_batch(self, packets: list[Packet]) -> int:
        """
        批量添加数据包
        :param packets: 数据包列表
        :return: 成功添加的数量
        """
        added = 0
        with self._lock:
            if self._start_time is None:
                self._start_time = time.time()

            for packet in packets:
                if len(self._buffer) >= self.max_size:
                    self._total_dropped += 1
                    self._buffer.popleft()
                self._buffer.append(packet)
                self._total_received += 1
                added += 1

        return added

    def get(self, count: Optional[int] = None) -> list[Packet]:
        """
        获取数据包
        :param count: 获取数量（None 表示全部）
        :return: 数据包列表
        """
        with self._lock:
            if count is None:
                return list(self._buffer)
            return list(self._buffer)[-count:]

    def get_range(self, start: int, end: int) -> list[Packet]:
        """
        获取指定范围的数据包
        :param start: 起始索引
        :param end: 结束索引
        :return: 数据包列表
        """
        with self._lock:
            return list(self._buffer)[start:end]

    def pop(self) -> Optional[Packet]:
        """
        弹出最旧的数据包
        :return: 数据包
        """
        with self._lock:
            if self._buffer:
                return self._buffer.popleft()
            return None

    def clear(self) -> None:
        """清空缓冲区"""
        with self._lock:
            self._buffer.clear()
            self._total_received = 0
            self._total_dropped = 0
            self._start_time = None

    def size(self) -> int:
        """获取当前缓冲区大小"""
        with self._lock:
            return len(self._buffer)

    def is_full(self) -> bool:
        """检查缓冲区是否已满"""
        with self._lock:
            return len(self._buffer) >= self.max_size

    def is_empty(self) -> bool:
        """检查缓冲区是否为空"""
        with self._lock:
            return len(self._buffer) == 0

    def get_stats(self) -> dict:
        """获取缓冲区统计信息"""
        with self._lock:
            elapsed = 0.0
            if self._start_time is not None:
                elapsed = time.time() - self._start_time

            return {
                "max_size": self.max_size,
                "current_size": len(self._buffer),
                "total_received": self._total_received,
                "total_dropped": self._total_dropped,
                "drop_rate": self._total_dropped / max(1, self._total_received),
                "elapsed_time": elapsed,
                "packets_per_second": self._total_received / max(0.001, elapsed),
            }

    def __iter__(self) -> Iterator[Packet]:
        """迭代器"""
        with self._lock:
            yield from self._buffer

    def __len__(self) -> int:
        """长度"""
        return self.size()
