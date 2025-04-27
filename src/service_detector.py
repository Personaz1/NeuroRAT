#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import socket
import re
import ssl
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("ServiceDetector")

class ServiceDetector:
    """
    Модуль для определения запущенных сервисов и их версий на открытых портах
    """
    
    # Регулярные выражения для распознавания баннеров различных сервисов
    SERVICE_PATTERNS = {
        "SSH": re.compile(r"SSH-(\d+\.\d+)-(.+)"),
        "FTP": re.compile(r"([\w\s\-\.]+) FTP ([\w\s\-\.]+)"),
        "SMTP": re.compile(r"([\w\-\.]+) ESMTP ([\w\-\.]+)"),
        "HTTP": re.compile(r"Server: ([^\r\n]+)"),
        "MySQL": re.compile(r"^\x0a\x00\x00\x00\x0a([\w\.]+)"),
        "PostgreSQL": re.compile(r"FATAL:.*"),
        "TELNET": re.compile(r"^.*\\r\\n.*telnet.*$", re.IGNORECASE),
    }
    
    # Словарь запросов для разных сервисов
    SERVICE_PROBES = {
        "HTTP": b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "HTTPS": b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "FTP": b"",  # FTP серверы обычно отправляют баннер при подключении
        "SMTP": b"",  # SMTP серверы обычно отправляют баннер при подключении
        "SSH": b"",   # SSH серверы обычно отправляют баннер при подключении
        "MySQL": b"\x16\x00\x00\x00\x0a",  # Простой MySQL handshake
        "PostgreSQL": b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # PostgreSQL handshake
        "TELNET": b"\xff\xfb\x01\xff\xfb\x03",  # Telnet negotiation
    }
    
    def __init__(self, timeout: int = 5):
        """
        Инициализация детектора сервисов
        
        Args:
            timeout: Таймаут для соединения (в секундах)
        """
        self.timeout = timeout
        logger.debug(f"ServiceDetector инициализирован с таймаутом {timeout}с")
    
    def get_service_banner(self, target: str, port: int, use_ssl: bool = False) -> Optional[str]:
        """
        Получает баннер сервиса с указанного порта
        
        Args:
            target: IP-адрес цели
            port: Номер порта
            use_ssl: Использовать SSL/TLS для подключения
            
        Returns:
            Строка баннера или None, если не удалось получить
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((target, port))
            
            # Используем SSL, если требуется
            if use_ssl:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock)
                except ssl.SSLError as e:
                    logger.debug(f"SSL ошибка на {target}:{port}: {e}")
                    return None
            
            # Определяем сервис по порту для выбора запроса
            service_name = self._guess_service_by_port(port)
            
            # Отправляем зонд, если он определен для сервиса
            if service_name in self.SERVICE_PROBES and self.SERVICE_PROBES[service_name]:
                try:
                    sock.send(self.SERVICE_PROBES[service_name])
                except socket.error as e:
                    logger.debug(f"Ошибка при отправке зонда на {target}:{port}: {e}")
            
            # Ждем ответа
            banner = b""
            try:
                # Пытаемся получить первоначальный баннер
                banner = sock.recv(4096)
                # Если не получили данные, попробуем отправить универсальный запрос
                if not banner:
                    sock.send(b"\\r\\n\\r\\n")
                    banner = sock.recv(4096)
            except socket.error as e:
                logger.debug(f"Ошибка при получении баннера с {target}:{port}: {e}")
                return None
                
            # Преобразуем в строку, если получили данные
            if banner:
                try:
                    return banner.decode('utf-8', errors='ignore').strip()
                except UnicodeDecodeError:
                    # Если не удалось декодировать как UTF-8, вернем hex представление первых байтов
                    return f"HEX:{banner[:20].hex()}"
            
            return None
            
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"Ошибка соединения с {target}:{port}: {e}")
            return None
        finally:
            sock.close()
    
    def detect_service(self, target: str, port: int) -> Dict:
        """
        Определяет сервис на указанном порту
        
        Args:
            target: IP-адрес цели
            port: Номер порта
            
        Returns:
            Словарь с информацией о сервисе
        """
        result = {
            "port": port,
            "service": "unknown",
            "version": "unknown",
            "banner": None,
            "ssl": False
        }
        
        # Предполагаем сервис по порту
        result["service"] = self._guess_service_by_port(port)
        
        # Пробуем получить баннер без SSL
        banner = self.get_service_banner(target, port)
        
        # Если баннер не получен и порт может использовать SSL - пробуем с SSL
        if banner is None and port in [443, 8443, 465, 993, 995]:
            banner = self.get_service_banner(target, port, use_ssl=True)
            if banner:
                result["ssl"] = True
                
        # Если баннер получен - сохраняем и пытаемся определить версию
        if banner:
            result["banner"] = banner
            service_info = self._parse_banner(banner, result["service"])
            
            if service_info:
                result["service"] = service_info["service"]
                result["version"] = service_info["version"]
        
        return result
    
    def _guess_service_by_port(self, port: int) -> str:
        """
        Предполагает тип сервиса по номеру порта
        
        Args:
            port: Номер порта
            
        Returns:
            Предполагаемое название сервиса
        """
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS", 
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP",
            8443: "HTTPS"
        }
        
        return common_ports.get(port, "unknown")
    
    def _parse_banner(self, banner: str, presumed_service: str) -> Optional[Dict]:
        """
        Анализирует баннер для определения сервиса и версии
        
        Args:
            banner: Строка баннера
            presumed_service: Предполагаемый сервис
            
        Returns:
            Словарь с сервисом и версией или None
        """
        # Проверяем регулярные выражения для разных сервисов
        for service, pattern in self.SERVICE_PATTERNS.items():
            match = pattern.search(banner)
            if match:
                if service == "SSH" and len(match.groups()) >= 2:
                    return {
                        "service": service,
                        "version": f"{match.group(1)} {match.group(2)}"
                    }
                elif len(match.groups()) >= 1:
                    return {
                        "service": service,
                        "version": match.group(1)
                    }
        
        # Простые проверки по содержанию баннера
        if "SSH" in banner:
            return {"service": "SSH", "version": "unknown"}
        elif "FTP" in banner:
            return {"service": "FTP", "version": "unknown"}
        elif "HTTP" in banner:
            return {"service": "HTTP", "version": "unknown"}
        elif "SMTP" in banner:
            return {"service": "SMTP", "version": "unknown"}
        elif "MySQL" in banner:
            return {"service": "MySQL", "version": "unknown"}
            
        # Не удалось определить версию - возвращаем предполагаемый сервис
        return {"service": presumed_service, "version": "unknown"}


if __name__ == "__main__":
    # Тестовый запуск при прямом выполнении файла
    logging.basicConfig(level=logging.INFO)
    detector = ServiceDetector(timeout=3)
    target_ip = "127.0.0.1"
    port = 80  # Порт для тестирования
    
    service_info = detector.detect_service(target_ip, port)
    print(f"Сервис на {target_ip}:{port}:")
    for key, value in service_info.items():
        print(f"  {key}: {value}") 