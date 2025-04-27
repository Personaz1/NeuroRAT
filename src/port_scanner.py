#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple, Set

logger = logging.getLogger("PortScanner")

class PortScanner:
    """
    Модуль для сканирования портов на целевом хосте
    """
    
    # Известные порты для быстрого сканирования
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    
    def __init__(self, threads: int = 10, timeout: int = 3):
        """
        Инициализация сканера портов
        
        Args:
            threads: Количество потоков для параллельного сканирования
            timeout: Таймаут для соединения (в секундах)
        """
        self.threads = threads
        self.timeout = timeout
        logger.debug(f"PortScanner инициализирован с {threads} потоками и таймаутом {timeout}с")
    
    def scan_port(self, target: str, port: int) -> Tuple[int, bool]:
        """
        Сканирует один порт и определяет, открыт ли он
        
        Args:
            target: IP-адрес цели
            port: Номер порта для сканирования
            
        Returns:
            Кортеж (номер порта, статус открытия)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            start_time = time.time()
            result = sock.connect_ex((target, port))
            response_time = time.time() - start_time
            
            if result == 0:
                logger.debug(f"Порт {port} на {target} открыт (время отклика: {response_time:.3f}с)")
                return port, True
            else:
                return port, False
                
        except (socket.timeout, ConnectionRefusedError):
            return port, False
        except socket.error as e:
            logger.error(f"Ошибка при сканировании порта {port} на {target}: {e}")
            return port, False
        finally:
            sock.close()
    
    def scan(self, target: str, scan_level: str = "basic") -> List[int]:
        """
        Сканирует порты на целевом хосте в зависимости от уровня сканирования
        
        Args:
            target: IP-адрес цели
            scan_level: Уровень сканирования (basic, advanced, deep)
            
        Returns:
            Список открытых портов
        """
        ports_to_scan = []
        
        if scan_level == "basic":
            # Сканируем только популярные порты
            ports_to_scan = list(self.COMMON_PORTS.keys())
        elif scan_level == "advanced":
            # Сканируем порты от 1 до 1024 и популярные порты выше 1024
            ports_to_scan = list(range(1, 1025))
            high_ports = [p for p in self.COMMON_PORTS.keys() if p > 1024]
            ports_to_scan.extend(high_ports)
        elif scan_level == "deep":
            # Сканируем порты от 1 до 65535
            ports_to_scan = list(range(1, 65536))
        
        open_ports = []
        logger.info(f"Сканирование {len(ports_to_scan)} портов на {target}...")
        
        start_time = time.time()
        
        # Используем ThreadPoolExecutor для параллельного сканирования
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            scan_results = list(executor.map(
                lambda p: self.scan_port(target, p),
                ports_to_scan
            ))
        
        # Фильтруем только открытые порты
        open_ports = [port for port, is_open in scan_results if is_open]
        
        scan_duration = time.time() - start_time
        logger.info(f"Сканирование завершено за {scan_duration:.2f}с. Найдено {len(open_ports)} открытых портов")
        
        return sorted(open_ports)
    
    def get_service_name(self, port: int) -> str:
        """
        Возвращает предполагаемое имя сервиса для порта
        
        Args:
            port: Номер порта
            
        Returns:
            Имя сервиса или "unknown"
        """
        return self.COMMON_PORTS.get(port, "unknown")


if __name__ == "__main__":
    # Тестовый запуск при прямом выполнении файла
    logging.basicConfig(level=logging.INFO)
    scanner = PortScanner(threads=50, timeout=1)
    target_ip = "127.0.0.1"  # Локальный хост для тестирования
    open_ports = scanner.scan(target_ip, "basic")
    
    print(f"Открытые порты на {target_ip}:")
    for port in open_ports:
        service = scanner.get_service_name(port)
        print(f"  {port}/tcp - {service}") 