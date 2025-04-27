#!/usr/bin/env python3
"""
AdvancedScanner - Продвинутый сканер для обнаружения уязвимостей и криптокошельков
Интегрирует функции обнаружения уязвимостей и поиска криптовалютных данных
"""

import os
import re
import subprocess
import socket
import threading
import random
import logging
import tempfile
from typing import Dict, List, Any, Optional, Tuple, Set, Union
import ipaddress

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='advanced_scanner.log'
)
logger = logging.getLogger('AdvancedScanner')

class AdvancedScanner:
    """
    Класс для продвинутого сканирования систем на наличие уязвимостей и криптовалютных данных
    """
    
    # Регулярные выражения для поиска криптовалютных данных
    WALLET_PATTERNS = {
        "ethereum_private_key": re.compile(r'(0x)?[0-9a-fA-F]{64}'),
        "ethereum_address": re.compile(r'0x[0-9a-fA-F]{40}'),
        "bitcoin_wif": re.compile(r'[5KL][1-9A-HJ-NP-Za-km-z]{50,51}'),
        "mnemonic_phrases": re.compile(r'([a-zA-Z]+ ){11,23}[a-zA-Z]+')
    }
    
    # Сигнатуры популярных криптовалютных приложений и файлов
    CRYPTO_APP_SIGNATURES = [
        {"name": "MetaMask", "paths": ["*/MetaMask/*", "*/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/*"]},
        {"name": "Electrum", "paths": ["*/electrum/wallets/*", "*/Electrum/*"]},
        {"name": "Exodus", "paths": ["*/exodus/exodus.wallet/*"]},
        {"name": "MyEtherWallet", "paths": ["*/Ethereum/keystore/*"]},
        {"name": "Bitcoin Core", "paths": ["*/Bitcoin/wallet.dat"]},
        {"name": "Binance", "paths": ["*/Binance/*"]}
    ]
    
    # Порты и сервисы, связанные с криптовалютой
    CRYPTO_RELATED_PORTS = {
        "8332": "Bitcoin RPC",
        "8333": "Bitcoin",
        "8545": "Ethereum RPC",
        "8546": "Ethereum WebSocket",
        "30303": "Ethereum P2P",
        "9735": "Lightning Network",
        "8555": "Ganache/Ethereum Dev",
        "18080": "Monero",
        "18081": "Monero RPC"
    }
    
    def __init__(self, concurrency: int = 10, timeout: int = 3, stealth_mode: bool = True):
        """
        Инициализация сканера
        
        Args:
            concurrency: Максимальное количество одновременных потоков
            timeout: Таймаут для сетевых операций (в секундах)
            stealth_mode: Режим стелс (случайные задержки и осторожное сканирование)
        """
        self.concurrency = concurrency
        self.timeout = timeout
        self.stealth_mode = stealth_mode
        self.logger = logger
        self.logger.info(f"AdvancedScanner initialized (concurrency={concurrency}, stealth_mode={stealth_mode})")
    
    def scan_network(self, subnet: str, port_scan: bool = True) -> List[Dict[str, Any]]:
        """
        Сканирует сеть для поиска живых хостов
        
        Args:
            subnet: Подсеть в формате CIDR (например, 192.168.1.0/24)
            port_scan: Выполнять ли сканирование портов
            
        Returns:
            List[Dict]: Список живых хостов с информацией о них
        """
        self.logger.info(f"Scanning network: {subnet}")
        
        try:
            # Преобразуем строку в объект IPv4Network
            network = ipaddress.IPv4Network(subnet)
        except ValueError as e:
            self.logger.error(f"Invalid subnet format: {e}")
            return []
        
        hosts = []
        threads = []
        thread_semaphore = threading.Semaphore(value=self.concurrency)
        hosts_lock = threading.Lock()
        total_hosts = network.num_addresses
        
        def scan_host(ip):
            if self.stealth_mode:
                # Случайная задержка для маскировки
                time.sleep(random.uniform(0.01, 0.1))
            
            # Проверяем, жив ли хост
            is_alive = self._is_host_alive(str(ip))
            
            if is_alive:
                host_info = {"ip": str(ip), "status": "alive"}
                
                if port_scan:
                    # Сканируем порты
                    open_ports = self._scan_ports(str(ip))
                    host_info["open_ports"] = open_ports
                    
                    # Проверяем на наличие криптовалютных сервисов
                    crypto_services = self._detect_crypto_services(open_ports)
                    if crypto_services:
                        host_info["crypto_services"] = crypto_services
                
                with hosts_lock:
                    hosts.append(host_info)
                    
            thread_semaphore.release()
        
        # Запускаем потоки для сканирования
        self.logger.info(f"Starting scan of {total_hosts} hosts in {subnet}")
        for ip in network:
            thread_semaphore.acquire()
            t = threading.Thread(target=scan_host, args=(ip,))
            t.daemon = True
            threads.append(t)
            t.start()
            
            # Периодически выводим прогресс
            if len(threads) % 100 == 0:
                self.logger.info(f"Progress: {len(threads)}/{total_hosts} hosts initiated")
        
        # Ждем завершения всех потоков
        for t in threads:
            t.join()
            
        self.logger.info(f"Network scan completed. Found {len(hosts)} alive hosts in {subnet}")
        return hosts
    
    def _is_host_alive(self, ip: str) -> bool:
        """
        Проверяет, жив ли хост
        
        Args:
            ip: IP-адрес хоста
            
        Returns:
            bool: True, если хост отвечает
        """
        # Используем разные методы проверки
        methods = [self._ping_check, self._tcp_check]
        random.shuffle(methods)  # Случайный порядок в режиме стелс
        
        for method in methods:
            if method(ip):
                return True
                
        return False
    
    def _ping_check(self, ip: str) -> bool:
        """
        Проверяет хост с помощью ICMP ping
        
        Args:
            ip: IP-адрес хоста
            
        Returns:
            bool: True, если хост отвечает на ping
        """
        try:
            # Для разных ОС могут быть разные параметры ping
            if os.name == "nt":  # Windows
                ping_cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), ip]
            else:  # Linux/Mac
                ping_cmd = ["ping", "-c", "1", "-W", str(self.timeout), ip]
                
            result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except Exception as e:
            self.logger.debug(f"Ping error for {ip}: {e}")
            return False
    
    def _tcp_check(self, ip: str) -> bool:
        """
        Проверяет хост с помощью TCP-соединения к популярным портам
        
        Args:
            ip: IP-адрес хоста
            
        Returns:
            bool: True, если хост отвечает на TCP-запрос
        """
        common_ports = [80, 443, 22, 445]
        random.shuffle(common_ports)  # Случайный порядок в режиме стелс
        
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        return True
            except Exception:
                pass
                
        return False
    
    def _scan_ports(self, ip: str) -> Dict[int, str]:
        """
        Сканирует порты хоста
        
        Args:
            ip: IP-адрес хоста
            
        Returns:
            Dict[int, str]: Словарь открытых портов и определенных сервисов
        """
        open_ports = {}
        
        # Список портов для сканирования (общие + криптовалютные)
        ports_to_scan = [21, 22, 23, 25, 80, 443, 445, 3389, 8080]
        crypto_ports = [int(port) for port in self.CRYPTO_RELATED_PORTS.keys()]
        ports_to_scan.extend(crypto_ports)
        
        # Перемешиваем порты для стелс-режима
        if self.stealth_mode:
            random.shuffle(ports_to_scan)
            
        for port in ports_to_scan:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        # Определяем сервис
                        service = self._detect_service(ip, port)
                        open_ports[port] = service
                        
                        # Добавляем случайную задержку в стелс-режиме
                        if self.stealth_mode:
                            time.sleep(random.uniform(0.05, 0.2))
            except Exception as e:
                self.logger.debug(f"Error scanning port {port} on {ip}: {e}")
                
        return open_ports
    
    def _detect_service(self, ip: str, port: int) -> str:
        """
        Определяет сервис на указанном порту
        
        Args:
            ip: IP-адрес хоста
            port: Номер порта
            
        Returns:
            str: Название сервиса
        """
        # Проверяем, известный ли это криптовалютный порт
        if str(port) in self.CRYPTO_RELATED_PORTS:
            return self.CRYPTO_RELATED_PORTS[str(port)]
            
        # Пытаемся получить баннер сервиса
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                
                # Отправляем простой HTTP-запрос для web-серверов
                if port in [80, 443, 8080, 8443]:
                    s.send(b"GET / HTTP/1.0\r\n\r\n")
                else:
                    # Для других сервисов просто слушаем
                    pass
                    
                banner = s.recv(1024)
                
                # Определяем сервис по баннеру
                if b"SSH" in banner:
                    return "SSH"
                elif b"HTTP" in banner:
                    return "HTTP"
                elif b"SMTP" in banner:
                    return "SMTP"
                elif b"FTP" in banner:
                    return "FTP"
                elif b"geth" in banner or b"ethereum" in banner.lower():
                    return "Ethereum Node"
                elif b"bitcoin" in banner.lower():
                    return "Bitcoin Node"
                else:
                    return f"Unknown ({banner[:20].decode('utf-8', errors='ignore')}...)"
                    
        except Exception:
            # Если не удалось получить баннер, используем известные порты
            common_services = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                80: "HTTP",
                443: "HTTPS",
                445: "SMB",
                3389: "RDP",
                8080: "HTTP-Proxy"
            }
            
            if port in common_services:
                return common_services[port]
            else:
                return "Unknown"
    
    def _detect_crypto_services(self, open_ports: Dict[int, str]) -> List[Dict[str, str]]:
        """
        Определяет криптовалютные сервисы на основе открытых портов
        
        Args:
            open_ports: Словарь открытых портов
            
        Returns:
            List[Dict]: Список обнаруженных криптовалютных сервисов
        """
        crypto_services = []
        
        for port, service in open_ports.items():
            port_str = str(port)
            
            # Проверяем, есть ли порт в списке криптовалютных
            if port_str in self.CRYPTO_RELATED_PORTS:
                crypto_services.append({
                    "port": port,
                    "service": self.CRYPTO_RELATED_PORTS[port_str],
                    "confidence": "high"
                })
            # Проверяем сервис на наличие криптовалютных ключевых слов
            elif any(keyword in service.lower() for keyword in ["ethereum", "bitcoin", "crypto", "blockchain", "wallet"]):
                crypto_services.append({
                    "port": port,
                    "service": service,
                    "confidence": "medium"
                })
                
        return crypto_services
    
    def scan_host_for_wallets(self, host: Dict[str, Any], scan_depth: str = "medium") -> Dict[str, Any]:
        """
        Сканирует хост на наличие криптовалютных кошельков и данных
        
        Args:
            host: Информация о хосте (должна включать IP и открытые порты)
            scan_depth: Глубина сканирования (low, medium, high)
            
        Returns:
            Dict: Результаты сканирования
        """
        ip = host.get("ip")
        if not ip:
            return {"error": "Missing IP address"}
            
        self.logger.info(f"Scanning host {ip} for crypto wallets (depth: {scan_depth})")
        
        results = {
            "ip": ip,
            "wallets_found": [],
            "scan_depth": scan_depth,
            "timestamp": time.time()
        }
        
        # Различные методы сканирования в зависимости от глубины
        if scan_depth == "low":
            # Только проверка на криптовалютные порты
            if "open_ports" in host:
                results["crypto_services"] = self._detect_crypto_services(host["open_ports"])
                
        elif scan_depth == "medium":
            # Проверка портов + сканирование общих путей
            if "open_ports" in host:
                results["crypto_services"] = self._detect_crypto_services(host["open_ports"])
            
            # Пытаемся найти криптовалютные данные по общим путям
            # Реализация зависит от доступа к системе и метода взаимодействия
            
        elif scan_depth == "high":
            # Полное сканирование системы и памяти
            # Реализация зависит от доступа к системе и метода взаимодействия
            pass
        
        self.logger.info(f"Wallet scan completed for {ip}")
        return results
    
    def extract_wallet_data(self, raw_data: str) -> List[Dict[str, Any]]:
        """
        Извлекает данные криптовалютных кошельков из строки
        
        Args:
            raw_data: Строка с данными для анализа
            
        Returns:
            List[Dict]: Список найденных кошельков и ключей
        """
        results = []
        
        # Ищем совпадения по всем паттернам
        for wallet_type, pattern in self.WALLET_PATTERNS.items():
            matches = pattern.findall(raw_data)
            
            for match in matches:
                # Валидируем найденные данные
                if self._validate_wallet_data(wallet_type, match):
                    results.append({
                        "type": wallet_type,
                        "data": match,
                        "confidence": "high" if wallet_type == "ethereum_private_key" else "medium"
                    })
        
        return results
    
    def _validate_wallet_data(self, wallet_type: str, data: str) -> bool:
        """
        Проверяет валидность найденных данных кошелька
        
        Args:
            wallet_type: Тип кошелька
            data: Найденные данные
            
        Returns:
            bool: True, если данные валидны
        """
        if wallet_type == "ethereum_private_key":
            # Проверяем, что это действительно приватный ключ, а не случайная строка
            return len(data) == 64 or (len(data) == 66 and data.startswith("0x"))
            
        elif wallet_type == "ethereum_address":
            # Простая проверка ethereum-адреса
            return len(data) == 42 and data.startswith("0x")
            
        elif wallet_type == "bitcoin_wif":
            # Базовая проверка формата WIF
            return len(data) >= 50 and data[0] in "5KL"
            
        elif wallet_type == "mnemonic_phrases":
            # Проверка мнемонической фразы (обычно 12 или 24 слова)
            words = data.split()
            return len(words) in [12, 15, 18, 21, 24]
            
        return True


if __name__ == "__main__":
    # Тестовый запуск
    scanner = AdvancedScanner(concurrency=5, stealth_mode=True)
    results = scanner.scan_network("127.0.0.1/24", port_scan=True)
    
    # Вывод результатов
    for host in results:
        print(f"Host: {host['ip']}")
        if "open_ports" in host:
            print(f"  Open ports: {len(host['open_ports'])}")
            for port, service in host['open_ports'].items():
                print(f"    {port}: {service}")
        
        if "crypto_services" in host:
            print(f"  Crypto services: {len(host['crypto_services'])}")
            for service in host['crypto_services']:
                print(f"    {service['port']}: {service['service']} (Confidence: {service['confidence']})")
        
        print("") 