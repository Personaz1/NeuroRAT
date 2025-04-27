#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import socket
import struct
import time
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional, Union

logger = logging.getLogger("HostScanner")

class HostScanner:
    """
    Модуль для обнаружения хостов в сети
    """
    
    def __init__(self, timeout: int = 2, max_threads: int = 50):
        """
        Инициализация сканера хостов
        
        Args:
            timeout: Таймаут для операций сканирования (в секундах)
            max_threads: Максимальное количество одновременных потоков
        """
        self.timeout = timeout
        self.max_threads = max_threads
        logger.debug(f"HostScanner инициализирован с таймаутом {timeout}с и {max_threads} потоками")
    
    def discover_hosts(self, target: str, method: str = "ping") -> List[Dict]:
        """
        Обнаруживает активные хосты в заданной сети
        
        Args:
            target: IP-адрес, диапазон CIDR (192.168.1.0/24) или диапазон (192.168.1.1-192.168.1.254)
            method: Метод обнаружения ('ping', 'tcp', 'arp')
            
        Returns:
            Список словарей с информацией об обнаруженных хостах
        """
        hosts = self._parse_target(target)
        
        if not hosts:
            logger.error(f"Не удалось распарсить цель сканирования: {target}")
            return []
        
        logger.info(f"Начинаем сканирование {len(hosts)} хостов методом {method}")
        start_time = time.time()
        
        alive_hosts = []
        
        # Выбор метода сканирования
        if method == "ping":
            alive_hosts = self._ping_scan(hosts)
        elif method == "tcp":
            alive_hosts = self._tcp_scan(hosts)
        elif method == "arp":
            alive_hosts = self._arp_scan(hosts)
        else:
            logger.error(f"Неизвестный метод сканирования: {method}")
            return []
        
        scan_duration = time.time() - start_time
        logger.info(f"Сканирование завершено за {scan_duration:.2f}с. Обнаружено {len(alive_hosts)} активных хостов")
        
        # Пытаемся получить дополнительную информацию о хостах
        for host in alive_hosts:
            try:
                hostname = socket.gethostbyaddr(host["ip"])[0]
                host["hostname"] = hostname
            except (socket.herror, socket.gaierror):
                host["hostname"] = ""
                
        return alive_hosts
    
    def _parse_target(self, target: str) -> List[str]:
        """
        Парсит цель сканирования в список IP-адресов
        
        Args:
            target: IP-адрес, диапазон CIDR или диапазон адресов
            
        Returns:
            Список IP-адресов
        """
        hosts = []
        
        # Проверяем, является ли цель диапазоном CIDR
        if "/" in target:
            try:
                network = ipaddress.IPv4Network(target, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
            except ValueError as e:
                logger.error(f"Неверный CIDR формат: {target}. Ошибка: {e}")
                return []
        
        # Проверяем, является ли цель диапазоном IP-адресов
        elif "-" in target:
            try:
                start_ip, end_ip = target.split("-")
                
                # Если в end_ip указана только последняя октета
                if "." not in end_ip:
                    # Получаем префикс из start_ip
                    prefix = start_ip.rsplit(".", 1)[0]
                    end_ip = f"{prefix}.{end_ip}"
                
                # Преобразуем IP-адреса в целые числа
                start_int = struct.unpack("!I", socket.inet_aton(start_ip))[0]
                end_int = struct.unpack("!I", socket.inet_aton(end_ip))[0]
                
                # Проверяем корректность диапазона
                if start_int > end_int:
                    logger.error(f"Неверный диапазон IP: {target}")
                    return []
                
                # Генерируем список IP-адресов
                for ip_int in range(start_int, end_int + 1):
                    ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                    hosts.append(ip)
            
            except Exception as e:
                logger.error(f"Ошибка при парсинге диапазона: {target}. Ошибка: {e}")
                return []
        
        # Если цель - одиночный IP-адрес
        else:
            try:
                socket.inet_aton(target)  # Проверяем, является ли строка валидным IPv4
                hosts.append(target)
            except socket.error:
                logger.error(f"Неверный IP-адрес: {target}")
                return []
        
        return hosts
    
    def _ping_scan(self, hosts: List[str]) -> List[Dict]:
        """
        Выполняет сканирование методом ICMP Echo (ping)
        
        Args:
            hosts: Список IP-адресов для сканирования
            
        Returns:
            Список словарей с информацией об активных хостах
        """
        alive_hosts = []
        
        logger.info(f"Начинаем ping-сканирование {len(hosts)} хостов")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(self._ping_host, hosts))
            
            for i, result in enumerate(results):
                if result:
                    alive_hosts.append({
                        "ip": hosts[i],
                        "status": "up",
                        "method": "ping"
                    })
        
        return alive_hosts
    
    def _ping_host(self, ip: str) -> bool:
        """
        Проверяет доступность хоста с помощью ping
        
        Args:
            ip: IP-адрес для проверки
            
        Returns:
            True, если хост доступен, иначе False
        """
        # Определяем параметры команды ping в зависимости от ОС
        param = "-n 1" if platform.system().lower() == "windows" else "-c 1 -W 1"
        command = f"ping {param} {ip}"
        
        try:
            # Выполняем команду ping и проверяем результат
            process = subprocess.Popen(
                command, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            process.communicate()
            
            # Возвращаем True, если команда выполнилась успешно
            return process.returncode == 0
            
        except Exception as e:
            logger.debug(f"Ошибка при выполнении ping для {ip}: {e}")
            return False
    
    def _tcp_scan(self, hosts: List[str]) -> List[Dict]:
        """
        Выполняет сканирование методом TCP-соединения
        
        Args:
            hosts: Список IP-адресов для сканирования
            
        Returns:
            Список словарей с информацией об активных хостах
        """
        alive_hosts = []
        
        # Список популярных портов для проверки
        common_ports = [21, 22, 23, 25, 80, 443, 3389]
        
        logger.info(f"Начинаем TCP-сканирование {len(hosts)} хостов по {len(common_ports)} портам")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Создаем задачи для каждого хоста и порта
            tasks = [(ip, port) for ip in hosts for port in common_ports]
            results = list(executor.map(lambda x: self._check_tcp_port(*x), tasks))
            
            # Обрабатываем результаты
            for i, result in enumerate(results):
                ip, port = tasks[i]
                
                # Если хост еще не добавлен в список активных и порт открыт
                if result and not any(h["ip"] == ip for h in alive_hosts):
                    alive_hosts.append({
                        "ip": ip,
                        "status": "up",
                        "method": "tcp",
                        "open_port": port
                    })
        
        return alive_hosts
    
    def _check_tcp_port(self, ip: str, port: int) -> bool:
        """
        Проверяет доступность TCP-порта на хосте
        
        Args:
            ip: IP-адрес
            port: Номер порта
            
        Returns:
            True, если порт открыт, иначе False
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((ip, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        finally:
            sock.close()
    
    def _arp_scan(self, hosts: List[str]) -> List[Dict]:
        """
        Выполняет сканирование с помощью ARP-запросов (требует root-привилегий)
        
        Args:
            hosts: Список IP-адресов для сканирования
            
        Returns:
            Список словарей с информацией об активных хостах
        """
        alive_hosts = []
        
        # Проверяем, поддерживается ли ARP-сканирование на текущей ОС
        if platform.system().lower() not in ["linux", "darwin"]:
            logger.warning("ARP-сканирование поддерживается только на Linux и macOS")
            return self._tcp_scan(hosts)  # Используем TCP-сканирование как запасной вариант
        
        # Получаем локальный интерфейс, подходящий для сканирования
        interface = self._get_interface_for_hosts(hosts)
        
        if not interface:
            logger.warning("Не удалось определить подходящий сетевой интерфейс для ARP-сканирования")
            return self._tcp_scan(hosts)  # Используем TCP-сканирование как запасной вариант
        
        logger.info(f"Начинаем ARP-сканирование {len(hosts)} хостов через интерфейс {interface}")
        
        try:
            # Импортируем scapy только если используется ARP-сканирование
            try:
                from scapy.all import ARP, Ether, srp
                
                # Создаем ARP-запросы для всех хостов
                for ip in hosts:
                    arp_request = ARP(pdst=ip)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = broadcast/arp_request
                    
                    # Отправляем запрос и получаем ответ
                    result = srp(packet, timeout=self.timeout, verbose=0, iface=interface)[0]
                    
                    # Если получен ответ, добавляем хост в список активных
                    for sent, received in result:
                        alive_hosts.append({
                            "ip": received.psrc,
                            "mac": received.hwsrc,
                            "status": "up",
                            "method": "arp"
                        })
            
            except ImportError:
                logger.warning("Библиотека scapy не установлена, ARP-сканирование невозможно")
                return self._ping_scan(hosts)  # Используем ping как запасной вариант
                
        except Exception as e:
            logger.error(f"Ошибка при выполнении ARP-сканирования: {e}")
            return self._ping_scan(hosts)  # Используем ping как запасной вариант
            
        return alive_hosts
    
    def _get_interface_for_hosts(self, hosts: List[str]) -> Optional[str]:
        """
        Определяет сетевой интерфейс, подходящий для сканирования указанных хостов
        
        Args:
            hosts: Список IP-адресов для сканирования
            
        Returns:
            Имя интерфейса или None, если не удалось определить
        """
        # На Linux можем использовать ip route
        if platform.system().lower() == "linux":
            try:
                # Пытаемся определить интерфейс для первого хоста в списке
                process = subprocess.Popen(
                    ["ip", "route", "get", hosts[0]], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE
                )
                output, _ = process.communicate()
                output = output.decode('utf-8')
                
                # Парсим вывод команды
                if "dev" in output:
                    interface = output.split("dev")[1].strip().split()[0]
                    return interface
                    
            except Exception as e:
                logger.debug(f"Ошибка при определении интерфейса: {e}")
                
        # На macOS используем route get
        elif platform.system().lower() == "darwin":
            try:
                process = subprocess.Popen(
                    ["route", "-n", "get", hosts[0]], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE
                )
                output, _ = process.communicate()
                output = output.decode('utf-8')
                
                # Парсим вывод команды
                if "interface:" in output:
                    interface = output.split("interface:")[1].strip().split()[0]
                    return interface
                    
            except Exception as e:
                logger.debug(f"Ошибка при определении интерфейса: {e}")
        
        return None


if __name__ == "__main__":
    # Тестовый запуск при прямом выполнении файла
    logging.basicConfig(level=logging.INFO)
    scanner = HostScanner()
    
    # Сканируем локальную сеть
    target = "127.0.0.1/30"  # Локальный адрес и несколько соседних
    
    print(f"Сканирование хостов в {target}:")
    results = scanner.discover_hosts(target, method="ping")
    
    if results:
        print(f"Обнаружено {len(results)} активных хостов:")
        for host in results:
            hostname = host.get("hostname", "")
            hostname_info = f" ({hostname})" if hostname else ""
            print(f"  {host['ip']}{hostname_info} - {host['status']}")
    else:
        print("Активные хосты не обнаружены") 