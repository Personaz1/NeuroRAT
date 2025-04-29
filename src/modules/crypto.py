#!/usr/bin/env python3
"""
Crypto Module - Модуль для шифрования и дешифрования данных
Обеспечивает криптографическую защиту для коммуникационных каналов
"""

import os
import base64
import hashlib
import hmac
import time
from src.common.utils import get_logger
import logging
from typing import Dict, List, Any, Optional, Tuple, Union, Callable

# Для AES и ChaCha20 требуется библиотека cryptography
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.backends import default_backend
    CRYPTO_LIB_AVAILABLE = True
except ImportError:
    CRYPTO_LIB_AVAILABLE = False


class CryptoProvider:
    """
    Базовый класс для криптографических провайдеров
    """
    
    def __init__(self, key: bytes = None):
        """
        Инициализация криптографического провайдера
        
        Args:
            key: Ключ шифрования (если None, генерируется автоматически)
        """
        self.key = key if key is not None else self._generate_key()
        self.logger = get_logger("crypto")
        
    def _generate_key(self) -> bytes:
        """Генерирует новый ключ шифрования"""
        return os.urandom(32)  # 256-битный ключ
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Шифрует данные
        
        Args:
            data: Данные для шифрования
            
        Returns:
            bytes: Зашифрованные данные
        """
        raise NotImplementedError("Метод encrypt должен быть реализован в подклассах")
    
    def decrypt(self, data: bytes) -> bytes:
        """
        Дешифрует данные
        
        Args:
            data: Данные для дешифрования
            
        Returns:
            bytes: Расшифрованные данные
        """
        raise NotImplementedError("Метод decrypt должен быть реализован в подклассах")
    
    def get_key_hash(self) -> str:
        """Возвращает хеш ключа для идентификации"""
        return hashlib.sha256(self.key).hexdigest()[:16]


class XORCrypto(CryptoProvider):
    """
    Простой XOR-шифр (только для базовой защиты)
    Не является криптографически стойким, используется в тестировании
    или когда другие методы недоступны
    """
    
    def encrypt(self, data: bytes) -> bytes:
        """Шифрует данные с помощью XOR"""
        key_len = len(self.key)
        return bytes([data[i] ^ self.key[i % key_len] for i in range(len(data))])
    
    def decrypt(self, data: bytes) -> bytes:
        """Дешифрует данные с помощью XOR (идентично шифрованию)"""
        return self.encrypt(data)  # XOR с тем же ключом выполняет обратную операцию


class AESCrypto(CryptoProvider):
    """
    Реализация шифрования с использованием AES-256-GCM
    Требует библиотеку cryptography
    """
    
    def __init__(self, key: bytes = None):
        """Инициализация AES-шифрования"""
        super().__init__(key)
        
        if not CRYPTO_LIB_AVAILABLE:
            self.logger.warning("Библиотека cryptography не установлена. AES недоступен.")
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Шифрует данные с помощью AES-256-GCM
        
        Args:
            data: Данные для шифрования
            
        Returns:
            bytes: Зашифрованные данные в формате nonce(12) + tag(16) + ciphertext
        """
        if not CRYPTO_LIB_AVAILABLE:
            raise ImportError("Библиотека cryptography не установлена")
        
        # Генерируем случайный nonce
        nonce = os.urandom(12)
        
        # Создаем шифр AES-GCM
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        # Шифруем данные
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Возвращаем nonce + tag + ciphertext
        return nonce + encryptor.tag + ciphertext
    
    def decrypt(self, data: bytes) -> bytes:
        """
        Дешифрует данные, зашифрованные с помощью AES-256-GCM
        
        Args:
            data: Данные для дешифрования в формате nonce(12) + tag(16) + ciphertext
            
        Returns:
            bytes: Расшифрованные данные
        """
        if not CRYPTO_LIB_AVAILABLE:
            raise ImportError("Библиотека cryptography не установлена")
        
        # Извлекаем nonce, tag и ciphertext
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        # Создаем шифр AES-GCM
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        
        # Дешифруем данные
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


class ChaCha20Crypto(CryptoProvider):
    """
    Реализация шифрования с использованием ChaCha20-Poly1305
    Требует библиотеку cryptography
    """
    
    def __init__(self, key: bytes = None):
        """Инициализация ChaCha20-шифрования"""
        super().__init__(key)
        
        if not CRYPTO_LIB_AVAILABLE:
            self.logger.warning("Библиотека cryptography не установлена. ChaCha20 недоступен.")
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Шифрует данные с помощью ChaCha20-Poly1305
        
        Args:
            data: Данные для шифрования
            
        Returns:
            bytes: Зашифрованные данные в формате nonce(12) + ciphertext+tag
        """
        if not CRYPTO_LIB_AVAILABLE:
            raise ImportError("Библиотека cryptography не установлена")
        
        # Генерируем случайный nonce
        nonce = os.urandom(12)
        
        # Создаем шифр ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(self.key)
        
        # Шифруем данные
        ciphertext = cipher.encrypt(nonce, data, None)  # None = без дополнительных данных
        
        # Возвращаем nonce + ciphertext+tag
        return nonce + ciphertext
    
    def decrypt(self, data: bytes) -> bytes:
        """
        Дешифрует данные, зашифрованные с помощью ChaCha20-Poly1305
        
        Args:
            data: Данные для дешифрования в формате nonce(12) + ciphertext+tag
            
        Returns:
            bytes: Расшифрованные данные
        """
        if not CRYPTO_LIB_AVAILABLE:
            raise ImportError("Библиотека cryptography не установлена")
        
        # Извлекаем nonce и ciphertext+tag
        nonce = data[:12]
        ciphertext = data[12:]
        
        # Создаем шифр ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(self.key)
        
        # Дешифруем данные
        return cipher.decrypt(nonce, ciphertext, None)  # None = без дополнительных данных


class CryptoUtils:
    """
    Утилитарный класс для работы с криптографией
    Предоставляет хеширование, кодирование/декодирование и т.д.
    """
    
    @staticmethod
    def hash_sha256(data: bytes) -> bytes:
        """
        Вычисляет SHA-256 хеш данных
        
        Args:
            data: Данные для хеширования
            
        Returns:
            bytes: SHA-256 хеш
        """
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def hash_md5(data: bytes) -> bytes:
        """
        Вычисляет MD5 хеш данных (использовать только там, где нужна совместимость)
        
        Args:
            data: Данные для хеширования
            
        Returns:
            bytes: MD5 хеш
        """
        return hashlib.md5(data).digest()
    
    @staticmethod
    def compute_hmac(key: bytes, data: bytes) -> bytes:
        """
        Вычисляет HMAC-SHA256 для данных
        
        Args:
            key: Ключ для HMAC
            data: Данные для подписи
            
        Returns:
            bytes: HMAC-SHA256 подпись
        """
        return hmac.new(key, data, hashlib.sha256).digest()
    
    @staticmethod
    def verify_hmac(key: bytes, data: bytes, signature: bytes) -> bool:
        """
        Проверяет HMAC-SHA256 подпись данных
        
        Args:
            key: Ключ для HMAC
            data: Данные для проверки
            signature: Ожидаемая подпись
            
        Returns:
            bool: True, если подпись верна
        """
        computed = CryptoUtils.compute_hmac(key, data)
        return hmac.compare_digest(computed, signature)
    
    @staticmethod
    def base64_encode(data: bytes) -> str:
        """
        Кодирует данные в base64
        
        Args:
            data: Данные для кодирования
            
        Returns:
            str: Данные в формате base64
        """
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def base64_decode(data: str) -> bytes:
        """
        Декодирует данные из base64
        
        Args:
            data: Данные в формате base64
            
        Returns:
            bytes: Декодированные данные
        """
        return base64.b64decode(data.encode('utf-8'))
    
    @staticmethod
    def base32_encode(data: bytes) -> str:
        """
        Кодирует данные в base32 (для использования в DNS)
        
        Args:
            data: Данные для кодирования
            
        Returns:
            str: Данные в формате base32
        """
        return base64.b32encode(data).decode('utf-8').lower().rstrip('=')
    
    @staticmethod
    def base32_decode(data: str) -> bytes:
        """
        Декодирует данные из base32
        
        Args:
            data: Данные в формате base32
            
        Returns:
            bytes: Декодированные данные
        """
        # Добавляем padding, если необходимо
        padding = (8 - len(data) % 8) % 8
        data = data.upper() + '=' * padding
        return base64.b32decode(data)
    
    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = None) -> bytes:
        """
        Генерирует ключ из пароля с использованием PBKDF2
        
        Args:
            password: Пароль
            salt: Соль (генерируется автоматически, если не указана)
            
        Returns:
            bytes: Ключ шифрования
        """
        if salt is None:
            salt = os.urandom(16)
        
        # Используем PBKDF2 с SHA-256
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations=100000,
            dklen=32  # 256-битный ключ
        )
        
        return key


class EncryptionManager:
    """
    Менеджер шифрования для управления различными криптопровайдерами
    """
    
    def __init__(self, default_method: str = "aes"):
        """
        Инициализация менеджера шифрования
        
        Args:
            default_method: Метод шифрования по умолчанию ('xor', 'aes', 'chacha20')
        """
        self.providers = {}
        self.default_method = default_method
        self.logger = get_logger("encryption_manager")
        
        # Инициализируем доступные провайдеры
        try:
            # XOR всегда доступен
            self.providers["xor"] = XORCrypto()
            
            if CRYPTO_LIB_AVAILABLE:
                self.providers["aes"] = AESCrypto()
                self.providers["chacha20"] = ChaCha20Crypto()
            else:
                self.logger.warning("Библиотека cryptography не установлена. Доступен только XOR.")
                self.default_method = "xor"
        except Exception as e:
            self.logger.error(f"Ошибка инициализации криптопровайдеров: {e}")
            # XOR как запасной вариант
            self.default_method = "xor"
    
    def set_key(self, method: str, key: bytes) -> bool:
        """
        Устанавливает ключ для указанного метода шифрования
        
        Args:
            method: Метод шифрования ('xor', 'aes', 'chacha20')
            key: Ключ шифрования
            
        Returns:
            bool: True если успешно
        """
        if method not in self.providers:
            self.logger.error(f"Неизвестный метод шифрования: {method}")
            return False
        
        try:
            self.providers[method] = self._create_provider(method, key)
            return True
        except Exception as e:
            self.logger.error(f"Ошибка установки ключа для {method}: {e}")
            return False
    
    def _create_provider(self, method: str, key: bytes) -> CryptoProvider:
        """Создает провайдер шифрования указанного типа"""
        if method == "xor":
            return XORCrypto(key)
        elif method == "aes":
            return AESCrypto(key)
        elif method == "chacha20":
            return ChaCha20Crypto(key)
        else:
            raise ValueError(f"Неизвестный метод шифрования: {method}")
    
    def encrypt(self, data: bytes, method: str = None) -> Dict[str, Any]:
        """
        Шифрует данные с помощью указанного метода
        
        Args:
            data: Данные для шифрования
            method: Метод шифрования (если None, используется default_method)
            
        Returns:
            Dict: Словарь с результатом шифрования
                {
                    "method": метод шифрования,
                    "data": зашифрованные данные в base64,
                    "timestamp": время шифрования,
                    "key_hash": хеш ключа (для проверки)
                }
        """
        method = method or self.default_method
        
        if method not in self.providers:
            self.logger.error(f"Неизвестный метод шифрования: {method}")
            method = "xor"  # Запасной вариант
        
        try:
            provider = self.providers[method]
            encrypted = provider.encrypt(data)
            
            return {
                "method": method,
                "data": CryptoUtils.base64_encode(encrypted),
                "timestamp": int(time.time()),
                "key_hash": provider.get_key_hash()
            }
        except Exception as e:
            self.logger.error(f"Ошибка шифрования: {e}")
            # В случае ошибки пытаемся использовать XOR
            if method != "xor":
                self.logger.warning("Переключение на XOR-шифрование после ошибки")
                return self.encrypt(data, "xor")
            
            raise
    
    def decrypt(self, encrypted_data: Dict[str, Any]) -> bytes:
        """
        Дешифрует данные
        
        Args:
            encrypted_data: Словарь с зашифрованными данными
                {
                    "method": метод шифрования,
                    "data": зашифрованные данные в base64,
                    "timestamp": время шифрования,
                    "key_hash": хеш ключа (для проверки)
                }
            
        Returns:
            bytes: Расшифрованные данные
        """
        method = encrypted_data.get("method", self.default_method)
        
        if method not in self.providers:
            self.logger.error(f"Неизвестный метод шифрования: {method}")
            raise ValueError(f"Неизвестный метод шифрования: {method}")
        
        # Проверяем хеш ключа, если он есть
        key_hash = encrypted_data.get("key_hash")
        if key_hash and key_hash != self.providers[method].get_key_hash():
            self.logger.warning(f"Несоответствие хеша ключа для {method}")
        
        try:
            # Декодируем base64 и расшифровываем
            encoded_data = encrypted_data["data"]
            binary_data = CryptoUtils.base64_decode(encoded_data)
            
            return self.providers[method].decrypt(binary_data)
        except Exception as e:
            self.logger.error(f"Ошибка дешифрования: {e}")
            raise

# Тестирование модуля
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Тестируем менеджер шифрования
    manager = EncryptionManager()
    
    test_data = b"Hello from NeuroRAT Crypto Module!"
    
    # Тестируем все доступные методы
    for method in manager.providers.keys():
        try:
            # Шифруем и дешифруем данные
            encrypted = manager.encrypt(test_data, method)
            decrypted = manager.decrypt(encrypted)
            
            print(f"[{method.upper()}] Проверка шифрования: {decrypted == test_data}")
            print(f"  Зашифровано: {encrypted['data'][:40]}...")
            print(f"  Ключ: {encrypted['key_hash']}")
        except Exception as e:
            print(f"[{method.upper()}] Ошибка: {e}")
    
    # Тестируем утилиты
    print("\nТестирование утилит:")
    
    # Хеширование
    data_hash = CryptoUtils.hash_sha256(test_data)
    print(f"SHA-256: {data_hash.hex()}")
    
    # HMAC
    key = os.urandom(32)
    signature = CryptoUtils.compute_hmac(key, test_data)
    valid = CryptoUtils.verify_hmac(key, test_data, signature)
    print(f"HMAC проверка: {valid}")
    
    # Base64 и Base32
    base64_encoded = CryptoUtils.base64_encode(test_data)
    base64_decoded = CryptoUtils.base64_decode(base64_encoded)
    print(f"Base64: {base64_encoded}")
    print(f"Base64 проверка: {base64_decoded == test_data}")
    
    base32_encoded = CryptoUtils.base32_encode(test_data)
    base32_decoded = CryptoUtils.base32_decode(base32_encoded)
    print(f"Base32: {base32_encoded}")
    print(f"Base32 проверка: {base32_decoded == test_data}")
    
    # Генерация ключа из пароля
    password = "SuperSecretPassword123"
    key = CryptoUtils.generate_key_from_password(password)
    print(f"Ключ из пароля: {key.hex()[:16]}...") 