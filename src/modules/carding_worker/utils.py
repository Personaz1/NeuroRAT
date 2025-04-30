# Утилиты для carding_worker: шифрование, генерация ключей и др.

from cryptography.fernet import Fernet


def generate_key():
    return Fernet.generate_key()


def encrypt_data(key, data: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_data(key, token: bytes) -> bytes:
    f = Fernet(key)
    return f.decrypt(token) 