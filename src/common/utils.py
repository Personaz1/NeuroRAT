import random
import time
import socket
import logging


def jitter_sleep(interval: float, jitter: float) -> None:
    '''Случайная задержка: interval ± interval*jitter'''  
    jitter_value = interval * jitter * random.uniform(-1, 1)
    time.sleep(interval + jitter_value)


def resolve_hostname(hostname: str, fallback: str = '127.0.0.1') -> str:
    '''Разрешает имя хоста в IP-адрес, возвращает fallback при ошибке'''  
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        get_logger(__name__).warning(f"Не удалось разрешить имя хоста: {hostname}")
        return fallback


def get_logger(name: str) -> logging.Logger:
    '''Возвращает настроенный логгер с консольным хендлером и базовым форматом'''  
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s [%(levelname)s]: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger 