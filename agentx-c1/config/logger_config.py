import logging
import sys

# Основная конфигурация логирования для проекта C1
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Создаём форматтер
formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

# Настройка корневого логгера
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

# Консольный обработчик
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)
root_logger.addHandler(console_handler)

# Файловый обработчик (ротация ежедневная)
from logging.handlers import TimedRotatingFileHandler
log_file = 'c1_brain.log'
file_handler = TimedRotatingFileHandler(log_file, when='midnight', backupCount=7, encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)
root_logger.addHandler(file_handler)

# Обработчик исключений по умолчанию
def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    root_logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

# Перехватываем неотловленные исключения
sys.excepthook = handle_exception 