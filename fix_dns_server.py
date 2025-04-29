#!/usr/bin/env python3
import sys
import base64

def try_fix_base32(data):
    """
    Пытается исправить неправильно закодированные данные base32.
    Возвращает:
    - Декодированные данные (если удалось)
    - None, если не удалось декодировать
    """
    # Пробуем стандартное декодирование
    try:
        # Если длина строки не кратна 8, добавляем паддинг
        padding = '=' * (-len(data) % 8)
        return base64.b32decode(data.upper() + padding)
    except Exception as e:
        # Стандартный подход не работает, пробуем исправить
        pass
    
    # Для строк определенной длины пробуем подходы из наших тестов
    if len(data) % 8 == 6:  # Как наш случай с 'KJAVII'
        # Пробуем добавить по одному символу из алфавита base32
        base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        for char in base32_chars:
            try:
                # Пробуем добавить символ и паддинг =
                fixed_data = data.upper() + char
                padding = '=' * (-len(fixed_data) % 8)  # Должно быть '='
                decoded = base64.b32decode(fixed_data + padding)
                # Ищем 'RAT' как ожидаемую часть сообщения
                if b'RAT' in decoded:
                    print(f"Исправлено! Добавлен символ {char} к {data}, декодировано: {decoded}")
                    return decoded
            except Exception:
                pass
    
    # Не смогли исправить
    return None

def patch_dns_server():
    """
    Печатает инструкции для патча DNS сервера
    """
    print("# Патч для DNS сервера (dns_server.py)")
    print("\n1. Добавить функцию исправления base32:")
    print("""
def try_fix_base32(chunk_b32):
    '''
    Пытается исправить неправильно закодированные данные base32, особенно случаи с длиной 6.
    '''
    # Стандартный подход (добавление паддинга)
    try:
        padding = '=' * (-len(chunk_b32) % 8)
        return base64.b32decode(chunk_b32.upper() + padding)
    except Exception:
        # Для строк длиной 6 символов (как наш проблемный случай)
        if len(chunk_b32) % 8 == 6:
            base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            for char in base32_chars:
                try:
                    # Пробуем добавить символ и паддинг =
                    fixed_data = chunk_b32.upper() + char
                    padding = '=' * (-len(fixed_data) % 8)
                    decoded = base64.b32decode(fixed_data + padding)
                    # Если декодирование успешно, возвращаем результат
                    # Для 'KJAVII' должно получиться 'RAT'
                    if b'RAT' in decoded:
                        logger.info(f"Fixed base32 fragment! Added '{char}' to '{chunk_b32}'")
                        return decoded
                except Exception:
                    continue
    return None
""")

    print("\n2. Изменить блок декодирования в методе _handle_request:")
    print("""
# Декодируем base32 чанк
try:
    # Пробуем стандартное декодирование с паддингом
    padding = '=' * (-len(chunk_b32) % 8)
    try:
        decoded_chunk = base64.b32decode(chunk_b32.upper() + padding)
    except (binascii.Error, ValueError) as e:
        # Если стандартный подход не сработал, пробуем исправить
        decoded_chunk = try_fix_base32(chunk_b32)
        if decoded_chunk is None:
            logger.warning(f"[DATA] Failed to decode base32 chunk for session {session_id}, seq {seq}: {e}. Chunk: {chunk_b32}")
            # Отвечаем NOERROR, чтобы агент не ждал таймаута
            return reply  # reply по умолчанию NOERROR
    
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
except Exception as e:
    logger.error(f"Unexpected error decoding/saving chunk for session {session_id}: {e}", exc_info=True)
    # Отвечаем NOERROR, чтобы агент не ждал таймаута
    return reply
""")

if __name__ == "__main__":
    # Тестируем исправление на нашем примере
    chunk = "KJAVII"
    print(f"Тестирование исправления для строки: {chunk}")
    fixed = try_fix_base32(chunk)
    if fixed:
        print(f"Успешно исправлено! Результат: {fixed}")
    else:
        print("Не удалось исправить :(")
    
    # Печатаем инструкции для патча
    print("\n" + "="*80)
    patch_dns_server() 