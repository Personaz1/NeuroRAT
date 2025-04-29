#!/usr/bin/env python3
import base64
import string

# Тестируемый чанк
chunk = 'kbeu4rzamzzg63jajzsxk4tpkjavii'
print(f'Chunk: {chunk}')
print(f'Length: {len(chunk)}')

# Проверка на соответствие алфавиту Base32
base32_alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
print("\nChecking each character:")
invalid_chars = []
for i, char in enumerate(chunk.upper()):
    if char not in base32_alphabet:
        print(f"Invalid character at position {i}: '{char}'")
        invalid_chars.append((i, char))

if not invalid_chars:
    print("All characters are valid Base32 characters")
else:
    print(f"Invalid characters found: {invalid_chars}")

# Проверяем последний фрагмент детально
last_fragment = chunk[24:].upper()  # KJAVII
print(f"\nДетальная проверка последнего фрагмента: {last_fragment}")
print(f"Длина: {len(last_fragment)}")

# В Base32 кодирование соотношения количества символов к количеству паддингов:
# 2 символа -> 6 паддингов (======)
# 4 символа -> 4 паддинга (====)
# 5 символов -> 3 паддинга (===)
# 7 символов -> 1 паддинг (=)
# 8 символов -> 0 паддингов

# Определяем правильный паддинг по длине фрагмента
padding_map = {2: 6, 4: 4, 5: 3, 7: 1, 8: 0}
if len(last_fragment) in padding_map:
    correct_padding = "=" * padding_map[len(last_fragment)]
    print(f"Правильный паддинг для {len(last_fragment)} символов: {correct_padding}")
    padded = last_fragment + correct_padding
    print(f"Строка с паддингом: {padded}")
    try:
        decoded = base64.b32decode(padded)
        print(f"✓ Успешно декодировано: {decoded}")
        print(f"Как строка: {decoded.decode('utf-8', errors='replace')}")
    except Exception as e:
        print(f"✗ Ошибка: {e}")
else:
    print(f"Для фрагмента длины {len(last_fragment)} нет стандартного паддинга в Base32")
    
    # Пробуем все возможные варианты паддинга
    print("Пробуем все варианты паддинга:")
    for padding in range(0, 8):
        padded = last_fragment + ("=" * padding)
        try:
            decoded = base64.b32decode(padded)
            print(f"  ✓ С паддингом {padding}: {decoded}")
            print(f"    Как строка: {decoded.decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"  ✗ С паддингом {padding}: {e}")

# Проверка возможной ошибки в самом фрагменте
print("\nПроверка на недостающие или лишние символы:")
# Базовый алфавит Base32
base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# Для длины 6 подходящие варианты с паддингом "=="
print("Возможные 6-символьные комбинации с правильным паддингом:")
for i in range(len(base32_chars)):
    # Пробуем добавить один символ в конец
    test_str = last_fragment + base32_chars[i]
    padded = test_str + "="
    try:
        decoded = base64.b32decode(padded)
        print(f"  ✓ {test_str}=: {decoded}")
        print(f"    Как строка: {decoded.decode('utf-8', errors='replace')}")
    except:
        pass
    
    # Пробуем заменить последний символ
    if len(last_fragment) > 0:
        test_str = last_fragment[:-1] + base32_chars[i]
        padded = test_str + "=="
        try:
            decoded = base64.b32decode(padded)
            print(f"  ✓ {test_str}==: {decoded}")
            print(f"    Как строка: {decoded.decode('utf-8', errors='replace')}")
        except:
            pass

# Соберем полную строку из правильно декодированных фрагментов
print("\nПопытка собрать полное сообщение из декодированных фрагментов:")
try:
    message = ""
    message += base64.b32decode(chunk[0:8].upper()).decode('utf-8')  # KBEU4RZA -> PING 
    message += base64.b32decode(chunk[8:16].upper()).decode('utf-8')  # MZZG63JA -> from 
    message += base64.b32decode(chunk[16:24].upper()).decode('utf-8')  # JZSXK4TP -> Neuro
    # Последний фрагмент не декодируется правильно, поэтому добавим многоточие
    print(f"Частично собранное сообщение: '{message}...'")
except Exception as e:
    print(f"Ошибка при сборке сообщения: {e}")

# Проверим для сравнения известный валидный base32
print("\nTest with known good base32:")
good_b32 = "MZXW6YTBOI======"  # Это "foobar" в base32
try:
    decoded = base64.b32decode(good_b32)
    print(f'Good base32 decoded: {decoded}')
    print(f'Decoded as string: {decoded.decode("utf-8")}')
except Exception as e:
    print(f'Error: {e}') 