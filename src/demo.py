#!/usr/bin/env python3
"""
NeuroRAT Demo - Демонстрация возможностей PolyMorpher и SteganoManager
"""

import os
import sys
import time
import random
import argparse
import logging
import tempfile
from typing import Dict, List, Any, Optional

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Добавляем текущую директорию в путь для импорта модулей
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Импортируем наши модули
from modules.poly_morpher import PolyMorpher
from modules.steganography import SteganoManager

def demo_polymorphism():
    """Демонстрация возможностей полиморфной трансформации кода"""
    print("\n[+] Демонстрация полиморфной трансформации кода")
    print("=" * 60)
    
    # Создаем экземпляр PolyMorpher
    morpher = PolyMorpher()
    print(f"[*] PolyMorpher инициализирован (ID: {morpher.current_iteration['id']})")
    
    # Создаем простой тестовый код
    test_code = '''
def calculate_fibonacci(n):
    """Calculates the Fibonacci sequence up to n numbers"""
    result = []
    a, b = 0, 1
    for _ in range(n):
        result.append(a)
        a, b = b, a + b
    return result

def print_sequence(sequence, message="Sequence:"):
    """Prints a sequence with a message"""
    print(f"{message} {', '.join(map(str, sequence))}")

# Calculate Fibonacci
fib_sequence = calculate_fibonacci(10)
print_sequence(fib_sequence, "Fibonacci sequence:")
    '''
    
    # Выводим исходный код
    print("\n[*] Исходный код:")
    print("-" * 60)
    print(test_code)
    
    # Трансформируем код
    transformed_code = morpher._transform_code(test_code)
    
    # Выводим трансформированный код
    print("\n[*] Трансформированный код:")
    print("-" * 60)
    print(transformed_code)
    
    # Создаем временные файлы для тестирования
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
        orig_file = f.name
        f.write(test_code)
    
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
        trans_file = f.name
        f.write(transformed_code)
    
    # Выполняем оба файла
    print("\n[*] Выполнение исходного кода:")
    print("-" * 60)
    os.system(f"{sys.executable} {orig_file}")
    
    print("\n[*] Выполнение трансформированного кода:")
    print("-" * 60)
    os.system(f"{sys.executable} {trans_file}")
    
    # Удаляем временные файлы
    os.unlink(orig_file)
    os.unlink(trans_file)
    
    print("\n[+] Демонстрация полиморфизма завершена")

def demo_steganography(image_path: str = None):
    """Демонстрация возможностей стеганографии"""
    print("\n[+] Демонстрация стеганографии")
    print("=" * 60)
    
    # Создаем экземпляр SteganoManager
    stegano = SteganoManager()
    print("[*] SteganoManager инициализирован")
    
    # Список поддерживаемых методов
    print("\n[*] Поддерживаемые методы стеганографии:")
    for method, (supported, description) in stegano.supported_methods.items():
        status = "✓" if supported else "✗"
        print(f"  {status} {method}: {description}")
    
    # Создаем временную директорию для файлов
    temp_dir = tempfile.mkdtemp(prefix="stegano_demo_")
    print(f"\n[*] Временная директория: {temp_dir}")
    
    # Если изображение не указано, создаем его
    if not image_path or not os.path.exists(image_path):
        # Проверяем наличие PIL
        try:
            from PIL import Image
            import numpy as np
            
            print("[*] Создаем тестовое изображение...")
            width, height = 800, 600
            img_array = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
            img = Image.fromarray(img_array)
            
            # Сохраняем изображение
            image_path = os.path.join(temp_dir, "test_image.png")
            img.save(image_path)
            print(f"[*] Создано тестовое изображение: {image_path}")
        except ImportError:
            print("[!] Ошибка: PIL/Pillow не установлен. Невозможно создать тестовое изображение.")
            return
    
    # Создаем тестовые данные для скрытия
    secret_data = b"This is a secret message that will be hidden inside the image. " + \
                  b"NeuroRAT uses steganography to hide data and establish covert communication channels."
    
    print(f"\n[*] Данные для скрытия ({len(secret_data)} байт):")
    print(secret_data.decode())
    
    # Скрываем данные в изображении
    try:
        # Пробуем разные методы
        for method in ["metadata", "lsb_image", "eof"]:
            if method not in stegano.supported_methods:
                continue
                
            supported, _ = stegano.supported_methods[method]
            if not supported:
                continue
            
            print(f"\n[*] Скрытие данных методом {method}...")
            output_file = os.path.join(temp_dir, f"output_{method}.png")
            
            result_file = stegano.hide_data(
                method=method,
                data=secret_data,
                carrier_file=image_path,
                output_file=output_file
            )
            
            print(f"[*] Данные скрыты в файле: {result_file}")
            
            # Извлекаем данные
            print(f"[*] Извлечение данных методом {method}...")
            extracted_data = stegano.extract_data(
                method=method,
                carrier_file=result_file
            )
            
            print(f"[*] Извлеченные данные ({len(extracted_data)} байт):")
            print(extracted_data.decode())
            
            # Проверяем, что данные совпадают
            if extracted_data == secret_data:
                print("[✓] Данные совпадают!")
            else:
                print("[✗] Данные не совпадают!")
    
    except Exception as e:
        print(f"[!] Ошибка: {e}")
    
    print("\n[+] Демонстрация стеганографии завершена")
    print(f"[*] Временные файлы находятся в: {temp_dir}")

def demo_payload_delivery():
    """Демонстрация доставки полезной нагрузки через полиморфную трансформацию"""
    print("\n[+] Демонстрация доставки полезной нагрузки")
    print("=" * 60)
    
    # Создаем экземпляры наших классов
    morpher = PolyMorpher()
    
    # Создаем полезную нагрузку (безвредную)
    payload = '''
import platform
import socket
import datetime
import random

def get_system_info():
    """Собирает базовую информацию о системе"""
    info = {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "platform_release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "hostname": socket.gethostname(),
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "random_id": random.randint(1000, 9999)
    }
    return info

def display_info(info):
    """Выводит информацию на экран"""
    print("\\n" + "=" * 40)
    print(" SYSTEM INFORMATION REPORT")
    print("=" * 40)
    
    for key, value in info.items():
        print(f"{key.ljust(20)}: {value}")
    
    print("=" * 40)
    print("Report generated for demonstration purposes")
    print("=" * 40)

# Основная функция
def main():
    info = get_system_info()
    display_info(info)

if __name__ == "__main__":
    main()
'''
    
    print("[*] Создана безопасная полезная нагрузка для демонстрации")
    
    # Мутируем полезную нагрузку
    print("[*] Применяем полиморфную трансформацию...")
    
    # Сохраняем оригинальную нагрузку
    temp_dir = tempfile.mkdtemp(prefix="payload_demo_")
    orig_path = os.path.join(temp_dir, "original_payload.py")
    
    with open(orig_path, 'w') as f:
        f.write(payload)
    
    # Трансформируем
    transformed_path = morpher.transform_module(orig_path)
    
    print(f"[*] Оригинальная нагрузка: {orig_path}")
    print(f"[*] Трансформированная нагрузка: {transformed_path}")
    
    # Выполняем оба файла
    print("\n[*] Выполнение оригинальной нагрузки:")
    print("-" * 60)
    os.system(f"{sys.executable} {orig_path}")
    
    print("\n[*] Выполнение трансформированной нагрузки:")
    print("-" * 60)
    os.system(f"{sys.executable} {transformed_path}")
    
    print("\n[+] Демонстрация доставки полезной нагрузки завершена")
    print(f"[*] Временные файлы находятся в: {temp_dir}")

def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(description="NeuroRAT Demo")
    parser.add_argument("--polymorphism", action="store_true", help="Демонстрация полиморфной трансформации кода")
    parser.add_argument("--steganography", action="store_true", help="Демонстрация стеганографии")
    parser.add_argument("--payload", action="store_true", help="Демонстрация доставки полезной нагрузки")
    parser.add_argument("--image", help="Путь к изображению для стеганографии")
    parser.add_argument("--all", action="store_true", help="Выполнить все демонстрации")
    
    args = parser.parse_args()
    
    # Если не указаны аргументы, выполняем все демонстрации
    if not (args.polymorphism or args.steganography or args.payload or args.all):
        args.all = True
    
    print("\n" + "=" * 60)
    print("NeuroRAT - Демонстрация возможностей")
    print("=" * 60)
    
    if args.polymorphism or args.all:
        demo_polymorphism()
    
    if args.steganography or args.all:
        demo_steganography(args.image)
    
    if args.payload or args.all:
        demo_payload_delivery()
    
    print("\n" + "=" * 60)
    print("Демонстрация завершена")
    print("=" * 60)

if __name__ == "__main__":
    main() 