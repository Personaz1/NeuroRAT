#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Steganography: Модуль для скрытия данных в изображениях.

Этот модуль предоставляет функциональность для внедрения данных в изображения
и последующего извлечения этих данных. Использует методы стеганографии
для скрытия информации в визуальном контенте без видимых изменений.
"""

import os
import sys
import base64
import json
import random
import struct
import zlib
import io
import numpy as np
from typing import Tuple, Dict, List, Union, Optional, Any, BinaryIO
from PIL import Image


class Steganography:
    """Класс для работы со стеганографией в изображениях."""
    
    def __init__(self, encryption_key: Optional[str] = None, compression: bool = True):
        """
        Инициализация модуля стеганографии.
        
        Args:
            encryption_key: Ключ для дополнительного шифрования данных (опционально).
            compression: Использовать сжатие данных перед внедрением.
        """
        self.compression = compression
        self.encryption_key = encryption_key
        
    def hide_data(self, image_path: str, data: Union[str, bytes], 
                  output_path: Optional[str] = None, method: str = 'lsb') -> str:
        """
        Скрывает данные в изображении.
        
        Args:
            image_path: Путь к исходному изображению.
            data: Данные для скрытия (строка или байты).
            output_path: Путь для сохранения изображения с внедренными данными.
                        Если None, генерируется путь на основе исходного.
            method: Метод стеганографии ('lsb', 'dct', 'metadata').
            
        Returns:
            Путь к изображению с внедренными данными.
        """
        # Преобразуем строку в байты, если необходимо
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Подготавливаем данные (сжатие, шифрование)
        prepared_data = self._prepare_data(data)
        
        # Открываем изображение
        img = Image.open(image_path)
        
        # Выбираем метод внедрения
        if method == 'lsb':
            stego_img = self._hide_lsb(img, prepared_data)
        elif method == 'metadata':
            stego_img = self._hide_metadata(img, prepared_data)
        else:
            raise ValueError(f"Неподдерживаемый метод стеганографии: {method}")
        
        # Если путь вывода не указан, создаем его
        if output_path is None:
            directory, filename = os.path.split(image_path)
            name, ext = os.path.splitext(filename)
            output_path = os.path.join(directory, f"{name}_stego{ext}")
        
        # Сохраняем изображение
        stego_img.save(output_path)
        return output_path
        
    def extract_data(self, stego_image_path: str, method: str = 'lsb') -> bytes:
        """
        Извлекает скрытые данные из изображения.
        
        Args:
            stego_image_path: Путь к изображению с внедренными данными.
            method: Метод стеганографии ('lsb', 'dct', 'metadata').
            
        Returns:
            Извлеченные данные в виде байтов.
        """
        # Открываем изображение
        img = Image.open(stego_image_path)
        
        # Выбираем метод извлечения
        if method == 'lsb':
            raw_data = self._extract_lsb(img)
        elif method == 'metadata':
            raw_data = self._extract_metadata(img)
        else:
            raise ValueError(f"Неподдерживаемый метод стеганографии: {method}")
        
        # Распаковываем данные (расшифровка, распаковка)
        return self._process_extracted_data(raw_data)
    
    def _prepare_data(self, data: bytes) -> bytes:
        """
        Подготавливает данные перед внедрением (сжатие, шифрование).
        
        Args:
            data: Исходные данные.
            
        Returns:
            Подготовленные данные.
        """
        # Сжимаем, если включено сжатие
        if self.compression:
            data = zlib.compress(data)
        
        # Шифруем, если указан ключ
        if self.encryption_key:
            data = self._encrypt(data, self.encryption_key)
        
        # Добавляем размер в начало данных
        data_size = len(data)
        header = struct.pack('!I', data_size)
        return header + data
    
    def _process_extracted_data(self, raw_data: bytes) -> bytes:
        """
        Обрабатывает извлеченные данные (расшифровка, распаковка).
        
        Args:
            raw_data: Извлеченные сырые данные.
            
        Returns:
            Обработанные данные.
        """
        # Извлекаем размер из заголовка
        size = struct.unpack('!I', raw_data[:4])[0]
        
        # Проверяем, соответствует ли размер ожидаемому
        if len(raw_data) - 4 < size:
            raise ValueError("Извлеченные данные повреждены")
        
        # Извлекаем данные
        data = raw_data[4:4+size]
        
        # Расшифровываем, если указан ключ
        if self.encryption_key:
            data = self._decrypt(data, self.encryption_key)
        
        # Распаковываем, если включено сжатие
        if self.compression:
            try:
                data = zlib.decompress(data)
            except zlib.error:
                raise ValueError("Не удалось распаковать данные")
        
        return data
    
    def _encrypt(self, data: bytes, key: str) -> bytes:
        """
        Шифрует данные с помощью XOR.
        
        Args:
            data: Данные для шифрования.
            key: Ключ шифрования.
            
        Returns:
            Зашифрованные данные.
        """
        key_bytes = key.encode('utf-8')
        key_length = len(key_bytes)
        encrypted = bytearray(len(data))
        
        for i in range(len(data)):
            encrypted[i] = data[i] ^ key_bytes[i % key_length]
        
        return bytes(encrypted)
    
    def _decrypt(self, data: bytes, key: str) -> bytes:
        """
        Дешифрует данные с помощью XOR (для XOR шифрования шифрование = дешифрованию).
        
        Args:
            data: Зашифрованные данные.
            key: Ключ шифрования.
            
        Returns:
            Дешифрованные данные.
        """
        return self._encrypt(data, key)
    
    def _hide_lsb(self, image: Image.Image, data: bytes) -> Image.Image:
        """
        Скрывает данные в наименее значимых битах изображения.
        
        Args:
            image: Исходное изображение.
            data: Данные для скрытия.
            
        Returns:
            Изображение с внедренными данными.
        """
        # Преобразуем изображение в массив
        img_array = np.array(image)
        
        # Проверяем, достаточно ли места для данных
        max_bytes = img_array.size // 8
        if len(data) > max_bytes:
            raise ValueError(f"Данные слишком велики для этого изображения. "
                            f"Максимальный размер: {max_bytes} байт")
        
        # Преобразуем данные в биты
        data_bits = ''.join(format(byte, '08b') for byte in data)
        data_bits_len = len(data_bits)
        
        # Внедряем биты в массив
        index = 0
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                for k in range(min(3, img_array.shape[2])):  # Используем только RGB каналы
                    if index < data_bits_len:
                        # Заменяем младший бит пикселя на бит данных
                        img_array[i, j, k] = (img_array[i, j, k] & 0xFE) | int(data_bits[index])
                        index += 1
                    else:
                        break
                if index >= data_bits_len:
                    break
            if index >= data_bits_len:
                break
        
        # Создаем новое изображение из массива
        return Image.fromarray(img_array)
    
    def _extract_lsb(self, image: Image.Image) -> bytes:
        """
        Извлекает данные из наименее значимых битов изображения.
        
        Args:
            image: Изображение с внедренными данными.
            
        Returns:
            Извлеченные данные.
        """
        # Преобразуем изображение в массив
        img_array = np.array(image)
        
        # Извлекаем биты из массива
        extracted_bits = []
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                for k in range(min(3, img_array.shape[2])):  # Используем только RGB каналы
                    extracted_bits.append(str(img_array[i, j, k] & 1))
        
        # Преобразуем биты в байты
        extracted_bits_str = ''.join(extracted_bits)
        
        # Сначала получаем размер данных из первых 32 бит (4 байта)
        if len(extracted_bits_str) < 32:
            raise ValueError("Изображение не содержит внедренных данных")
        
        header_bytes = int(extracted_bits_str[:32], 2).to_bytes(4, byteorder='big')
        data_size = struct.unpack('!I', header_bytes)[0]
        
        # Проверяем, достаточно ли бит для данных указанного размера
        total_bits_needed = 32 + data_size * 8
        if len(extracted_bits_str) < total_bits_needed:
            raise ValueError("Недостаточно данных в изображении")
        
        # Извлекаем данные
        data_bits = extracted_bits_str[32:total_bits_needed]
        
        # Преобразуем биты в байты
        extracted_bytes = bytearray()
        for i in range(0, len(data_bits), 8):
            byte_bits = data_bits[i:i+8]
            if len(byte_bits) == 8:  # Проверяем, что у нас есть полный байт
                extracted_bytes.append(int(byte_bits, 2))
        
        return header_bytes + bytes(extracted_bytes)
    
    def _hide_metadata(self, image: Image.Image, data: bytes) -> Image.Image:
        """
        Скрывает данные в метаданных изображения.
        
        Args:
            image: Исходное изображение.
            data: Данные для скрытия.
            
        Returns:
            Изображение с внедренными данными.
        """
        # Создаем копию изображения
        stego_img = image.copy()
        
        # Кодируем данные в Base64
        encoded_data = base64.b64encode(data).decode('ascii')
        
        # Сохраняем данные в EXIF
        exif_data = stego_img.getexif() if hasattr(stego_img, 'getexif') else {}
        
        # Используем тег UserComment (0x9286) для хранения данных
        exif_data[0x9286] = encoded_data
        
        # Сохраняем EXIF в изображение
        if hasattr(stego_img, 'save'):
            # Для PIL >= 7.0.0
            stego_img.save(io.BytesIO(), format=stego_img.format, exif=exif_data)
        else:
            # Для более старых версий PIL
            stego_img.info['exif'] = exif_data
        
        return stego_img
    
    def _extract_metadata(self, image: Image.Image) -> bytes:
        """
        Извлекает данные из метаданных изображения.
        
        Args:
            image: Изображение с внедренными данными.
            
        Returns:
            Извлеченные данные.
        """
        # Получаем EXIF данные
        exif_data = image.getexif() if hasattr(image, 'getexif') else {}
        
        # Извлекаем данные из тега UserComment
        encoded_data = exif_data.get(0x9286)
        if not encoded_data:
            raise ValueError("Метаданные не содержат внедренных данных")
        
        # Декодируем из Base64
        try:
            return base64.b64decode(encoded_data)
        except:
            raise ValueError("Не удалось декодировать данные из метаданных")
    
    def capacity(self, image_path: str, method: str = 'lsb') -> int:
        """
        Определяет максимальный размер данных, которые можно скрыть в изображении.
        
        Args:
            image_path: Путь к изображению.
            method: Метод стеганографии ('lsb', 'dct', 'metadata').
            
        Returns:
            Максимальный размер данных в байтах.
        """
        img = Image.open(image_path)
        
        if method == 'lsb':
            # Для LSB: 1 бит на канал RGB, за вычетом 32 бит на заголовок
            return (img.width * img.height * 3) // 8 - 4
        elif method == 'metadata':
            # Для метаданных: примерное значение, зависит от формата
            return 1024  # Примерное значение для JPEG
        else:
            raise ValueError(f"Неподдерживаемый метод стеганографии: {method}")


# Пример использования, если файл запущен напрямую
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Простой инструмент стеганографии')
    parser.add_argument('--hide', action='store_true', help='Скрыть данные в изображении')
    parser.add_argument('--extract', action='store_true', help='Извлечь данные из изображения')
    parser.add_argument('--capacity', action='store_true', help='Показать емкость изображения')
    parser.add_argument('--image', type=str, required=True, help='Путь к изображению')
    parser.add_argument('--data', type=str, help='Данные для скрытия или файл с данными')
    parser.add_argument('--output', type=str, help='Путь для сохранения результата')
    parser.add_argument('--method', type=str, default='lsb', choices=['lsb', 'metadata'], 
                        help='Метод стеганографии')
    parser.add_argument('--key', type=str, help='Ключ шифрования (опционально)')
    parser.add_argument('--no-compress', action='store_true', help='Отключить сжатие')
    
    args = parser.parse_args()
    
    stego = Steganography(encryption_key=args.key, compression=not args.no_compress)
    
    if args.capacity:
        print(f"Максимальный размер данных: {stego.capacity(args.image, args.method)} байт")
        sys.exit(0)
    
    if args.hide:
        if not args.data:
            parser.error("Для скрытия необходимо указать данные (--data)")
        
        # Проверяем, является ли data путем к файлу
        if os.path.isfile(args.data):
            with open(args.data, 'rb') as f:
                data = f.read()
        else:
            data = args.data
        
        output_path = stego.hide_data(args.image, data, args.output, args.method)
        print(f"Данные успешно скрыты в {output_path}")
    
    elif args.extract:
        extracted = stego.extract_data(args.image, args.method)
        
        # Определяем, текстовые это данные или бинарные
        try:
            text = extracted.decode('utf-8')
            is_text = True
        except UnicodeDecodeError:
            is_text = False
        
        if args.output:
            # Сохраняем в файл
            with open(args.output, 'wb') as f:
                f.write(extracted)
            print(f"Извлеченные данные сохранены в {args.output}")
        else:
            # Выводим в консоль, если это текст
            if is_text:
                print("Извлеченный текст:")
                print(text)
            else:
                print(f"Извлечено {len(extracted)} байт бинарных данных")
                print("Используйте --output для сохранения в файл") 