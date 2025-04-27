#!/usr/bin/env python3
"""
Steganography - Модуль для скрытия данных в изображениях, аудио и других типах файлов
Позволяет создавать скрытые каналы связи через обычные файлы
"""

import os
import sys
import zlib
import base64
import random
import struct
from common.utils import get_logger
import logging
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Union, BinaryIO

# Пытаемся импортировать основные модули стеганографии
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import wave
    HAS_WAVE = True
except ImportError:
    HAS_WAVE = False

class SteganoManager:
    """
    Базовый класс для управления различными типами стеганографии
    """
    
    # Доступные методы стеганографии
    METHOD_LSB_IMAGE = "lsb_image"  # Метод наименее значащего бита для изображений
    METHOD_LSB_AUDIO = "lsb_audio"  # Метод наименее значащего бита для аудио
    METHOD_METADATA = "metadata"    # Скрытие в метаданных файлов
    METHOD_EOF = "eof"             # Скрытие после маркера EOF
    
    def __init__(self, log_level: str = "INFO"):
        """
        Инициализация SteganoManager
        
        Args:
            log_level: Уровень логирования
        """
        self.logger = get_logger("steganography")
        self.logger.setLevel(getattr(logging, log_level, logging.INFO))
        
        # Проверяем наличие необходимых модулей
        self._check_dependencies()
        
        # Словарь поддерживаемых методов и функций
        self.supported_methods = self._get_supported_methods()
        
        self.logger.info(f"SteganoManager инициализирован. Доступно методов: {len(self.supported_methods)}")
    
    def _check_dependencies(self) -> None:
        """Проверяет наличие необходимых зависимостей и логирует результаты"""
        dependencies = {
            "PIL (Pillow)": HAS_PIL,
            "NumPy": HAS_NUMPY,
            "wave": HAS_WAVE
        }
        
        for name, available in dependencies.items():
            status = "доступен" if available else "НЕ доступен"
            self.logger.info(f"Модуль {name}: {status}")
    
    def _get_supported_methods(self) -> Dict[str, Tuple[bool, str]]:
        """
        Определяет поддерживаемые методы стеганографии
        
        Returns:
            Dict: Словарь с методами и их статусом доступности
        """
        methods = {
            self.METHOD_LSB_IMAGE: (HAS_PIL and HAS_NUMPY, "Скрытие данных в наименее значащих битах изображений"),
            self.METHOD_LSB_AUDIO: (HAS_WAVE and HAS_NUMPY, "Скрытие данных в наименее значащих битах аудио"),
            self.METHOD_METADATA: (True, "Скрытие данных в метаданных файлов"),
            self.METHOD_EOF: (True, "Скрытие данных после маркера конца файла")
        }
        return methods
    
    def hide_data(self, method: str, data: bytes, carrier_file: str, output_file: str = None, 
                  password: str = None, **kwargs) -> str:
        """
        Скрывает данные в файле-носителе
        
        Args:
            method: Метод стеганографии
            data: Данные для скрытия
            carrier_file: Путь к файлу-носителю
            output_file: Путь для сохранения результата (если None, создается автоматически)
            password: Пароль для дополнительного шифрования (опционально)
            **kwargs: Дополнительные параметры для конкретного метода
            
        Returns:
            str: Путь к файлу с скрытыми данными
        """
        # Проверяем поддержку выбранного метода
        if method not in self.supported_methods:
            raise ValueError(f"Метод {method} не поддерживается")
        
        supported, description = self.supported_methods[method]
        if not supported:
            raise RuntimeError(f"Метод {method} требует отсутствующих зависимостей")
        
        # Проверяем наличие файла-носителя
        if not os.path.exists(carrier_file):
            raise FileNotFoundError(f"Файл-носитель не найден: {carrier_file}")
        
        # Если выходной файл не указан, создаем автоматически
        if not output_file:
            base, ext = os.path.splitext(carrier_file)
            output_file = f"{base}_steg{ext}"
        
        # Предварительно подготавливаем данные (сжатие, шифрование)
        processed_data = self._preprocess_data(data, password)
        
        # Вызываем соответствующий метод стеганографии
        if method == self.METHOD_LSB_IMAGE:
            result = self._hide_in_image_lsb(processed_data, carrier_file, output_file, **kwargs)
        elif method == self.METHOD_LSB_AUDIO:
            result = self._hide_in_audio_lsb(processed_data, carrier_file, output_file, **kwargs)
        elif method == self.METHOD_METADATA:
            result = self._hide_in_metadata(processed_data, carrier_file, output_file, **kwargs)
        elif method == self.METHOD_EOF:
            result = self._hide_in_eof(processed_data, carrier_file, output_file, **kwargs)
        else:
            raise ValueError(f"Неизвестный метод: {method}")
        
        self.logger.info(f"Данные успешно скрыты в {result} используя метод {method}")
        return result
    
    def extract_data(self, method: str, carrier_file: str, password: str = None, **kwargs) -> bytes:
        """
        Извлекает скрытые данные из файла-носителя
        
        Args:
            method: Метод стеганографии
            carrier_file: Путь к файлу-носителю со скрытыми данными
            password: Пароль для расшифровки (если использовался при скрытии)
            **kwargs: Дополнительные параметры для конкретного метода
            
        Returns:
            bytes: Извлеченные данные
        """
        # Проверяем поддержку выбранного метода
        if method not in self.supported_methods:
            raise ValueError(f"Метод {method} не поддерживается")
        
        supported, description = self.supported_methods[method]
        if not supported:
            raise RuntimeError(f"Метод {method} требует отсутствующих зависимостей")
        
        # Проверяем наличие файла-носителя
        if not os.path.exists(carrier_file):
            raise FileNotFoundError(f"Файл-носитель не найден: {carrier_file}")
        
        # Вызываем соответствующий метод извлечения
        if method == self.METHOD_LSB_IMAGE:
            raw_data = self._extract_from_image_lsb(carrier_file, **kwargs)
        elif method == self.METHOD_LSB_AUDIO:
            raw_data = self._extract_from_audio_lsb(carrier_file, **kwargs)
        elif method == self.METHOD_METADATA:
            raw_data = self._extract_from_metadata(carrier_file, **kwargs)
        elif method == self.METHOD_EOF:
            raw_data = self._extract_from_eof(carrier_file, **kwargs)
        else:
            raise ValueError(f"Неизвестный метод: {method}")
        
        # Постобработка данных (распаковка, расшифровка)
        data = self._postprocess_data(raw_data, password)
        
        self.logger.info(f"Данные успешно извлечены из {carrier_file} используя метод {method}")
        return data
    
    def _preprocess_data(self, data: bytes, password: str = None) -> bytes:
        """
        Предварительная обработка данных перед скрытием
        
        Args:
            data: Исходные данные
            password: Пароль для шифрования
            
        Returns:
            bytes: Обработанные данные
        """
        # Сжимаем данные
        compressed = zlib.compress(data)
        
        # Если указан пароль, шифруем данные
        if password:
            # Простое XOR-шифрование (в реальном приложении использовать AES)
            key = hashlib.sha256(password.encode()).digest()
            encrypted = bytearray(len(compressed))
            for i in range(len(compressed)):
                encrypted[i] = compressed[i] ^ key[i % len(key)]
            
            # Добавляем соль к зашифрованным данным
            salt = os.urandom(8)
            result = salt + bytes(encrypted)
        else:
            result = compressed
        
        # Добавляем сигнатуру и длину данных для проверки целостности
        signature = b'STEG'
        length_bytes = struct.pack('<I', len(result))
        checksum = hashlib.md5(result).digest()
        
        return signature + length_bytes + checksum + result
    
    def _postprocess_data(self, data: bytes, password: str = None) -> bytes:
        """
        Обработка извлеченных данных
        
        Args:
            data: Извлеченные данные
            password: Пароль для расшифровки
            
        Returns:
            bytes: Обработанные данные
        """
        # Проверяем сигнатуру
        if not data.startswith(b'STEG'):
            raise ValueError("Неверная сигнатура данных")
        
        # Извлекаем информацию из заголовка
        header_size = 4 + 4 + 16  # signature + length + checksum
        length_bytes = data[4:8]
        checksum = data[8:24]
        
        payload = data[header_size:]
        
        # Проверяем длину данных
        expected_length = struct.unpack('<I', length_bytes)[0]
        if len(payload) != expected_length:
            raise ValueError(f"Несоответствие длины данных: ожидалось {expected_length}, получено {len(payload)}")
        
        # Проверяем контрольную сумму
        if hashlib.md5(payload).digest() != checksum:
            raise ValueError("Контрольная сумма не соответствует, данные повреждены")
        
        # Если указан пароль, расшифровываем данные
        if password:
            # Извлекаем соль и зашифрованные данные
            salt = payload[:8]
            encrypted = payload[8:]
            
            # Расшифровываем данные
            key = hashlib.sha256(password.encode()).digest()
            decrypted = bytearray(len(encrypted))
            for i in range(len(encrypted)):
                decrypted[i] = encrypted[i] ^ key[i % len(key)]
            
            to_decompress = bytes(decrypted)
        else:
            to_decompress = payload
        
        # Распаковываем данные
        try:
            return zlib.decompress(to_decompress)
        except zlib.error:
            raise ValueError("Ошибка распаковки данных. Возможно, требуется пароль или данные повреждены.")
    
    def _hide_in_eof(self, data: bytes, carrier_file: str, output_file: str, **kwargs) -> str:
        """
        Скрывает данные после маркера конца файла
        
        Args:
            data: Данные для скрытия
            carrier_file: Путь к файлу-носителю
            output_file: Путь для сохранения результата
            
        Returns:
            str: Путь к файлу с скрытыми данными
        """
        try:
            with open(carrier_file, 'rb') as f:
                carrier_data = f.read()
            
            with open(output_file, 'wb') as f:
                f.write(carrier_data)
                f.write(b"\x00STEG_MARKER\x00")  # Маркер начала скрытых данных
                f.write(data)
            
            return output_file
        
        except Exception as e:
            self.logger.error(f"Ошибка при скрытии данных в EOF: {e}")
            raise
    
    def _extract_from_eof(self, carrier_file: str, **kwargs) -> bytes:
        """
        Извлекает данные, скрытые после маркера конца файла
        
        Args:
            carrier_file: Путь к файлу-носителю
            
        Returns:
            bytes: Извлеченные данные
        """
        try:
            with open(carrier_file, 'rb') as f:
                data = f.read()
            
            marker = b"\x00STEG_MARKER\x00"
            pos = data.find(marker)
            
            if pos == -1:
                raise ValueError("Маркер скрытых данных не найден")
            
            hidden_data = data[pos + len(marker):]
            return hidden_data
        
        except Exception as e:
            self.logger.error(f"Ошибка при извлечении данных из EOF: {e}")
            raise
    
    def _hide_in_metadata(self, data: bytes, carrier_file: str, output_file: str, **kwargs) -> str:
        """
        Скрывает данные в метаданных файла
        Реализация зависит от типа файла (изображение, PDF, документ и т.д.)
        
        Args:
            data: Данные для скрытия
            carrier_file: Путь к файлу-носителю
            output_file: Путь для сохранения результата
            
        Returns:
            str: Путь к файлу с скрытыми данными
        """
        if not HAS_PIL:
            raise RuntimeError("Для работы с метаданными изображений требуется PIL (Pillow)")
        
        try:
            # Определяем тип файла по расширению
            ext = os.path.splitext(carrier_file)[1].lower()
            
            if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']:
                # Скрываем в метаданных изображения
                return self._hide_in_image_metadata(data, carrier_file, output_file, **kwargs)
            else:
                # Скрываем в EOF для всех остальных типов файлов
                return self._hide_in_eof(data, carrier_file, output_file)
        
        except Exception as e:
            self.logger.error(f"Ошибка при скрытии данных в метаданных: {e}")
            raise
    
    def _extract_from_metadata(self, carrier_file: str, **kwargs) -> bytes:
        """
        Извлекает данные из метаданных файла
        
        Args:
            carrier_file: Путь к файлу-носителю
            
        Returns:
            bytes: Извлеченные данные
        """
        if not HAS_PIL:
            raise RuntimeError("Для работы с метаданными изображений требуется PIL (Pillow)")
        
        try:
            # Определяем тип файла по расширению
            ext = os.path.splitext(carrier_file)[1].lower()
            
            if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']:
                # Извлекаем из метаданных изображения
                return self._extract_from_image_metadata(carrier_file, **kwargs)
            else:
                # Извлекаем из EOF для всех остальных типов файлов
                return self._extract_from_eof(carrier_file)
        
        except Exception as e:
            self.logger.error(f"Ошибка при извлечении данных из метаданных: {e}")
            raise
    
    def _hide_in_image_lsb(self, data: bytes, carrier_file: str, output_file: str, 
                        bits_per_pixel: int = 1, **kwargs) -> str:
        """
        Скрывает данные в наименее значащих битах изображения
        
        Args:
            data: Данные для скрытия
            carrier_file: Путь к изображению-носителю
            output_file: Путь для сохранения результата
            bits_per_pixel: Количество бит на пиксель для изменения (1-3)
            
        Returns:
            str: Путь к изображению с скрытыми данными
        """
        if not HAS_PIL or not HAS_NUMPY:
            raise RuntimeError("Для скрытия данных в изображении требуются PIL и NumPy")
        
        try:
            # Ограничиваем количество бит до допустимого значения
            bits_per_pixel = min(max(bits_per_pixel, 1), 3)
            
            # Открываем изображение и преобразуем в массив NumPy
            img = Image.open(carrier_file)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img)
            
            # Вычисляем максимальный объем данных, который можно скрыть
            height, width, channels = img_array.shape
            max_bytes = (height * width * channels * bits_per_pixel) // 8
            
            if len(data) > max_bytes:
                raise ValueError(f"Размер данных ({len(data)} байт) превышает доступную емкость ({max_bytes} байт)")
            
            # Конвертируем данные в битовую последовательность
            binary_data = ''.join(format(byte, '08b') for byte in data)
            binary_data += '0' * (8 - (len(binary_data) % 8)) if len(binary_data) % 8 != 0 else ''  # Выравнивание
            
            # Скрываем данные
            data_index = 0
            for h in range(height):
                for w in range(width):
                    for c in range(channels):
                        if data_index < len(binary_data):
                            # Маска для обнуления последних bits_per_pixel битов
                            mask = 0xFF - ((1 << bits_per_pixel) - 1)
                            
                            # Обнуляем последние биты и добавляем новые из данных
                            bits_to_set = 0
                            for b in range(bits_per_pixel):
                                if data_index < len(binary_data):
                                    bits_to_set |= (int(binary_data[data_index]) << b)
                                    data_index += 1
                            
                            img_array[h, w, c] = (img_array[h, w, c] & mask) | bits_to_set
            
            # Сохраняем изображение с скрытыми данными
            output_img = Image.fromarray(img_array)
            output_img.save(output_file)
            
            return output_file
        
        except Exception as e:
            self.logger.error(f"Ошибка при скрытии данных в изображении (LSB): {e}")
            raise
    
    def _extract_from_image_lsb(self, carrier_file: str, bits_per_pixel: int = 1, 
                             data_length: int = None, **kwargs) -> bytes:
        """
        Извлекает данные, скрытые в наименее значащих битах изображения
        
        Args:
            carrier_file: Путь к изображению с скрытыми данными
            bits_per_pixel: Количество бит на пиксель (должно совпадать с значением при скрытии)
            data_length: Длина скрытых данных (в байтах), если известна
            
        Returns:
            bytes: Извлеченные данные
        """
        if not HAS_PIL or not HAS_NUMPY:
            raise RuntimeError("Для извлечения данных из изображения требуются PIL и NumPy")
        
        try:
            # Ограничиваем количество бит до допустимого значения
            bits_per_pixel = min(max(bits_per_pixel, 1), 3)
            
            # Открываем изображение и преобразуем в массив NumPy
            img = Image.open(carrier_file)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img)
            
            # Вычисляем максимальный объем данных, который можно извлечь
            height, width, channels = img_array.shape
            max_bytes = (height * width * channels * bits_per_pixel) // 8
            
            if data_length is not None:
                bytes_to_extract = min(data_length, max_bytes)
            else:
                bytes_to_extract = max_bytes
            
            bits_to_extract = bytes_to_extract * 8
            
            # Извлекаем биты данных
            extracted_bits = ''
            bits_count = 0
            
            for h in range(height):
                for w in range(width):
                    for c in range(channels):
                        if bits_count < bits_to_extract:
                            for b in range(bits_per_pixel):
                                if bits_count < bits_to_extract:
                                    # Извлекаем бит из значения пикселя
                                    extracted_bits += str((img_array[h, w, c] >> b) & 1)
                                    bits_count += 1
            
            # Конвертируем битовую последовательность в байты
            extracted_bytes = bytearray()
            for i in range(0, len(extracted_bits), 8):
                byte = extracted_bits[i:i+8]
                if len(byte) == 8:
                    extracted_bytes.append(int(byte, 2))
            
            # Проверяем сигнатуру 'STEG' (для нашего формата)
            if len(extracted_bytes) > 4 and extracted_bytes[:4] == b'STEG':
                return bytes(extracted_bytes)
            
            # Если сигнатура не найдена, но у нас был указан data_length
            if data_length is not None:
                return bytes(extracted_bytes[:data_length])
            
            # В противном случае пытаемся найти маркер конца данных
            null_byte_pos = 0
            for i in range(len(extracted_bytes) - 4):
                if extracted_bytes[i:i+4] == b'\x00\x00\x00\x00':
                    null_byte_pos = i
                    break
            
            return bytes(extracted_bytes[:null_byte_pos]) if null_byte_pos > 0 else bytes(extracted_bytes)
        
        except Exception as e:
            self.logger.error(f"Ошибка при извлечении данных из изображения (LSB): {e}")
            raise
    
    def _hide_in_image_metadata(self, data: bytes, carrier_file: str, output_file: str, **kwargs) -> str:
        """
        Скрывает данные в метаданных изображения
        
        Args:
            data: Данные для скрытия
            carrier_file: Путь к изображению-носителю
            output_file: Путь для сохранения результата
            
        Returns:
            str: Путь к изображению с скрытыми данными
        """
        if not HAS_PIL:
            raise RuntimeError("Для работы с метаданными изображений требуется PIL (Pillow)")
        
        try:
            # Открываем изображение
            img = Image.open(carrier_file)
            
            # Кодируем данные в base64 для безопасного хранения в строке
            encoded_data = base64.b64encode(data).decode('ascii')
            
            # Скрываем данные в метаданных
            exif_data = img.info.get('exif', b'')
            
            # Создаем или обновляем EXIF-данные
            if HAS_PIL and hasattr(Image, 'Exif'):
                from PIL.ExifTags import TAGS
                
                # Проверяем, есть ли уже EXIF
                exif_dict = {}
                if exif_data:
                    try:
                        exif = Image.Exif()
                        exif.load(exif_data)
                        exif_dict = exif.get_ifd(0x8769)  # Exif IFD
                    except:
                        pass
                else:
                    exif = Image.Exif()
                
                # Скрываем данные в пользовательском комментарии
                # Используем тег 0x9286 - UserComment
                exif_dict[0x9286] = f"STEG{encoded_data}"
                
                # Обновляем или создаем EXIF
                if not exif_data:
                    img.save(output_file, exif=exif.tobytes())
                else:
                    # Если не можем обновить EXIF, сохраняем как есть и используем EOF
                    img.save(output_file)
                    return self._hide_in_eof(data, output_file, output_file)
            else:
                # Если не можем работать с EXIF, используем EOF
                img.save(output_file)
                return self._hide_in_eof(data, output_file, output_file)
            
            return output_file
        
        except Exception as e:
            self.logger.error(f"Ошибка при скрытии данных в метаданных изображения: {e}")
            # Если не удалось скрыть в метаданных, пробуем EOF
            try:
                return self._hide_in_eof(data, carrier_file, output_file)
            except:
                raise
    
    def _extract_from_image_metadata(self, carrier_file: str, **kwargs) -> bytes:
        """
        Извлекает данные из метаданных изображения
        
        Args:
            carrier_file: Путь к изображению с скрытыми данными
            
        Returns:
            bytes: Извлеченные данные
        """
        if not HAS_PIL:
            raise RuntimeError("Для работы с метаданными изображений требуется PIL (Pillow)")
        
        try:
            # Открываем изображение
            img = Image.open(carrier_file)
            
            # Получаем EXIF-данные
            exif_data = img.info.get('exif', b'')
            
            if HAS_PIL and hasattr(Image, 'Exif') and exif_data:
                from PIL.ExifTags import TAGS
                
                try:
                    exif = Image.Exif()
                    exif.load(exif_data)
                    exif_dict = exif.get_ifd(0x8769)  # Exif IFD
                    
                    # Извлекаем данные из пользовательского комментария
                    if 0x9286 in exif_dict:
                        comment = exif_dict[0x9286]
                        if comment.startswith("STEG"):
                            encoded_data = comment[4:]  # Удаляем префикс "STEG"
                            return base64.b64decode(encoded_data)
                except:
                    pass
            
            # Если не удалось извлечь из метаданных, пробуем EOF
            return self._extract_from_eof(carrier_file)
        
        except Exception as e:
            self.logger.error(f"Ошибка при извлечении данных из метаданных изображения: {e}")
            # Если не удалось извлечь из метаданных, пробуем EOF
            try:
                return self._extract_from_eof(carrier_file)
            except:
                raise
    
    def _hide_in_audio_lsb(self, data: bytes, carrier_file: str, output_file: str, 
                        bits_per_sample: int = 1, **kwargs) -> str:
        """
        Скрывает данные в наименее значащих битах аудиофайла WAV
        
        Args:
            data: Данные для скрытия
            carrier_file: Путь к аудио-носителю (WAV)
            output_file: Путь для сохранения результата
            bits_per_sample: Количество бит на сэмпл для изменения (1-4)
            
        Returns:
            str: Путь к аудиофайлу с скрытыми данными
        """
        if not HAS_WAVE or not HAS_NUMPY:
            raise RuntimeError("Для скрытия данных в аудио требуются модули wave и NumPy")
        
        try:
            # Ограничиваем количество бит до допустимого значения
            bits_per_sample = min(max(bits_per_sample, 1), 4)
            
            # Открываем WAV-файл
            with wave.open(carrier_file, 'rb') as wav:
                # Получаем параметры аудио
                n_channels = wav.getnchannels()
                sample_width = wav.getsampwidth()
                n_frames = wav.getnframes()
                framerate = wav.getframerate()
                
                # Читаем все фреймы
                wav_frames = wav.readframes(n_frames)
            
            # Преобразуем аудиоданные в массив
            if sample_width == 1:
                # 8-bit audio (unsigned)
                audio_array = np.frombuffer(wav_frames, dtype=np.uint8)
                max_val = 255
            elif sample_width == 2:
                # 16-bit audio (signed)
                audio_array = np.frombuffer(wav_frames, dtype=np.int16)
                max_val = 32767
            elif sample_width == 3:
                # 24-bit audio - преобразуем в 32-bit
                # Для 24-bit нужна особая обработка
                audio_array = np.zeros(len(wav_frames) // 3, dtype=np.int32)
                for i in range(len(audio_array)):
                    audio_array[i] = int.from_bytes(wav_frames[i*3:i*3+3], byteorder='little', signed=True)
                max_val = 8388607
            elif sample_width == 4:
                # 32-bit audio (signed)
                audio_array = np.frombuffer(wav_frames, dtype=np.int32)
                max_val = 2147483647
            else:
                raise ValueError(f"Неподдерживаемая битность аудио: {sample_width * 8} бит")
            
            # Вычисляем максимальный объем данных, который можно скрыть
            max_bytes = (len(audio_array) * bits_per_sample) // 8
            
            if len(data) > max_bytes:
                raise ValueError(f"Размер данных ({len(data)} байт) превышает доступную емкость ({max_bytes} байт)")
            
            # Конвертируем данные в битовую последовательность
            binary_data = ''.join(format(byte, '08b') for byte in data)
            binary_data += '0' * (8 - (len(binary_data) % 8)) if len(binary_data) % 8 != 0 else ''  # Выравнивание
            
            # Скрываем данные в наименее значащих битах
            data_index = 0
            for i in range(len(audio_array)):
                if data_index < len(binary_data):
                    # Маска для обнуления последних bits_per_sample битов
                    mask = ~((1 << bits_per_sample) - 1)
                    
                    # Обнуляем последние биты и добавляем новые из данных
                    bits_to_set = 0
                    for b in range(bits_per_sample):
                        if data_index < len(binary_data):
                            bits_to_set |= (int(binary_data[data_index]) << b)
                            data_index += 1
                    
                    audio_array[i] = (audio_array[i] & mask) | bits_to_set
            
            # Преобразуем массив обратно в байты
            if sample_width == 1:
                modified_frames = audio_array.tobytes()
            elif sample_width == 2:
                modified_frames = audio_array.tobytes()
            elif sample_width == 3:
                # Преобразуем 32-bit обратно в 24-bit
                modified_frames = bytearray()
                for sample in audio_array:
                    modified_frames.extend(sample.to_bytes(3, byteorder='little', signed=True))
                modified_frames = bytes(modified_frames)
            elif sample_width == 4:
                modified_frames = audio_array.tobytes()
            
            # Создаем новый WAV-файл с модифицированными данными
            with wave.open(output_file, 'wb') as wav_out:
                wav_out.setparams((n_channels, sample_width, framerate, n_frames, 'NONE', 'not compressed'))
                wav_out.writeframes(modified_frames)
            
            return output_file
        
        except Exception as e:
            self.logger.error(f"Ошибка при скрытии данных в аудио (LSB): {e}")
            raise
    
    def _extract_from_audio_lsb(self, carrier_file: str, bits_per_sample: int = 1, 
                             data_length: int = None, **kwargs) -> bytes:
        """
        Извлекает данные, скрытые в наименее значащих битах аудиофайла WAV
        
        Args:
            carrier_file: Путь к аудиофайлу с скрытыми данными
            bits_per_sample: Количество бит на сэмпл (должно совпадать с значением при скрытии)
            data_length: Длина скрытых данных (в байтах), если известна
            
        Returns:
            bytes: Извлеченные данные
        """
        if not HAS_WAVE or not HAS_NUMPY:
            raise RuntimeError("Для извлечения данных из аудио требуются модули wave и NumPy")
        
        try:
            # Ограничиваем количество бит до допустимого значения
            bits_per_sample = min(max(bits_per_sample, 1), 4)
            
            # Открываем WAV-файл
            with wave.open(carrier_file, 'rb') as wav:
                # Получаем параметры аудио
                n_channels = wav.getnchannels()
                sample_width = wav.getsampwidth()
                n_frames = wav.getnframes()
                
                # Читаем все фреймы
                wav_frames = wav.readframes(n_frames)
            
            # Преобразуем аудиоданные в массив
            if sample_width == 1:
                # 8-bit audio (unsigned)
                audio_array = np.frombuffer(wav_frames, dtype=np.uint8)
            elif sample_width == 2:
                # 16-bit audio (signed)
                audio_array = np.frombuffer(wav_frames, dtype=np.int16)
            elif sample_width == 3:
                # 24-bit audio - преобразуем в 32-bit
                audio_array = np.zeros(len(wav_frames) // 3, dtype=np.int32)
                for i in range(len(audio_array)):
                    audio_array[i] = int.from_bytes(wav_frames[i*3:i*3+3], byteorder='little', signed=True)
            elif sample_width == 4:
                # 32-bit audio (signed)
                audio_array = np.frombuffer(wav_frames, dtype=np.int32)
            else:
                raise ValueError(f"Неподдерживаемая битность аудио: {sample_width * 8} бит")
            
            # Вычисляем максимальный объем данных, который можно извлечь
            max_bytes = (len(audio_array) * bits_per_sample) // 8
            
            if data_length is not None:
                bytes_to_extract = min(data_length, max_bytes)
            else:
                bytes_to_extract = max_bytes
            
            bits_to_extract = bytes_to_extract * 8
            
            # Извлекаем биты данных
            extracted_bits = ''
            bits_count = 0
            
            for i in range(len(audio_array)):
                if bits_count < bits_to_extract:
                    for b in range(bits_per_sample):
                        if bits_count < bits_to_extract:
                            # Извлекаем бит из значения сэмпла
                            extracted_bits += str((audio_array[i] >> b) & 1)
                            bits_count += 1
            
            # Конвертируем битовую последовательность в байты
            extracted_bytes = bytearray()
            for i in range(0, len(extracted_bits), 8):
                byte = extracted_bits[i:i+8]
                if len(byte) == 8:
                    extracted_bytes.append(int(byte, 2))
            
            # Проверяем сигнатуру 'STEG' (для нашего формата)
            if len(extracted_bytes) > 4 and extracted_bytes[:4] == b'STEG':
                return bytes(extracted_bytes)
            
            # Если сигнатура не найдена, но у нас был указан data_length
            if data_length is not None:
                return bytes(extracted_bytes[:data_length])
            
            # В противном случае пытаемся найти маркер конца данных
            null_byte_pos = 0
            for i in range(len(extracted_bytes) - 4):
                if extracted_bytes[i:i+4] == b'\x00\x00\x00\x00':
                    null_byte_pos = i
                    break
            
            return bytes(extracted_bytes[:null_byte_pos]) if null_byte_pos > 0 else bytes(extracted_bytes)
        
        except Exception as e:
            self.logger.error(f"Ошибка при извлечении данных из аудио (LSB): {e}")
            raise


if __name__ == "__main__":
    # Пример использования
    import argparse
    
    parser = argparse.ArgumentParser(description="Steganography - Утилита для скрытия и извлечения данных")
    parser.add_argument("mode", choices=["hide", "extract"], help="Режим работы: hide (скрыть) или extract (извлечь)")
    parser.add_argument("--method", choices=["lsb_image", "lsb_audio", "metadata", "eof"], 
                       default="lsb_image", help="Метод стеганографии")
    parser.add_argument("--carrier", required=True, help="Файл-носитель")
    parser.add_argument("--output", help="Выходной файл (для режима hide)")
    parser.add_argument("--data-file", help="Файл с данными (для режима hide) или для сохранения извлеченных данных (для режима extract)")
    parser.add_argument("--password", help="Пароль для шифрования/расшифровки")
    parser.add_argument("--bits", type=int, default=1, help="Количество бит для LSB-методов")
    
    args = parser.parse_args()
    
    # Создаем экземпляр SteganoManager
    stegano = SteganoManager(log_level="INFO")
    
    try:
        if args.mode == "hide":
            if not args.data_file:
                print("Ошибка: Для режима hide требуется указать --data-file с данными для скрытия")
                sys.exit(1)
            
            with open(args.data_file, 'rb') as f:
                data = f.read()
            
            output_file = args.output or f"{os.path.splitext(args.carrier)[0]}_steg{os.path.splitext(args.carrier)[1]}"
            
            result = stegano.hide_data(
                method=args.method,
                data=data,
                carrier_file=args.carrier,
                output_file=output_file,
                password=args.password,
                bits_per_pixel=args.bits,
                bits_per_sample=args.bits
            )
            
            print(f"Данные успешно скрыты в {result}")
            
        elif args.mode == "extract":
            result = stegano.extract_data(
                method=args.method,
                carrier_file=args.carrier,
                password=args.password,
                bits_per_pixel=args.bits,
                bits_per_sample=args.bits
            )
            
            if args.data_file:
                with open(args.data_file, 'wb') as f:
                    f.write(result)
                print(f"Извлеченные данные сохранены в {args.data_file}")
            else:
                # Если данные - текст, пытаемся отобразить их
                try:
                    text = result.decode('utf-8')
                    print(f"Извлеченные данные: {text[:100]}...")
                except UnicodeDecodeError:
                    print(f"Извлечено {len(result)} байт бинарных данных")
    
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1) 