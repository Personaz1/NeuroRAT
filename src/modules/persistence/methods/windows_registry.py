# Метод персистентности через Windows Registry (Run key)

import platform
import logging
from typing import Optional, Tuple
import winreg # Используем стандартный модуль

from .base import PersistenceMethodBase

logger = logging.getLogger('PersistenceRegistry')

# Пути к ключам автозапуска (HKCU и HKLM)
# HKCU используется для user-level persistence (не требует прав администратора)
# HKLM требует прав администратора
REG_PATH_HKCU = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_PATH_HKLM = r"Software\Microsoft\Windows\CurrentVersion\Run"

class WindowsRegistryRun(PersistenceMethodBase):

    def get_method_id(self) -> str:
        return "registry"

    def is_supported(self, os_name: str) -> bool:
        return os_name == "windows"

    def _get_registry_key(self, use_hklm: bool = False):
        """Возвращает дескриптор нужного ключа реестра."""
        root_key = winreg.HKEY_LOCAL_MACHINE if use_hklm else winreg.HKEY_CURRENT_USER
        reg_path = REG_PATH_HKLM if use_hklm else REG_PATH_HKCU
        try:
            # Открываем ключ с правами на запись/чтение
            key = winreg.OpenKey(root_key, reg_path, 0, winreg.KEY_ALL_ACCESS)
            return key
        except FileNotFoundError:
            # Если ключа нет, пытаемся его создать
            try:
                key = winreg.CreateKey(root_key, reg_path)
                logger.info(f"Created registry key: {reg_path} under {'HKLM' if use_hklm else 'HKCU'}")
                return key
            except PermissionError:
                 logger.error(f"Permission denied to create registry key: {reg_path} under {'HKLM' if use_hklm else 'HKCU'}")
                 return None
            except Exception as e:
                 logger.error(f"Failed to create registry key {reg_path} under {'HKLM' if use_hklm else 'HKCU'}: {e}")
                 return None
        except PermissionError:
            logger.error(f"Permission denied to open registry key: {reg_path} under {'HKLM' if use_hklm else 'HKCU'}")
            return None
        except Exception as e:
            logger.error(f"Failed to open registry key {reg_path} under {'HKLM' if use_hklm else 'HKCU'}: {e}")
            return None

    def enable(self, name: str, executable_path: str, args: Optional[str] = None) -> Tuple[bool, str]:
        use_hklm = False # По умолчанию используем HKCU
        # TODO: Добавить параметр для выбора HKCU/HKLM или автоматического определения прав

        key = self._get_registry_key(use_hklm)
        if not key:
            return False, f"Failed to access registry key ('{ 'HKLM' if use_hklm else 'HKCU'}')"

        try:
            # Формируем значение: путь к файлу и аргументы
            # Обрамляем путь кавычками на случай пробелов
            value = f'"{executable_path}"'
            if args:
                value += f' {args}'

            # Устанавливаем значение реестра
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            winreg.CloseKey(key)
            logger.info(f"Persistence enabled via registry: [\'{ 'HKLM' if use_hklm else 'HKCU'}\\{REG_PATH_HKCU}] '{name}' = '{value}'")
            return True, f"Registry persistence enabled ('{ 'HKLM' if use_hklm else 'HKCU'}')"
        except Exception as e:
            if key: winreg.CloseKey(key)
            logger.error(f"Failed to set registry value '{name}': {e}", exc_info=True)
            return False, f"Failed to set registry value: {e}"

    def disable(self, name: str) -> Tuple[bool, str]:
        use_hklm = False # По умолчанию используем HKCU
        # TODO: Добавить параметр для выбора HKCU/HKLM

        key = self._get_registry_key(use_hklm)
        if not key:
            # Если ключ не удалось открыть, возможно, записи уже нет
            return True, f"Failed to access registry key, assuming persistence disabled ('{ 'HKLM' if use_hklm else 'HKCU'}')"

        try:
            # Пытаемся удалить значение
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            logger.info(f"Persistence disabled via registry: Deleted '{name}' from [\'{ 'HKLM' if use_hklm else 'HKCU'}\\{REG_PATH_HKCU}]")
            return True, f"Registry persistence disabled ('{ 'HKLM' if use_hklm else 'HKCU'}')"
        except FileNotFoundError:
            # Значения и так нет
            if key: winreg.CloseKey(key)
            logger.info(f"Registry value '{name}' not found for disabling.")
            return True, "Registry persistence was not enabled or already disabled."
        except Exception as e:
            if key: winreg.CloseKey(key)
            logger.error(f"Failed to delete registry value '{name}': {e}", exc_info=True)
            return False, f"Failed to delete registry value: {e}"

    def check(self, name: str) -> bool:
        use_hklm = False # По умолчанию используем HKCU
        # TODO: Добавить параметр для выбора HKCU/HKLM

        key = self._get_registry_key(use_hklm)
        if not key:
            return False # Не удалось получить доступ к ключу

        try:
            # Пытаемся прочитать значение
            winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return True # Значение существует
        except FileNotFoundError:
            if key: winreg.CloseKey(key)
            return False # Значение не найдено
        except Exception as e:
            if key: winreg.CloseKey(key)
            logger.error(f"Error checking registry value '{name}': {e}")
            return False 