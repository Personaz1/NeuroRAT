# Метод персистентности через Linux cron

import platform
import logging
import subprocess
import getpass # Для определения текущего пользователя
from typing import Optional, Tuple

from .base import PersistenceMethodBase

logger = logging.getLogger('PersistenceCron')

class LinuxCron(PersistenceMethodBase):

    def get_method_id(self) -> str:
        return "cron"

    def is_supported(self, os_name: str) -> bool:
        return os_name == "linux"

    def _get_cron_command(self, name: str, executable_path: str, args: Optional[str] = None) -> str:
        """Формирует команду для добавления/удаления из crontab."""
        # Используем @reboot для запуска при старте системы
        # Добавляем уникальный комментарий для идентификации
        comment = f"# PersistenceManager:{name}"
        command = f'\"@{executable_path}\"' # Экранируем путь
        if args:
            command += f' {args}'
        # Команда для cron: запуск при ребуте, путь к исполняемому файлу, аргументы, комментарий
        cron_line = f"@reboot {command} {comment}"
        return cron_line

    def _get_current_crontab(self, username: str) -> Optional[str]:
        """Получает текущий crontab пользователя."""
        try:
            # Выполняем crontab -l от имени пользователя
            result = subprocess.run(['crontab', '-l', '-u', username], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return result.stdout
            elif "no crontab for" in result.stderr:
                return "" # Пустой crontab
            else:
                logger.error(f"Error getting crontab for user '{username}': {result.stderr}")
                return None
        except FileNotFoundError:
            logger.error("'crontab' command not found. Is cron installed?")
            return None
        except Exception as e:
            logger.error(f"Failed to get crontab for user '{username}': {e}")
            return None

    def _update_crontab(self, username: str, new_crontab_content: str) -> bool:
        """Обновляет crontab пользователя."""
        try:
            # Используем subprocess для передачи нового crontab через stdin
            process = subprocess.Popen(['crontab', '-u', username, '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(input=new_crontab_content)
            if process.returncode == 0:
                logger.info(f"Successfully updated crontab for user '{username}'")
                return True
            else:
                logger.error(f"Error updating crontab for user '{username}': {stderr}")
                return False
        except FileNotFoundError:
            logger.error("'crontab' command not found. Is cron installed?")
            return False
        except Exception as e:
            logger.error(f"Failed to update crontab for user '{username}': {e}")
            return False

    def enable(self, name: str, executable_path: str, args: Optional[str] = None) -> Tuple[bool, str]:
        username = getpass.getuser() # Получаем имя текущего пользователя
        current_crontab = self._get_current_crontab(username)
        if current_crontab is None:
            return False, "Failed to get current crontab."

        new_cron_line = self._get_cron_command(name, executable_path, args)
        comment_tag = f"# PersistenceManager:{name}"

        # Проверяем, нет ли уже такой записи (по комментарию)
        if comment_tag in current_crontab:
            # Удаляем старую запись перед добавлением новой
            lines = current_crontab.splitlines()
            lines = [line for line in lines if comment_tag not in line]
            current_crontab = "\n".join(lines) + "\n" if lines else ""
            logger.info(f"Removed existing cron entry for '{name}'")

        # Добавляем новую строку
        new_crontab_content = current_crontab.strip() + "\n" + new_cron_line + "\n"

        if self._update_crontab(username, new_crontab_content):
            return True, f"Cron persistence enabled for user '{username}' (@reboot)"
        else:
            return False, "Failed to update crontab."

    def disable(self, name: str) -> Tuple[bool, str]:
        username = getpass.getuser()
        current_crontab = self._get_current_crontab(username)
        if current_crontab is None:
            # Если не удалось получить crontab, считаем, что записи нет или ошибка
            return False, "Failed to get current crontab, cannot disable."

        comment_tag = f"# PersistenceManager:{name}"
        if comment_tag not in current_crontab:
            return True, "Cron persistence was not enabled or already disabled."

        lines = current_crontab.splitlines()
        new_lines = [line for line in lines if comment_tag not in line]
        new_crontab_content = "\n".join(new_lines) + "\n"

        if self._update_crontab(username, new_crontab_content):
            return True, f"Cron persistence disabled for user '{username}'"
        else:
            return False, "Failed to update crontab."

    def check(self, name: str) -> bool:
        username = getpass.getuser()
        current_crontab = self._get_current_crontab(username)
        if current_crontab is None:
            return False

        comment_tag = f"# PersistenceManager:{name}"
        return comment_tag in current_crontab 