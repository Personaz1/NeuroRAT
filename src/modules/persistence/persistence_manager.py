# Persistence Manager - Управляет различными методами персистентности

import os
import importlib
import platform
import logging
from typing import Dict, Optional, Tuple, Type

from .interface import PersistenceInterface
from .methods.base import PersistenceMethodBase

logger = logging.getLogger('PersistenceManager')

class PersistenceManager(PersistenceInterface):

    def __init__(self):
        self.methods: Dict[str, PersistenceMethodBase] = {}
        # Добавляем обработку ошибок при загрузке
        try:
            self._load_methods()
        except Exception as e:
             logger.error(f"Failed to load persistence methods during init: {e}", exc_info=True)

    def _load_methods(self):
        """Динамически загружает доступные методы персистентности."""
        methods_dir = os.path.join(os.path.dirname(__file__), 'methods')
        if not os.path.isdir(methods_dir):
             logger.warning(f"Persistence methods directory not found: {methods_dir}")
             return

        current_os = platform.system().lower()
        logger.info(f"Loading persistence methods from {methods_dir} for OS: {current_os}")

        for filename in os.listdir(methods_dir):
            if filename.endswith('.py') and not filename.startswith('__') and filename != 'base.py':
                module_name = f"src.modules.persistence.methods.{filename[:-3]}"
                try:
                    module = importlib.import_module(module_name)
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        # Ищем класс, наследующий PersistenceMethodBase
                        if isinstance(attr, type) and issubclass(attr, PersistenceMethodBase) and attr is not PersistenceMethodBase:
                            try:
                                 instance = attr()
                                 # Проверяем поддержку ОС
                                 if instance.is_supported(current_os):
                                     method_id = instance.get_method_id()
                                     self.methods[method_id] = instance
                                     logger.info(f"Loaded persistence method: {method_id} ({attr_name})")
                                 else:
                                     logger.debug(f"Skipping method {attr_name}, not supported on {current_os}")
                            except Exception as instance_err:
                                 logger.error(f"Failed to instantiate or check support for method {attr_name} from {filename}: {instance_err}")
                except ImportError as import_err:
                     logger.error(f"Failed to import persistence module {module_name}: {import_err}")
                except Exception as e:
                    logger.error(f"Failed to load persistence method from {filename}: {e}", exc_info=True)

    def get_available_methods(self) -> list[str]:
        return list(self.methods.keys())

    def enable(self, method: str, name: str, executable_path: str, args: Optional[str] = None) -> Tuple[bool, str]:
        if method not in self.methods:
            return False, f"Method '{method}' not supported or available."
        try:
            logger.info(f"Enabling persistence: method='{method}', name='{name}', path='{executable_path}'")
            return self.methods[method].enable(name, executable_path, args)
        except Exception as e:
            logger.error(f"Error enabling persistence method '{method}' for name '{name}': {e}", exc_info=True)
            return False, f"Failed to enable method '{method}': {e}"

    def disable(self, method: str, name: str) -> Tuple[bool, str]:
        if method not in self.methods:
            return False, f"Method '{method}' not supported or available."
        try:
            logger.info(f"Disabling persistence: method='{method}', name='{name}'")
            return self.methods[method].disable(name)
        except Exception as e:
            logger.error(f"Error disabling persistence method '{method}' for name '{name}': {e}", exc_info=True)
            return False, f"Failed to disable method '{method}': {e}"

    def check(self, method: str, name: str) -> bool:
        if method not in self.methods:
            logger.warning(f"Check persistence called for unavailable method: '{method}'")
            return False
        try:
            logger.debug(f"Checking persistence: method='{method}', name='{name}'")
            return self.methods[method].check(name)
        except Exception as e:
            logger.error(f"Error checking persistence method '{method}' for name '{name}': {e}", exc_info=True)
            return False 