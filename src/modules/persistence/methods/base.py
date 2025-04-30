# Базовый класс для методов персистентности

from abc import ABC, abstractmethod
from typing import Optional, Tuple

class PersistenceMethodBase(ABC):

    @abstractmethod
    def get_method_id(self) -> str:
        """Возвращает уникальный ID метода (e.g., 'registry', 'cron')."""
        pass

    @abstractmethod
    def is_supported(self, os_name: str) -> bool:
        """Проверяет, поддерживается ли метод на данной ОС.

        Args:
            os_name: Имя ОС в нижнем регистре (e.g., 'windows', 'linux', 'darwin').
        """
        pass

    @abstractmethod
    def enable(self, name: str, executable_path: str, args: Optional[str] = None) -> Tuple[bool, str]:
        """Включает метод персистентности."""
        pass

    @abstractmethod
    def disable(self, name: str) -> Tuple[bool, str]:
        """Отключает метод персистентности."""
        pass

    @abstractmethod
    def check(self, name: str) -> bool:
        """Проверяет, активен ли метод."""
        pass 