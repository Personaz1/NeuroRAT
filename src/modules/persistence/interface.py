# Интерфейс для взаимодействия модуля Persistence с ядром агента

from typing import Optional, Tuple

class PersistenceInterface:
    """Абстрактный интерфейс для управления методами персистентности."""

    def get_available_methods(self) -> list[str]:
        """Возвращает список ID доступных методов персистентности."""
        raise NotImplementedError

    def enable(self, method: str, name: str, executable_path: str, args: Optional[str] = None) -> Tuple[bool, str]:
        """Включает указанный метод персистентности.

        Args:
            method: ID метода (e.g., 'registry', 'cron').
            name: Имя для записи/задачи.
            executable_path: Путь к исполняемому файлу агента.
            args: Аргументы командной строки (если применимо).

        Returns:
            Кортеж (успех: bool, сообщение: str).
        """
        raise NotImplementedError

    def disable(self, method: str, name: str) -> Tuple[bool, str]:
        """Отключает указанный метод персистентности.

        Args:
            method: ID метода.
            name: Имя записи/задачи для удаления.

        Returns:
            Кортеж (успех: bool, сообщение: str).
        """
        raise NotImplementedError

    def check(self, method: str, name: str) -> bool:
        """Проверяет, активен ли указанный метод персистентности.

        Args:
            method: ID метода.
            name: Имя записи/задачи для проверки.

        Returns:
            True, если метод активен, иначе False.
        """
        raise NotImplementedError 