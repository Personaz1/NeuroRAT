# Интерфейс для Webinject Engine

from abc import ABC, abstractmethod
from typing import Optional, List, Dict

class WebinjectInterface(ABC):
    """Интерфейс для управления Webinject Engine (MITM Proxy)."""

    @abstractmethod
    def start_proxy(self, port: int = 8080, target_domains: Optional[list[str]] = None):
        """Запускает MITM прокси на указанном порту.

        Args:
            port: Локальный порт для прокси.
            target_domains: Список доменов (или шаблонов), для которых будут применяться инъекции.
                            Если None, инъекции могут применяться ко всем (зависит от аддона).
        """
        pass

    @abstractmethod
    def stop_proxy(self):
        """Останавливает MITM прокси."""
        pass

    @abstractmethod
    def update_injects(self, inject_templates: Dict[str, str]):
        """Обновляет шаблоны JS-инъекций.

        Args:
            inject_templates: Словарь, где ключ - паттерн домена/URL, значение - JS код.
        """
        pass

    @abstractmethod
    def install_ca_certificate(self) -> bool:
        """Пытается установить корневой сертификат mitmproxy в систему.

        Returns:
            True в случае успеха, False иначе.
        """
        pass 