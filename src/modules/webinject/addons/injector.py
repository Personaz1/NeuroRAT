# Injector Addon for mitmproxy

import logging
from typing import Optional, List, Dict
import re

from mitmproxy import http
from mitmproxy import ctx
from mitmproxy.addonmanager import Loader

logger = logging.getLogger('InjectorAddon')

class InjectorAddon:
    def __init__(self):
        self.inject_templates: Dict[str, str] = {}
        self.target_domains: Optional[List[str]] = None
        logger.info("InjectorAddon initialized.")

    def load(self, loader: Loader):
        # Метод, вызываемый mitmproxy при загрузке аддона
        # Здесь можно добавить опции для аддона, если нужно
        pass

    def set_target_domains(self, domains: List[str]):
        self.target_domains = [d.lower() for d in domains]
        logger.info(f"Target domains set: {self.target_domains}")

    def update_injects(self, templates: Dict[str, str]):
        # TODO: Компилировать регекспы для ключей?
        self.inject_templates = templates
        logger.info(f"Inject templates updated ({len(templates)} rules)." )

    def _get_injection_script(self, host: str, url: str) -> Optional[str]:
        """Находит подходящий скрипт для инъекции по хосту и URL."""
        if not self.inject_templates:
            return None

        # TODO: Реализовать более сложный матчинг (регекспы, wildcards)
        # Простой поиск по точному совпадению хоста (приоритет)
        if host in self.inject_templates:
             return self.inject_templates[host]

        # Поиск по совпадению с началом URL?
        # Поиск по регекспу?
        for pattern, script in self.inject_templates.items():
            # Пока считаем паттерн простым хостом для проверки
            if host.endswith(pattern): # Проверка на поддомены
                 return script

        return None

    def response(self, flow: http.HTTPFlow):
        """Хук, вызываемый для каждого HTTP ответа."""
        # Проверяем, есть ли вообще шаблоны для инъекций
        if not self.inject_templates:
            return

        # Проверяем, что есть ответ и это HTML
        if not flow.response or not flow.response.headers.get("content-type", "").startswith("text/html"):
            return

        # Проверяем, соответствует ли хост целевым доменам (если они заданы)
        host = flow.request.host.lower()
        if self.target_domains and host not in self.target_domains:
            # TODO: Добавить поддержку wildcards в target_domains?
            match = False
            for target in self.target_domains:
                 if host.endswith(target): # Простая проверка на поддомены
                      match = True
                      break
            if not match:
                 return

        # Получаем скрипт для инъекции
        script_to_inject = self._get_injection_script(host, flow.request.pretty_url)
        if not script_to_inject:
            return

        logger.info(f"Injecting script into response for {flow.request.pretty_url}")

        # Читаем тело ответа
        try:
            html_body = flow.response.text # mitmproxy автоматически декодирует
            if not html_body:
                 return # Пустое тело?
        except UnicodeDecodeError:
             logger.warning(f"Could not decode HTML body for {flow.request.pretty_url}")
             return

        # Формируем тег для инъекции
        # Используем CDATA для предотвращения проблем с символами в JS
        inject_tag = f'<script type="text/javascript">//<![CDATA[\n{script_to_inject}\n//]]></script>'

        # Пытаемся вставить скрипт перед закрывающим </head> или </body>
        # Простой поиск и вставка
        # TODO: Использовать HTML парсер (BeautifulSoup?) для более надежной вставки?
        head_match = re.search(r'</head>', html_body, re.IGNORECASE)
        body_match = re.search(r'</body>', html_body, re.IGNORECASE)

        injected = False
        if head_match:
            insert_pos = head_match.start()
            flow.response.text = html_body[:insert_pos] + inject_tag + html_body[insert_pos:]
            injected = True
            logger.debug("Injected script before </head>")
        elif body_match:
            insert_pos = body_match.start()
            flow.response.text = html_body[:insert_pos] + inject_tag + html_body[insert_pos:]
            injected = True
            logger.debug("Injected script before </body>")
        else:
            # Если не нашли тегов, просто добавляем в конец (менее надежно)
            flow.response.text = html_body + inject_tag
            injected = True
            logger.debug("Injected script at the end of the body (fallback)")

        if injected:
             logger.info(f"Successfully injected script for {host}")
        else:
             # Этого не должно произойти с fallback логикой, но на всякий случай
             logger.warning(f"Failed to find injection point for {host}") 