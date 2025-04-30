import os
import logging
from typing import Dict, Optional

logger = logging.getLogger('WebinjectUtils')

def load_inject_templates(templates_dir: str) -> Dict[str, str]:
    """Загружает JS шаблоны инъекций из указанной директории.

    Ожидает, что имя файла (без .js) будет использоваться как ключ (паттерн домена/URL).
    Например, 'example.com.js' будет загружен с ключом 'example.com'.
    """
    templates: Dict[str, str] = {}
    if not os.path.isdir(templates_dir):
        logger.warning(f"Inject templates directory not found: {templates_dir}")
        return templates

    logger.info(f"Loading inject templates from: {templates_dir}")
    for filename in os.listdir(templates_dir):
        if filename.endswith('.js'):
            template_key = filename[:-3] # Удаляем .js
            file_path = os.path.join(templates_dir, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    templates[template_key] = f.read()
                logger.debug(f"Loaded inject template '{template_key}' from {filename}")
            except Exception as e:
                 logger.error(f"Failed to load inject template {filename}: {e}")

    logger.info(f"Loaded {len(templates)} inject templates.")
    return templates 