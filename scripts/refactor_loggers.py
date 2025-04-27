#!/usr/bin/env python3
"""
Refactor loggers in src/modules to use common.utils.get_logger.
Replaces 'import logging' with 'from common.utils import get_logger' and rebinds loggers.
"""
import os
import re

MODULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'src', 'modules')

pattern_import = re.compile(r'^\s*import logging', re.MULTILINE)
pattern_logger_simple = re.compile(r"logger\s*=\s*logging\.getLogger\(([^)]+)\)")
pattern_self_logger = re.compile(r"self\.logger\s*=\s*logging\.getLogger\(([^)]+)\)")

for root, dirs, files in os.walk(MODULES_DIR):
    for filename in files:
        if not filename.endswith('.py'):
            continue
        path = os.path.join(root, filename)
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
        original = text
        # Insert import for get_logger
        if pattern_import.search(text):
            text = pattern_import.sub('from common.utils import get_logger\nimport logging', text)
        # Replace global logger
        text = pattern_logger_simple.sub(r'logger = get_logger(\1)', text)
        # Replace instance logger
        text = pattern_self_logger.sub(r'self.logger = get_logger(\1)', text)
        if text != original:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)
            print(f'Patched {path}') 