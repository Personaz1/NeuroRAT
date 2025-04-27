import sys
import os

# Добавляем директорию src в путь импорта, чтобы можно было делать import api.app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 