# Stealth Module - Kernel-level techniques

from .interface import StealthInterface
# Позже добавим импорт конкретного менеджера, например, WindowsStealthManager
from .windows_manager import WindowsStealthManager # Добавляем импорт менеджера 