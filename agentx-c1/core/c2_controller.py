#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
C2Controller - модуль для управления ботнетом и зондами
API для взаимодействия с C1Brain
"""

import os
import sys
import json
import time
import uuid
import random
import logging
import asyncio
import ipaddress
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='c2_controller.log'
)
logger = logging.getLogger('C2Controller')

class Agent:
    """Класс, представляющий агента (зонд) в ботнете"""
    
    def __init__(self, ip_address: str, agent_type: str = "basic"):
        """
        Инициализация агента
        
        Args:
            ip_address: IP-адрес зараженной системы
            agent_type: Тип агента (basic, advanced, stealth)
        """
        self.agent_id = str(uuid.uuid4())
        self.ip_address = ip_address
        self.agent_type = agent_type
        self.creation_time = datetime.now()
        self.last_check_in = self.creation_time
        self.status = "active"
        self.version = "1.0.0"
        self.os_info = self._generate_os_info()
        self.capabilities = self._generate_capabilities()
        self.commands = []
        self.command_history = []
        
        logger.info(f"Created new agent {self.agent_id} at {ip_address}")
    
    def _generate_os_info(self) -> Dict[str, str]:
        """Генерирует информацию об ОС на основе вероятностей"""
        os_types = [
            {"name": "Windows 10", "version": "10.0.19044", "arch": "x64"},
            {"name": "Windows 11", "version": "11.0.22000", "arch": "x64"},
            {"name": "Windows Server", "version": "2019", "arch": "x64"},
            {"name": "Ubuntu", "version": "20.04 LTS", "arch": "x64"},
            {"name": "CentOS", "version": "8.5", "arch": "x64"},
            {"name": "Debian", "version": "11", "arch": "x64"},
            {"name": "macOS", "version": "12.6", "arch": "x64"},
            {"name": "macOS", "version": "13.0", "arch": "arm64"}
        ]
        
        return random.choice(os_types)
    
    def _generate_capabilities(self) -> List[str]:
        """Генерирует список возможностей агента на основе его типа"""
        base_capabilities = ["command_execution", "file_transfer", "persistence"]
        
        if self.agent_type == "advanced":
            advanced_capabilities = ["keylogging", "screen_capture", "process_injection"]
            base_capabilities.extend(advanced_capabilities)
        
        if self.agent_type == "stealth":
            stealth_capabilities = ["anti_forensics", "encrypted_comms", "memory_only", "privilege_escalation"]
            base_capabilities.extend(stealth_capabilities)
            
        return base_capabilities
    
    def add_command(self, command_type: str, args: Dict[str, Any] = None) -> str:
        """
        Добавляет команду в очередь агента
        
        Args:
            command_type: Тип команды
            args: Аргументы команды
            
        Returns:
            ID команды
        """
        if args is None:
            args = {}
            
        command_id = str(uuid.uuid4())
        command = {
            "id": command_id,
            "type": command_type,
            "args": args,
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "executed_at": None,
            "result": None
        }
        
        self.commands.append(command)
        logger.info(f"Added command {command_type} (ID: {command_id}) to agent {self.agent_id}")
        
        return command_id
    
    def simulate_check_in(self):
        """Симулирует проверку связи с C2-сервером"""
        self.last_check_in = datetime.now()
        
        # Обрабатываем команды в очереди
        for command in self.commands:
            if command["status"] == "pending":
                command["status"] = "completed"
                command["executed_at"] = datetime.now().isoformat()
                command["result"] = self._simulate_command_result(command["type"], command["args"])
                
                # Добавляем в историю и удаляем из очереди
                self.command_history.append(command)
        
        # Очищаем очередь команд
        self.commands = [cmd for cmd in self.commands if cmd["status"] == "pending"]
        
        logger.info(f"Agent {self.agent_id} checked in at {self.last_check_in}")
    
    def _simulate_command_result(self, command_type: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Симулирует результат выполнения команды"""
        if command_type == "shell":
            return {
                "stdout": f"Executed command: {args.get('command', 'echo Hello')}",
                "stderr": "",
                "exit_code": 0
            }
        elif command_type == "download":
            return {
                "success": True,
                "bytes_transferred": random.randint(1024, 1048576),
                "path": args.get("destination", "/tmp/file")
            }
        elif command_type == "upload":
            return {
                "success": True,
                "bytes_transferred": random.randint(1024, 1048576)
            }
        elif command_type == "screenshot":
            return {
                "success": True,
                "screenshot_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat()
            }
        elif command_type == "keylog":
            return {
                "success": True,
                "keylog_id": str(uuid.uuid4()),
                "entries": random.randint(10, 100)
            }
        elif command_type == "kill":
            self.status = "terminated"
            return {
                "success": True,
                "message": "Agent terminated successfully"
            }
        else:
            return {
                "success": True,
                "message": f"Command {command_type} executed"
            }
    
    def to_dict(self) -> Dict[str, Any]:
        """Возвращает словарь с данными агента"""
        return {
            "agent_id": self.agent_id,
            "ip_address": self.ip_address,
            "agent_type": self.agent_type,
            "creation_time": self.creation_time.isoformat(),
            "last_check_in": self.last_check_in.isoformat(),
            "status": self.status,
            "version": self.version,
            "os_info": self.os_info,
            "capabilities": self.capabilities,
            "commands_pending": len([cmd for cmd in self.commands if cmd["status"] == "pending"]),
            "commands_history": len(self.command_history)
        }

class C2Controller:
    """Класс контроллера для управления ботнетом"""
    
    def __init__(self):
        """Инициализация контроллера"""
        self.agents = {}  # agent_id -> Agent
        self.operations = {}  # operation_id -> Operation
        self.infections = {}  # ip -> infection_details
        self.stats = {
            "total_agents": 0,
            "active_agents": 0,
            "agents_by_type": {},
            "agents_by_os": {},
            "commands_sent": 0,
            "infections_attempted": 0,
            "infections_successful": 0
        }
        
        # Для демонстрационных целей создаем несколько агентов
        self._create_demo_agents()
        logger.info(f"C2Controller initialized with {len(self.agents)} demo agents")
    
    def _create_demo_agents(self, count: int = 10):
        """Создает демонстрационные агенты"""
        for _ in range(count):
            ip = self._generate_random_ip()
            agent_type = random.choice(["basic", "advanced", "stealth"])
            agent = Agent(ip, agent_type)
            
            # Добавляем агента в контроллер
            self.agents[agent.agent_id] = agent
            
            # Обновляем статистику
            self.stats["total_agents"] += 1
            self.stats["active_agents"] += 1
            
            self.stats["agents_by_type"][agent_type] = self.stats["agents_by_type"].get(agent_type, 0) + 1
            
            os_name = agent.os_info["name"]
            self.stats["agents_by_os"][os_name] = self.stats["agents_by_os"].get(os_name, 0) + 1
            
            # Добавляем информацию о заражении
            self.infections[ip] = {
                "agent_id": agent.agent_id,
                "timestamp": agent.creation_time.isoformat(),
                "method": random.choice(["exploit", "phishing", "malicious_document", "supply_chain"]),
                "entry_point": random.choice(["browser", "email", "usb", "network_share"]),
                "status": "active"
            }
    
    def _generate_random_ip(self) -> str:
        """Генерирует случайный IP-адрес"""
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
    
    def get_agent(self, agent_id: str) -> Optional[Agent]:
        """Возвращает агента по ID"""
        return self.agents.get(agent_id)
    
    def get_all_agents(self) -> List[Dict[str, Any]]:
        """Возвращает список всех агентов"""
        return [agent.to_dict() for agent in self.agents.values()]
    
    def search_agents(self, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Поиск агентов по критериям
        
        Args:
            criteria: Словарь с критериями поиска
            
        Returns:
            Список агентов, соответствующих критериям
        """
        results = []
        
        for agent in self.agents.values():
            matches = True
            
            for key, value in criteria.items():
                if key == "os":
                    if value.lower() not in agent.os_info["name"].lower():
                        matches = False
                        break
                elif key == "status":
                    if agent.status != value:
                        matches = False
                        break
                elif key == "agent_type":
                    if agent.agent_type != value:
                        matches = False
                        break
                elif key == "capability":
                    if value not in agent.capabilities:
                        matches = False
                        break
                elif key == "ip_subnet":
                    try:
                        subnet = ipaddress.IPv4Network(value, strict=False)
                        ip = ipaddress.IPv4Address(agent.ip_address)
                        if ip not in subnet:
                            matches = False
                            break
                    except:
                        matches = False
                        break
            
            if matches:
                results.append(agent.to_dict())
        
        return results
    
    def add_command_to_agent(self, agent_id: str, command_type: str, args: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Добавляет команду агенту
        
        Args:
            agent_id: ID агента
            command_type: Тип команды
            args: Аргументы команды
            
        Returns:
            Информация о добавленной команде
        """
        agent = self.get_agent(agent_id)
        
        if agent is None:
            return {"success": False, "error": f"Agent {agent_id} not found"}
        
        if agent.status != "active":
            return {"success": False, "error": f"Agent {agent_id} is not active"}
        
        command_id = agent.add_command(command_type, args)
        self.stats["commands_sent"] += 1
        
        return {
            "success": True,
            "command_id": command_id,
            "agent_id": agent_id,
            "status": "pending"
        }
    
    def propagate_to_targets(self, targets: List[str], techniques: List[str] = None) -> Dict[str, Any]:
        """
        Запускает распространение на указанные цели
        
        Args:
            targets: Список IP-адресов или подсетей
            techniques: Список техник распространения
            
        Returns:
            Результат операции
        """
        if techniques is None:
            techniques = ["exploit", "brute_force"]
        
        operation_id = str(uuid.uuid4())
        
        # Разворачиваем подсети в отдельные IP
        expanded_targets = []
        for target in targets:
            try:
                # Проверяем, является ли цель подсетью
                if "/" in target:
                    network = ipaddress.IPv4Network(target, strict=False)
                    # Берем только первые 10 IP для демонстрации
                    for ip in list(network.hosts())[:10]:
                        expanded_targets.append(str(ip))
                else:
                    expanded_targets.append(target)
            except:
                expanded_targets.append(target)
        
        # Создаем операцию
        self.operations[operation_id] = {
            "id": operation_id,
            "targets": expanded_targets,
            "techniques": techniques,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "status": "in_progress",
            "results": {}
        }
        
        # Симулируем распространение
        for target in expanded_targets:
            self.stats["infections_attempted"] += 1
            
            # С вероятностью 70% заражение успешно
            success = random.random() < 0.7
            
            if success:
                self.stats["infections_successful"] += 1
                
                # Выбираем технику, которая "сработала"
                successful_technique = random.choice(techniques)
                
                # Создаем нового агента
                agent_type = random.choice(["basic", "advanced", "stealth"])
                agent = Agent(target, agent_type)
                
                # Добавляем агента в контроллер
                self.agents[agent.agent_id] = agent
                
                # Обновляем статистику
                self.stats["total_agents"] += 1
                self.stats["active_agents"] += 1
                
                self.stats["agents_by_type"][agent_type] = self.stats["agents_by_type"].get(agent_type, 0) + 1
                
                os_name = agent.os_info["name"]
                self.stats["agents_by_os"][os_name] = self.stats["agents_by_os"].get(os_name, 0) + 1
                
                # Добавляем информацию о заражении
                self.infections[target] = {
                    "agent_id": agent.agent_id,
                    "timestamp": agent.creation_time.isoformat(),
                    "method": successful_technique,
                    "entry_point": random.choice(["service", "vulnerability", "credentials"]),
                    "status": "active",
                    "operation_id": operation_id
                }
                
                # Записываем результат операции
                self.operations[operation_id]["results"][target] = {
                    "success": True,
                    "technique": successful_technique,
                    "agent_id": agent.agent_id
                }
            else:
                # Записываем результат операции
                self.operations[operation_id]["results"][target] = {
                    "success": False,
                    "reason": random.choice([
                        "firewall_blocked",
                        "patch_applied",
                        "credentials_invalid",
                        "service_not_vulnerable",
                        "target_offline"
                    ])
                }
        
        # Завершаем операцию
        self.operations[operation_id]["status"] = "completed"
        self.operations[operation_id]["end_time"] = datetime.now().isoformat()
        
        # Результат операции
        successful_infections = sum(1 for result in self.operations[operation_id]["results"].values() if result.get("success", False))
        
        return {
            "operation_id": operation_id,
            "targets_count": len(expanded_targets),
            "successful_infections": successful_infections,
            "success_rate": successful_infections / len(expanded_targets) if expanded_targets else 0
        }
    
    def get_agent_infections(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Возвращает информацию о заражениях для агента
        
        Args:
            agent_id: ID агента
            
        Returns:
            Список заражений
        """
        agent_infections = []
        
        for ip, infection in self.infections.items():
            if infection.get("agent_id") == agent_id:
                infection_data = infection.copy()
                infection_data["ip_address"] = ip
                agent_infections.append(infection_data)
        
        return agent_infections
    
    def get_all_infections(self) -> List[Dict[str, Any]]:
        """Возвращает информацию о всех заражениях"""
        all_infections = []
        
        for ip, infection in self.infections.items():
            infection_data = infection.copy()
            infection_data["ip_address"] = ip
            all_infections.append(infection_data)
        
        return all_infections
    
    def kill_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Отправляет команду на самоуничтожение агента
        
        Args:
            agent_id: ID агента
            
        Returns:
            Результат операции
        """
        agent = self.get_agent(agent_id)
        
        if agent is None:
            return {"success": False, "error": f"Agent {agent_id} not found"}
        
        if agent.status != "active":
            return {"success": False, "error": f"Agent {agent_id} is not active"}
        
        # Добавляем команду kill и сразу выполняем ее
        agent.add_command("kill")
        agent.simulate_check_in()
        
        # Обновляем статистику
        self.stats["active_agents"] -= 1
        
        # Обновляем информацию о заражении
        for ip, infection in self.infections.items():
            if infection.get("agent_id") == agent_id:
                infection["status"] = "terminated"
        
        return {
            "success": True,
            "agent_id": agent_id,
            "status": agent.status
        }
    
    def upgrade_agent(self, agent_id: str, version: str = "latest") -> Dict[str, Any]:
        """
        Обновляет агент на новую версию
        
        Args:
            agent_id: ID агента
            version: Версия агента
            
        Returns:
            Результат операции
        """
        agent = self.get_agent(agent_id)
        
        if agent is None:
            return {"success": False, "error": f"Agent {agent_id} not found"}
        
        if agent.status != "active":
            return {"success": False, "error": f"Agent {agent_id} is not active"}
        
        # Для демонстрации используем фиксированную последнюю версию
        if version == "latest":
            version = "1.2.0"
        
        # Добавляем команду upgrade и сразу выполняем ее
        agent.add_command("upgrade", {"version": version})
        agent.simulate_check_in()
        
        # Обновляем версию агента
        agent.version = version
        
        return {
            "success": True,
            "agent_id": agent_id,
            "previous_version": "1.0.0",
            "new_version": version
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику ботнета"""
        # Обновляем статистику перед возвратом
        active_count = 0
        for agent in self.agents.values():
            if agent.status == "active":
                active_count += 1
        
        self.stats["active_agents"] = active_count
        
        return self.stats

class C2API:
    """API для взаимодействия с C2Controller"""
    
    def __init__(self, controller: C2Controller):
        """
        Инициализация API
        
        Args:
            controller: Экземпляр C2Controller
        """
        self.controller = controller
    
    def get_agents(self) -> List[Dict[str, Any]]:
        """Возвращает список всех агентов"""
        return self.controller.get_all_agents()
    
    def search_agents(self, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Поиск агентов по критериям"""
        return self.controller.search_agents(criteria)
    
    def add_command(self, agent_id: str, command_type: str, args: Dict[str, Any] = None) -> Dict[str, Any]:
        """Добавляет команду агенту"""
        return self.controller.add_command_to_agent(agent_id, command_type, args)
    
    def propagate_to_targets(self, targets: List[str], techniques: List[str] = None) -> Dict[str, Any]:
        """Запускает распространение на указанные цели"""
        return self.controller.propagate_to_targets(targets, techniques)
    
    def get_agent_infections(self, agent_id: str) -> List[Dict[str, Any]]:
        """Возвращает информацию о заражениях для агента"""
        return self.controller.get_agent_infections(agent_id)
    
    def get_all_infections(self) -> List[Dict[str, Any]]:
        """Возвращает информацию о всех заражениях"""
        return self.controller.get_all_infections()
    
    def kill_agent(self, agent_id: str) -> Dict[str, Any]:
        """Отправляет команду на самоуничтожение агента"""
        return self.controller.kill_agent(agent_id)
    
    def upgrade_agent(self, agent_id: str, version: str = "latest") -> Dict[str, Any]:
        """Обновляет агент на новую версию"""
        return self.controller.upgrade_agent(agent_id, version)
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику ботнета"""
        return self.controller.get_stats()

# Пример использования
if __name__ == "__main__":
    # Создаем контроллер
    controller = C2Controller()
    
    # Создаем API
    api = C2API(controller)
    
    # Получаем список агентов
    agents = api.get_agents()
    print(f"Total agents: {len(agents)}")
    
    if agents:
        # Берем первого агента
        agent_id = agents[0]["agent_id"]
        
        # Добавляем команду
        result = api.add_command(agent_id, "shell", {"command": "whoami"})
        print(f"Command added: {result}")
        
        # Получаем информацию о заражениях
        infections = api.get_agent_infections(agent_id)
        print(f"Infections for agent {agent_id}: {len(infections)}")
    
    # Запускаем распространение
    targets = ["192.168.1.0/24", "10.0.0.1"]
    result = api.propagate_to_targets(targets, ["exploit", "brute_force"])
    print(f"Propagation result: {result}")
    
    # Получаем статистику
    stats = api.get_stats()
    print(f"Botnet stats: {stats}") 