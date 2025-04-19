from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import os
import logging # Добавляем logging
from dotenv import load_dotenv
from typing import Dict, List, Any # Добавляем List

# Импортируем C1Brain и контроллер
from core.c1_brain import C1Brain
from core.botnet_controller import BotnetController

# Загрузка переменных окружения (если есть .env файл)
load_dotenv()

# Настройка логирования (можно вынести в отдельный модуль)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s') # Устанавливаем DEBUG
logger = logging.getLogger(__name__)

app = FastAPI(title="AGENTX C1 API")

# --- Настройка CORS --- 
# Разрешаем запросы от нашего frontend (запущенного на localhost:5173)
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    # Добавь другие origins, если frontend будет на другом порту/домене
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Инициализация компонентов ---
try:
    # Создаем мозг C1
    # Передаем None вместо botnet_controller, т.к. он не используется в MVP
    c1_brain = C1Brain(controller=None, llm_provider="api") # Используем API LLM 
    # TODO: Передать реальную конфигурацию LLM из .env
    # logger.info("C1 Brain и Botnet Controller инициализированы.") # Убираем лог про контроллер
    logger.info("C1 Brain инициализирован.") # Оставляем только лог про мозг
except Exception as e:
    logger.error(f"Ошибка инициализации C1 Brain: {e}", exc_info=True) # Уточняем лог ошибки
    # В случае ошибки инициализации, используем заглушки
    # botnet_controller = None # Переменная больше не нужна
    c1_brain = None
    logger.warning("C1 Brain не инициализирован, API будет работать в режиме заглушек.")

# --- Модели данных (Pydantic) ---
class ChatRequest(BaseModel):
    prompt: str
    mode: str = 'STANDARD' # Режимы STANDARD, REASONING, etc.
    # Добавляем историю чата
    history: List[Dict[str, str]] = [] # Список словарей вида {"role": "user/agent", "content": "..."}
    # TODO: Добавить context, history, etc.

class ChatResponse(BaseModel):
    role: str = 'agent'
    content: str

class TerminalRequest(BaseModel):
    command: str

class TerminalResponse(BaseModel):
    output: str
    error: str | None = None

# --- API Эндпоинты ---

@app.get("/")
def read_root():
    return {"message": "Welcome to AGENTX C1 API"}

@app.post("/api/chat", response_model=ChatResponse)
async def handle_chat(request: ChatRequest):
    """Обрабатывает запрос чата от UI."""
    logger.info(f"Received chat request: prompt='{request.prompt}', mode='{request.mode}'")
    
    if not c1_brain:
        # Режим заглушки
        response_content = f"C1 received (STUB MODE - BRAIN INIT FAILED): '{request.prompt}'"
        return ChatResponse(content=response_content)
        
    try:
        # Передаем запрос в C1Brain, включая историю
        response_content = await c1_brain.process_chat(prompt=request.prompt, history=request.history)
        return ChatResponse(content=response_content)
    except Exception as e:
        logger.error(f"Ошибка обработки чата: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ошибка обработки чата: {e}")

@app.post("/api/terminal/execute", response_model=TerminalResponse)
async def execute_terminal_command(request: TerminalRequest):
    """Выполняет команду в терминале (заглушка)."""
    logger.info(f"Received terminal command: '{request.command}'")
    
    if not c1_brain:
        # Режим заглушки
        output = f"Simulated execution (STUB MODE - BRAIN INIT FAILED): {request.command}"
        error = "C1 Brain not initialized"
        return TerminalResponse(output=output, error=error)
        
    try:
        # Выполняем команду через инструмент C1Brain
        result = await c1_brain.execute_local_command(request.command)
        return TerminalResponse(output=result.get('output', ''), error=result.get('error'))
    except Exception as e:
        logger.error(f"Ошибка выполнения команды терминала: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ошибка выполнения команды: {e}")

# --- Запуск сервера (для локальной разработки) ---
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000)) # Порт по умолчанию 8000
    logger.info(f"Starting AGENTX C1 API server on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port) 