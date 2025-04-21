from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import os
import logging
import config.logger_config  # Инициализируем конфиг логирования
from dotenv import load_dotenv
from typing import Dict, List, Any # Добавляем List
from fastapi.responses import StreamingResponse
import json
from fastapi import UploadFile, File
import asyncio  # For streaming subprocess output

# Импортируем C1Brain и контроллер
from core.c1_brain import C1Brain
from core.botnet_controller import BotnetController

# Загрузка переменных окружения (если есть .env файл)
load_dotenv()

# Используем конфигурацию логирования из config/logger_config.py
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

@app.post("/api/chat")
async def handle_chat_stream(request: ChatRequest):
    """Стримим ответ чата от C1Brain через Server-Sent Events"""
    logger.info(f"Received chat stream request: prompt='{request.prompt}', mode='{request.mode}'")
    if not c1_brain:
        async def stub():
            yield f"data: {{\"content\": \"C1 stub mode: '{request.prompt}'\"}}\n\n"
        return StreamingResponse(stub(), media_type="text/event-stream")
    
    async def event_generator():
        try:
            # Получаем полный ответ от мозга
            content = await c1_brain.process_chat(prompt=request.prompt, history=request.history)
            # Отдаем в одном SSE-сообщении
            json_payload = json.dumps({"content": content}, ensure_ascii=False)
            yield f"data: {json_payload}\n\n"
        except Exception as e:
            logger.error(f"Error in chat stream: {e}", exc_info=True)
            error_payload = json.dumps({"error": str(e)}, ensure_ascii=False)
            yield f"data: {error_payload}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")

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

@app.post("/api/terminal/stream")
async def stream_terminal_command(request: TerminalRequest):
    """Стриминг вывода команд в реальном времени через SSE"""
    logger.info(f"Streaming terminal command: '{request.command}'")
    async def event_generator():
        # Запускаем subprocess для команды
        process = await asyncio.create_subprocess_shell(
            request.command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        # Читаем stdout построчно и отдаем через SSE
        if process.stdout:
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                text = line.decode(errors='ignore')
                payload = json.dumps({"output": text}, ensure_ascii=False)
                yield f"data: {payload}\n\n"
        # Ждем завершения процесса и сообщаем об окончании
        await process.wait()
        yield f"data: {json.dumps({"done": True})}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/terminal/stream")
async def stream_terminal_command_get(command: str):
    """Стриминг вывода команд через GET для EventSource"""
    logger.info(f"Streaming terminal command GET: '{command}'")
    async def event_generator():
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        if process.stdout:
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                text = line.decode(errors='ignore')
                payload = json.dumps({"output": text}, ensure_ascii=False)
                yield f"data: {payload}\n\n"
        await process.wait()
        yield f"data: {json.dumps({"done": True})}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/api/ocr_image", response_model=Dict[str, str])
async def ocr_image(file: UploadFile = File(...)):
    """Принимает файл изображения и возвращает распознанный текст"""
    try:
        img_bytes = await file.read()
        result = await c1_brain.ocr_image(image_bytes=img_bytes)
        return result
    except Exception as e:
        logger.error(f"Ошибка ocr_image: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error ocr_image: {e}")

@app.post("/api/image_caption", response_model=Dict[str, str])
async def image_caption(file: UploadFile = File(...)):
    """Принимает файл изображения и возвращает подпись (caption)"""
    try:
        img_bytes = await file.read()
        result = await c1_brain.caption_image(image_bytes=img_bytes)
        return result
    except Exception as e:
        logger.error(f"Ошибка caption_image: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error caption_image: {e}")

# --- Запуск сервера (для локальной разработки) ---
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000)) # Порт по умолчанию 8000
    logger.info(f"Starting AGENTX C1 API server on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port) 