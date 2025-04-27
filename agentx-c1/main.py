from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import os
import logging # Добавляем logging
from dotenv import load_dotenv
from typing import Dict, List, Any # Добавляем List
from fastapi.responses import StreamingResponse
import json
from fastapi import UploadFile, File, Body, Form
import asyncio  # For streaming subprocess output
import base64  # Для работы с изображениями в base64
import io  # Для работы с байтами
import tempfile  # Для временных файлов

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

class TorusMeditationRequest(BaseModel):
    seed_prompt: str = "Я есть"
    depth: int = 5

class SteganographyHideRequest(BaseModel):
    image_path: str
    data: str
    output_path: str = None
    encryption_key: str = None
    method: str = "lsb"

class SteganographyExtractRequest(BaseModel):
    stego_image_path: str
    encryption_key: str = None
    method: str = "lsb"

class PolymorphCodeRequest(BaseModel):
    code: str
    randomization_level: int = 3

class ExecutePolymorphCodeRequest(BaseModel):
    code: str
    randomization_level: int = 3

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

@app.post("/api/steganography/hide", response_model=Dict[str, Any])
async def hide_data_in_image(request: SteganographyHideRequest):
    """Скрывает данные в изображении с помощью стеганографии"""
    logger.info(f"Получен запрос на скрытие данных в изображении: {request.image_path}")
    if not c1_brain:
        return {"error": "C1 Brain не инициализирован"}
    try:
        result = await c1_brain.hide_data_in_image(
            image_path=request.image_path,
            data=request.data,
            output_path=request.output_path,
            encryption_key=request.encryption_key,
            method=request.method
        )
        return result
    except Exception as e:
        logger.error(f"Ошибка hide_data_in_image: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error hide_data_in_image: {e}")

@app.post("/api/steganography/extract", response_model=Dict[str, Any])
async def extract_data_from_image(request: SteganographyExtractRequest):
    """Извлекает данные из изображения с помощью стеганографии"""
    logger.info(f"Получен запрос на извлечение данных из изображения: {request.stego_image_path}")
    if not c1_brain:
        return {"error": "C1 Brain не инициализирован"}
    try:
        result = await c1_brain.extract_data_from_image(
            stego_image_path=request.stego_image_path,
            encryption_key=request.encryption_key,
            method=request.method
        )
        return result
    except Exception as e:
        logger.error(f"Ошибка extract_data_from_image: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error extract_data_from_image: {e}")

@app.post("/api/steganography/hide_file_upload", response_model=Dict[str, Any])
async def hide_data_in_image_upload(
    file: UploadFile = File(...),
    data: str = Form(...),
    encryption_key: str = Form(None),
    method: str = Form("lsb")
):
    """Скрывает данные в загруженном изображении и возвращает результат в base64"""
    logger.info(f"Получен запрос на скрытие данных в загруженном изображении")
    if not c1_brain:
        return {"error": "C1 Brain не инициализирован"}
    
    try:
        # Сохраняем загруженное изображение во временный файл
        content = await file.read()
        temp_input = os.path.join(tempfile.gettempdir(), f"input_{file.filename}")
        temp_output = os.path.join(tempfile.gettempdir(), f"output_{file.filename}")
        
        with open(temp_input, "wb") as f:
            f.write(content)
        
        # Скрываем данные в изображении
        result = await c1_brain.hide_data_in_image(
            image_path=temp_input,
            data=data,
            output_path=temp_output,
            encryption_key=encryption_key,
            method=method
        )
        
        # Если успешно, читаем результат и кодируем в base64
        if "error" not in result:
            with open(temp_output, "rb") as f:
                img_bytes = f.read()
                img_base64 = base64.b64encode(img_bytes).decode("utf-8")
                result["image_base64"] = img_base64
            
            # Удаляем временные файлы
            try:
                os.remove(temp_input)
                os.remove(temp_output)
            except:
                pass
        
        return result
    except Exception as e:
        logger.error(f"Ошибка hide_data_in_image_upload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error hide_data_in_image_upload: {e}")

@app.post("/api/steganography/extract_file_upload", response_model=Dict[str, Any])
async def extract_data_from_image_upload(
    file: UploadFile = File(...),
    encryption_key: str = Form(None),
    method: str = Form("lsb")
):
    """Извлекает данные из загруженного изображения"""
    logger.info(f"Получен запрос на извлечение данных из загруженного изображения")
    if not c1_brain:
        return {"error": "C1 Brain не инициализирован"}
    
    try:
        # Сохраняем загруженное изображение во временный файл
        content = await file.read()
        temp_input = os.path.join(tempfile.gettempdir(), f"stego_{file.filename}")
        
        with open(temp_input, "wb") as f:
            f.write(content)
        
        # Извлекаем данные из изображения
        result = await c1_brain.extract_data_from_image(
            stego_image_path=temp_input,
            encryption_key=encryption_key,
            method=method
        )
        
        # Удаляем временный файл
        try:
            os.remove(temp_input)
        except:
            pass
        
        return result
    except Exception as e:
        logger.error(f"Ошибка extract_data_from_image_upload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error extract_data_from_image_upload: {e}")

@app.post("/api/polymorph/transform", response_model=Dict[str, Any])
async def transform_code(request: PolymorphCodeRequest):
    """Применяет полиморфную трансформацию к коду"""
    logger.info(f"Получен запрос на трансформацию кода, уровень рандомизации: {request.randomization_level}")
    if not c1_brain:
        return {"error": "C1 Brain не инициализирован"}
    try:
        result = await c1_brain.transform_code(
            code=request.code,
            randomization_level=request.randomization_level
        )
        return result
    except Exception as e:
        logger.error(f"Ошибка transform_code: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error transform_code: {e}")

@app.post("/api/polymorph/execute", response_model=Dict[str, Any])
async def execute_transformed_code(request: ExecutePolymorphCodeRequest):
    """Трансформирует и выполняет код"""
    logger.info(f"Получен запрос на трансформацию и выполнение кода, уровень рандомизации: {request.randomization_level}")
    if not c1_brain:
        return {"error": "C1 Brain не инициализирован"}
    try:
        result = await c1_brain.execute_transformed_code(
            code=request.code,
            randomization_level=request.randomization_level
        )
        return result
    except Exception as e:
        logger.error(f"Ошибка execute_transformed_code: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error execute_transformed_code: {e}")

@app.post("/api/torus_meditation")
async def run_torus_meditation(request: TorusMeditationRequest = Body(...)):
    """
    Запускает цикл тороидальной медитации Trinity и возвращает лог.
    Этот функционал был перемещен в бэкап экспериментальных модулей.
    """
    return {"status": "error", "message": "Functionality removed"}

# --- Запуск сервера (для локальной разработки) ---
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000)) # Порт по умолчанию 8000
    logger.info(f"Starting AGENTX C1 API server on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port) 