# Dockerfile: Channel-Service
FROM python:3.10-slim

WORKDIR /app

# Устанавливаем зависимости
COPY src/requirements.txt src/requirements-dev.txt ./
RUN pip install --no-cache-dir -r src/requirements.txt -r src/requirements-dev.txt

# Копируем код приложения
COPY src/ ./src
COPY src/api/app.py ./src/api/app.py
COPY src/common ./src/common
COPY src/channel_manager.py ./src/channel_manager.py
COPY src/modules ./src/modules

# Открываем порт
EXPOSE 8000

# Команда запуска FastAPI приложения
CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"] 