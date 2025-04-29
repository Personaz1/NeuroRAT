# Dockerfile: Channel-Service
FROM python:3.10-slim as backend

WORKDIR /app

# Copy backend requirements
COPY requirements.txt .
COPY requirements-dev.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install fastapi uvicorn

# Copy backend code
COPY src/ ./src/
COPY README.md .
COPY pytest.ini .

# Expose API port
EXPOSE 8000

# Command to run the server
CMD ["python", "-m", "src.main"]

FROM node:18 as frontend-build

WORKDIR /app

# Copy frontend source code
COPY agentx-ui/package*.json ./
RUN npm ci

COPY agentx-ui/ ./
RUN npm run build

FROM nginx:alpine as frontend

COPY --from=frontend-build /app/dist /usr/share/nginx/html
COPY agentx-ui/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

FROM backend

# Install supervisord
RUN apt-get update && apt-get install -y supervisor nginx

# Copy frontend files
COPY --from=frontend /usr/share/nginx/html /usr/share/nginx/html
COPY --from=frontend /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf

# Create supervisord config
RUN echo '[supervisord]\nnodaemon=true\n\n\
[program:nginx]\ncommand=nginx -g "daemon off;"\n\n\
[program:backend]\ncommand=python -m src.main\n'\
> /etc/supervisor/conf.d/supervisord.conf

# Expose both frontend and backend ports
EXPOSE 80 8000

# Start supervisord
CMD ["/usr/bin/supervisord"] 