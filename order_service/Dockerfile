FROM python:3.11-slim

WORKDIR /app

# Копируем зависимости сначала — чтобы кэшировался слой установки
COPY ./requirements.txt .
RUN pip install --no-cache-dir -r ./requirements.txt

# Копируем код сервиса
COPY . .

# Порт по умолчанию — 8000, но переопределяется в docker-compose
EXPOSE 8000

# Запускаем uvicorn: имя приложения (main:app) берётся из контекста сборки
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]