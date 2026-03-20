FROM python:3.11-slim

WORKDIR /app

# 1. Копируем общий файл зависимостей
COPY requirements.txt .

# 2. Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# 3. Копируем весь код проекта в контейнер
COPY . .

# Порт по умолчанию (хотя в compose мы его переопределим для каждого сервиса)
EXPOSE 8000

# Команда по умолчанию (будет переопределена в docker-compose.yml для каждого сервиса)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]