FROM python:3.11-slim

WORKDIR /app

# 1️⃣ Копируем requirements.txt в контейнер
COPY requirements.txt .

# 2️⃣ Скачиваем Linux-версии пакетов (офлайн или для кэша)
RUN pip download -r requirements.txt -d /deps

# 3️⃣ Устанавливаем зависимости из скачанных файлов
RUN pip install --no-cache-dir /deps/*

# 4️⃣ Копируем весь проект
COPY . .

# 5️⃣ Создаём безопасного пользователя
RUN useradd -m appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]