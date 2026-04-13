# Secure REST API — Дипломный проект

Демонстрационный проект микросервисной REST API с реализацией защиты от угроз **OWASP API Security Top 10**.  
Разработан как учебный стенд: содержит три независимых сервиса, обратный прокси, автоматические тесты безопасности.

---

## Архитектура

```
           HTTP
Client ──────────► Nginx (порт 80)
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
     /auth/...   /user/...   /order/...
          │           │           │
    auth_service  user_service  order_service
     (port 8000)  (port 8000)  (port 8000)
          │           │           │
          └───────────┴───────────┘
                      │
               PostgreSQL (db)
               [внутри Docker, не опубликован]
```

Все сервисы изолированы во внутренней Docker-сети `api_net`.  
Наружу открыт только порт **80** (nginx).

---

## Структура проекта

```
api_code/
├── auth_service/       # Аутентификация, выдача JWT (POST /v1/login)
├── user_service/       # Профили пользователей, RBAC (GET /v1/users/{id})
├── order_service/      # Заказы, межсервисные вызовы (GET|POST /v1/orders)
├── nginx.conf          # Обратный прокси, security-заголовки
├── docker-compose.yml  # Оркестрация всех сервисов
├── init_db.sql         # Схема базы данных
├── seed.py             # Начальное заполнение БД тестовыми данными
├── test_security.py    # Автоматические тесты OWASP API Top 10
├── requirements.txt    # Python-зависимости
└── .env                # Переменные окружения (не коммитить в prod!)
```

---

## Стек технологий

| Компонент | Технология |
|---|---|
| Фреймворк | FastAPI (Python 3.11) |
| База данных | PostgreSQL 15 |
| ORM | SQLAlchemy |
| Аутентификация | JWT (python-jose), bcrypt (passlib) |
| Обратный прокси | Nginx |
| Контейнеризация | Docker / Docker Compose |
| Тестирование | pytest + requests |

---

## Защита от угроз OWASP API Top 10

### API1 — Broken Object Level Authorization (BOLA)
Каждый запрос к `/user/{id}` и `/order/{id}` проверяет, является ли запрашивающий владельцем ресурса или администратором. Чужие данные возвращают **403 Forbidden**.

### API2 — Broken Authentication
- JWT обязателен для всех защищённых эндпоинтов
- Невалидный / истёкший токен → **401 Unauthorized**
- Credentials принимаются только в теле запроса (JSON), не в query params
- Одинаковое сообщение об ошибке для несуществующего пользователя и неверного пароля (защита от user enumeration)

### API3 — Broken Object Property Level Authorization
- Ответ `/users/{id}` возвращает только `id` и `name` — без `password` и `role`
- Лишние поля в теле запроса игнорируются (Pydantic-схема `OrderCreate` принимает только `product`)

### API4 & API6 — Rate Limiting (Unrestricted Resource Consumption / Business Flows)
Middleware на каждом сервисе ограничивает количество запросов с одного IP:
- **Auth-сервис**: 10 запросов / 60 сек — защищает от брутфорса паролей
- **Order-сервис**: 10 запросов / 60 сек — защищает от спама заказами
- При превышении → **429 Too Many Requests**

### API5 — Broken Function Level Authorization (RBAC)
Роли `user` и `admin` закодированы в JWT. Пользователь с ролью `user` не может получить данные другого пользователя — только admin имеет доступ ко всем профилям.

### API7 — Server Side Request Forgery (SSRF)
URL внутреннего `user_service` задаётся через переменную окружения `USER_SERVICE_URL` и не может быть переопределён через тело запроса. Внутренние сервисы не опубликованы наружу Docker-сети.

### API8 — Security Misconfiguration
Nginx добавляет security-заголовки к каждому ответу:
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
База данных (порт 5432) не опубликована на хост — только `expose` внутри Docker-сети.

### API9 — Improper Inventory Management
- Все эндпоинты версионированы: `/v1/login`, `/v1/users`, `/v1/orders`
- Обращение к `/login` без версии → **404**
- `/docs` и `/openapi.json` доступны только при `APP_ENV=development`

### API10 — Unsafe Consumption of APIs
При создании заказа `order_service` верифицирует пользователя через `user_service`. Если `user_service` недоступен — возвращает **503**, если пользователь не найден — **403**. Длинный input не вызывает падения сервиса.

---

## Быстрый старт

### 1. Настройка окружения

Скопируй `.env` и при необходимости задай свои секреты:
```bash
cp .env .env.local
```

Минимальный `.env`:
```env
SECRET_KEY=your_super_secret_key_here
POSTGRES_USER=api_user
POSTGRES_PASSWORD=strong_password
POSTGRES_DB=api_secure_db
APP_ENV=development
TEST_USERS=ivan:secret:user,anna:secret:user,admin:secret:admin
```

### 2. Запуск

```bash
docker compose up --build
```

### 3. Заполнение базы данных

```bash
docker compose exec db psql -U api_user -d api_secure_db -f /docker-entrypoint-initdb.d/init_db.sql
python seed.py
```

### 4. Проверка

```bash
# Получить токен
curl -X POST http://localhost/auth/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username": "ivan", "password": "secret"}'

# Получить свои данные
curl http://localhost/user/v1/users/1 \
  -H "Authorization: Bearer <token>"
```

---

## Тестирование безопасности

Тесты покрывают все 10 угроз OWASP API Security Top 10.

```bash
# Запуск всех тестов кроме rate limiting (быстро, ~3 мин)
pytest test_security.py -v -k "not API4 and not API6"

# Только rate limiting тесты (медленно, ~10 мин)
pytest test_security.py -v -k "API4 or API6"

# Все тесты сразу
pytest test_security.py -v
```

> **Примечание:** rate limiting тесты (`API4`, `API6`) делают паузы по 65 секунд между попытками — это ожидаемое поведение.

---

## API Reference

| Метод | Эндпоинт | Описание | Auth |
|---|---|---|---|
| `POST` | `/auth/v1/login` | Получить JWT токен | — |
| `GET` | `/user/v1/users/{id}` | Профиль пользователя | Bearer |
| `GET` | `/order/v1/orders/{id}` | Данные заказа | Bearer |
| `POST` | `/order/v1/orders` | Создать заказ | Bearer |
| `GET` | `/auth/docs` | Swagger UI (dev) | — |
