# ВЕРСИЯ С УЯЗВИМОСТЯМИ
Отсутствие авторизации, нет контроля выдачи данных, нет ограничения по количеству запросов

## Структура

- `auth_service/` — аутентификация, выдача JWT
- `user_service/` — управление профилями, проверка прав (RBAC)
- `order_service/` — бизнес-логика заказов, межсервисные вызовы

## Запуск

start_services.py — НЕ для запуска, для дебага.

### Локально (для разработки)

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python start_services.py