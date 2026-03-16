# ВЕРСИЯ БЕЗ УЯЗВИМОСТЕЙ
## Структура

- `auth_service/` — аутентификация, выдача JWT
- `user_service/` — управление профилями, проверка прав (RBAC)
- `order_service/` — бизнес-логика заказов, межсервисные вызовы

## Запуск

start_services.py — НЕ для запуска, для дебага.

### Локально (для разработки)

```bash
venv\Scripts\activate
python start_services.py
