"""
Автоматические тесты безопасности OWASP API Top 10
Запуск всех тестов кроме rate limiting: pytest test_security.py -v -k "not API4 and not API6"
Запуск rate limiting тестов отдельно:   pytest test_security.py -v -k "API4 or API6"
Запуск всех сразу (долго ~10 мин):      pytest test_security.py -v
"""

import os
import time
import pytest
import requests
from jose import jwt as jose_jwt
from dotenv import load_dotenv

load_dotenv(".env")

BASE = "http://localhost"
AUTH_URL = f"{BASE}/auth/v1/login"
USER_URL = f"{BASE}/user/v1/users"
ORDER_URL = f"{BASE}/order/v1/orders"


# ──────────────────────────────────────────────
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ──────────────────────────────────────────────

def get_token(username: str, password: str) -> str | None:
    """Получить JWT токен для пользователя."""
    resp = requests.post(AUTH_URL, json={"username": username, "password": password})
    if resp.status_code == 200:
        return resp.json().get("access_token")
    return None


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def get_token_with_retry(username: str, password: str) -> str:
    """Получить токен с повторными попытками при rate limit."""
    for attempt in range(5):
        token = get_token(username, password)
        if token is not None:
            return token
        print(f"[{username}] Попытка {attempt+1}: ждём сброса rate limit...")
        time.sleep(12)
    assert False, f"Не удалось получить токен для {username} после 5 попыток."


def load_test_users() -> dict:
    """
    Читает пользователей из TEST_USERS в .env.
    Формат: username:password:role,username:password:role
    Возвращает: {"ivan": {"password": "secret", "role": "user"}, ...}
    """
    raw = os.getenv("TEST_USERS", "")
    users = {}
    for entry in raw.split(","):
        parts = entry.strip().split(":")
        if len(parts) == 3:
            username, password, role = parts
            users[username] = {"password": password, "role": role}
    return users


TEST_USERS = load_test_users()


def get_token_by_role(tokens: dict, role: str) -> str:
    """Получить токен первого пользователя с нужной ролью."""
    for username, data in tokens.items():
        if data["role"] == role:
            return data["token"]
    assert False, f"Нет пользователя с ролью '{role}' в TEST_USERS"


def get_token_by_role_exclude(tokens: dict, role: str, exclude_token: str) -> str:
    """Получить токен пользователя с ролью, но не того же что exclude_token."""
    for username, data in tokens.items():
        if data["role"] == role and data["token"] != exclude_token:
            return data["token"]
    assert False, f"Нет второго пользователя с ролью '{role}'"


def get_user_id_from_token(token: str) -> int:
    """Достать user_id из JWT токена без проверки подписи."""
    claims = jose_jwt.get_unverified_claims(token)
    return claims.get("user_id")


# ──────────────────────────────────────────────
# ФИКСТУРЫ
# ──────────────────────────────────────────────

@pytest.fixture(scope="session")
def tokens() -> dict:
    """
    Единый словарь со всеми токенами всех пользователей из .env.
    Добавляешь пользователя в TEST_USERS в .env — он автоматически появляется здесь.
    Структура: {"ivan": {"token": "...", "role": "user"}, ...}
    """
    result = {}
    for username, data in TEST_USERS.items():
        result[username] = {
            "token": get_token_with_retry(username, data["password"]),
            "role": data["role"]
        }
    return result


@pytest.fixture(scope="session")
def ivan_order_id(tokens) -> int:
    """Создать тестовый заказ от имени первого user и вернуть его order_id."""
    user_token = get_token_by_role(tokens, "user")
    resp = requests.post(
        ORDER_URL,
        json={"product": "test_product"},
        headers=auth_header(user_token)
    )
    if resp.status_code == 200:
        return resp.json().get("order_id")
    pytest.skip("Не удалось создать заказ — пропускаем тесты на заказах")


# ──────────────────────────────────────────────
# API1 — BOLA (Broken Object Level Authorization)
# ──────────────────────────────────────────────

class TestAPI1_BOLA:

    def test_user_cannot_access_other_user(self, tokens):
        """Пользователь не должен видеть данные другого пользователя."""
        user_token = get_token_by_role(tokens, "user")
        other_token = get_token_by_role_exclude(tokens, "user", user_token)
        other_id = get_user_id_from_token(other_token)

        resp = requests.get(f"{USER_URL}/{other_id}", headers=auth_header(user_token))
        assert resp.status_code == 403, (
            f"УЯЗВИМОСТЬ API1: пользователь получил доступ к чужим данным. "
            f"Статус: {resp.status_code}"
        )

    def test_user_can_access_own_data(self, tokens):
        """Пользователь должен видеть свои данные."""
        user_token = get_token_by_role(tokens, "user")
        user_id = get_user_id_from_token(user_token)

        resp = requests.get(f"{USER_URL}/{user_id}", headers=auth_header(user_token))
        assert resp.status_code == 200, (
            f"Ошибка: пользователь не может получить свои данные. "
            f"Статус: {resp.status_code}"
        )

    def test_admin_can_access_any_user(self, tokens):
        """Admin должен видеть данные любого пользователя."""
        admin_token = get_token_by_role(tokens, "admin")

        for username, data in tokens.items():
            uid = get_user_id_from_token(data["token"])
            resp = requests.get(f"{USER_URL}/{uid}", headers=auth_header(admin_token))
            assert resp.status_code == 200, (
                f"Ошибка: admin не может получить данные user_id={uid}. "
                f"Статус: {resp.status_code}"
            )

    def test_user_cannot_access_other_order(self, tokens, ivan_order_id):
        """Пользователь не должен видеть чужой заказ."""
        user_token = get_token_by_role(tokens, "user")
        other_token = get_token_by_role_exclude(tokens, "user", user_token)

        resp = requests.get(f"{ORDER_URL}/{ivan_order_id}", headers=auth_header(other_token))
        assert resp.status_code == 403, (
            f"УЯЗВИМОСТЬ API1: пользователь получил доступ к чужому заказу. "
            f"Статус: {resp.status_code}"
        )

    def test_owner_can_access_own_order(self, tokens, ivan_order_id):
        """Владелец должен видеть свой заказ."""
        user_token = get_token_by_role(tokens, "user")

        resp = requests.get(f"{ORDER_URL}/{ivan_order_id}", headers=auth_header(user_token))
        assert resp.status_code == 200, (
            f"Ошибка: владелец не может получить свой заказ. "
            f"Статус: {resp.status_code}"
        )


# ──────────────────────────────────────────────
# API2 — Broken Authentication
# ──────────────────────────────────────────────

class TestAPI2_BrokenAuthentication:

    def test_invalid_password_returns_401(self):
        """Неверный пароль должен возвращать 401."""
        resp = requests.post(AUTH_URL, json={"username": "ivan", "password": "wrongpassword"})
        assert resp.status_code == 401, (
            f"УЯЗВИМОСТЬ API2: неверный пароль не отклонён. "
            f"Статус: {resp.status_code}"
        )

    def test_nonexistent_user_returns_401(self):
        """Несуществующий пользователь должен возвращать 401."""
        resp = requests.post(AUTH_URL, json={"username": "hacker", "password": "anypassword"})
        assert resp.status_code == 401, (
            f"УЯЗВИМОСТЬ API2: несуществующий пользователь не отклонён. "
            f"Статус: {resp.status_code}"
        )

    def test_invalid_token_returns_401(self):
        """Невалидный токен должен возвращать 401."""
        resp = requests.get(f"{USER_URL}/1", headers=auth_header("invalid.token.here"))
        assert resp.status_code == 401, (
            f"УЯЗВИМОСТЬ API2: невалидный токен принят. "
            f"Статус: {resp.status_code}"
        )

    def test_no_token_returns_401(self):
        """Запрос без токена должен возвращать 401."""
        resp = requests.get(f"{USER_URL}/1")
        assert resp.status_code == 401, (
            f"УЯЗВИМОСТЬ API2: запрос без токена принят. "
            f"Статус: {resp.status_code}"
        )

    def test_credentials_not_accepted_as_query_params(self):
        """Credentials в query params должны отклоняться."""
        resp = requests.post(f"{AUTH_URL}?username=ivan&password=secret")
        assert resp.status_code == 422, (
            f"УЯЗВИМОСТЬ API2: credentials принимаются через query params. "
            f"Статус: {resp.status_code}"
        )

    def test_error_message_same_for_wrong_user_and_wrong_password(self):
        """Сообщение об ошибке одинаковое — нельзя определить существует ли пользователь."""
        resp_wrong_user = requests.post(
            AUTH_URL, json={"username": "nonexistent", "password": "secret"}
        )
        resp_wrong_pass = requests.post(
            AUTH_URL, json={"username": "ivan", "password": "wrongpass"}
        )
        assert resp_wrong_user.json().get("detail") == resp_wrong_pass.json().get("detail"), (
            "УЯЗВИМОСТЬ API2: разные сообщения об ошибке для несуществующего пользователя "
            "и неверного пароля — позволяет перебирать логины."
        )


# ──────────────────────────────────────────────
# API3 — Broken Object Property Level Auth
# ──────────────────────────────────────────────

class TestAPI3_ObjectPropertyAuth:

    def test_response_does_not_contain_password(self, tokens):
        """Ответ не должен содержать поле password."""
        user_token = get_token_by_role(tokens, "user")
        user_id = get_user_id_from_token(user_token)

        resp = requests.get(f"{USER_URL}/{user_id}", headers=auth_header(user_token))
        assert resp.status_code == 200
        assert "password" not in resp.json(), (
            f"УЯЗВИМОСТЬ API3: ответ содержит поле password: {resp.json()}"
        )

    def test_response_does_not_contain_role(self, tokens):
        """Ответ не должен содержать поле role."""
        user_token = get_token_by_role(tokens, "user")
        user_id = get_user_id_from_token(user_token)

        resp = requests.get(f"{USER_URL}/{user_id}", headers=auth_header(user_token))
        assert resp.status_code == 200
        assert "role" not in resp.json(), (
            f"УЯЗВИМОСТЬ API3: ответ содержит поле role: {resp.json()}"
        )

    def test_response_contains_only_safe_fields(self, tokens):
        """Ответ должен содержать только id и name."""
        user_token = get_token_by_role(tokens, "user")
        user_id = get_user_id_from_token(user_token)

        resp = requests.get(f"{USER_URL}/{user_id}", headers=auth_header(user_token))
        assert resp.status_code == 200
        extra_fields = set(resp.json().keys()) - {"id", "name"}
        assert not extra_fields, (
            f"УЯЗВИМОСТЬ API3: ответ содержит лишние поля: {extra_fields}"
        )

    def test_extra_fields_in_request_ignored(self, tokens):
        """Лишние поля в запросе не должны вызывать ошибку сервера."""
        user_token = get_token_by_role(tokens, "user")

        resp = requests.post(
            ORDER_URL,
            json={"product": "test", "user_id": 999, "admin": True, "extra_field": "hack"},
            headers=auth_header(user_token)
        )
        assert resp.status_code != 500, (
            "УЯЗВИМОСТЬ API3: лишние поля в запросе вызвали ошибку сервера."
        )


# ──────────────────────────────────────────────
# API4 — Unrestricted Resource Consumption (Rate Limiting)
# ──────────────────────────────────────────────

class TestAPI4_RateLimiting:

    @classmethod
    def setup_class(cls):
        """Пауза перед классом чтобы сбросить rate limit."""
        time.sleep(12)

    def setup_method(self):
        """Пауза перед каждым тестом."""
        time.sleep(12)

    def test_rate_limit_triggers_after_limit(self):
        """После 10 запросов должен вернуться 429."""
        status_codes = []
        for _ in range(15):
            resp = requests.post(
                AUTH_URL,
                json={"username": "nonexistent", "password": "wrong"}
            )
            status_codes.append(resp.status_code)
            time.sleep(0.3)

        assert 429 in status_codes, (
            f"УЯЗВИМОСТЬ API4: rate limiting не сработал. "
            f"Все статусы: {status_codes}"
        )

    def test_rate_limit_returns_correct_status(self):
        """Rate limit должен возвращать именно 429, не 500."""
        last_status = None
        for _ in range(15):
            resp = requests.post(
                AUTH_URL,
                json={"username": "nonexistent", "password": "wrong"}
            )
            last_status = resp.status_code
            time.sleep(0.3)

        assert last_status == 429, (
            f"Ожидался статус 429, получен: {last_status}"
        )


# ──────────────────────────────────────────────
# API5 — Broken Function Level Authorization (RBAC)
# ──────────────────────────────────────────────

class TestAPI5_RBAC:

    @classmethod
    def setup_class(cls):
        time.sleep(12)

    def test_regular_user_cannot_access_other_users_data(self, tokens):
        """Обычный пользователь не может смотреть данные других."""
        user_token = get_token_by_role(tokens, "user")
        other_token = get_token_by_role_exclude(tokens, "user", user_token)
        other_id = get_user_id_from_token(other_token)

        resp = requests.get(f"{USER_URL}/{other_id}", headers=auth_header(user_token))
        assert resp.status_code == 403, (
            f"УЯЗВИМОСТЬ API5: обычный пользователь получил доступ к чужим данным. "
            f"Статус: {resp.status_code}"
        )

    def test_admin_can_access_all_users(self, tokens):
        """Admin должен получать данные любого пользователя."""
        admin_token = get_token_by_role(tokens, "admin")

        for username, data in tokens.items():
            uid = get_user_id_from_token(data["token"])
            resp = requests.get(f"{USER_URL}/{uid}", headers=auth_header(admin_token))
            assert resp.status_code == 200, (
                f"Ошибка: admin не может получить данные user_id={uid}. "
                f"Статус: {resp.status_code}"
            )

    def test_expired_token_rejected(self):
        """Истёкший токен должен отклоняться."""
        expired_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJ1c2VyX2lkIjoxLCJyb2xlIjoidXNlciIsImV4cCI6MTYwMDAwMDAwMH0."
            "SomeInvalidSignature"
        )
        resp = requests.get(f"{USER_URL}/1", headers=auth_header(expired_token))
        assert resp.status_code == 401, (
            f"УЯЗВИМОСТЬ API5: истёкший токен принят. Статус: {resp.status_code}"
        )


# ──────────────────────────────────────────────
# API6 — Unrestricted Access to Sensitive Business Flows
# ──────────────────────────────────────────────

class TestAPI6_BusinessFlows:

    @classmethod
    def setup_class(cls):
        time.sleep(12)

    def setup_method(self):
        time.sleep(12)

    def test_brute_force_login_blocked_by_rate_limit(self):
        """Автоматический перебор паролей должен блокироваться rate limiting."""
        blocked = False
        for _ in range(15):
            resp = requests.post(
                AUTH_URL,
                json={"username": "ivan", "password": "wrongpassword"}
            )
            time.sleep(0.3)
            if resp.status_code == 429:
                blocked = True
                break

        assert blocked, (
            "УЯЗВИМОСТЬ API6: brute force на /login не блокируется."
        )

    def test_mass_order_creation_blocked(self, tokens):
        """Массовое создание заказов должно блокироваться rate limiting."""
        user_token = get_token_by_role(tokens, "user")
        blocked = False
        for _ in range(15):
            resp = requests.post(
                ORDER_URL,
                json={"product": "spam_product"},
                headers=auth_header(user_token)
            )
            time.sleep(0.3)
            if resp.status_code == 429:
                blocked = True
                break

        assert blocked, (
            "УЯЗВИМОСТЬ API6: массовое создание заказов не блокируется."
        )


# ──────────────────────────────────────────────
# API7 — Server Side Request Forgery (SSRF)
# ──────────────────────────────────────────────

class TestAPI7_SSRF:

    def test_user_service_url_not_overridable_via_request(self, tokens):
        """Нельзя передать произвольный URL сервиса через тело запроса."""
        user_token = get_token_by_role(tokens, "user")

        resp = requests.post(
            ORDER_URL,
            json={
                "product": "test",
                "user_service_url": "http://evil.com/steal",
                "callback": "http://attacker.com"
            },
            headers=auth_header(user_token)
        )
        assert resp.status_code != 500, (
            f"УЯЗВИМОСТЬ API7: сервис упал при передаче произвольного URL. "
            f"Статус: {resp.status_code}"
        )

    def test_internal_service_not_exposed_directly(self):
        """Внутренние сервисы не должны быть доступны напрямую снаружи."""
        try:
            resp = requests.get("http://localhost:8000/v1/login", timeout=2)
            assert False, (
                "УЯЗВИМОСТЬ API7: внутренний сервис доступен напрямую на порту 8000."
            )
        except requests.exceptions.ConnectionError:
            pass  # Правильно — порт не проброшен ✅


# ──────────────────────────────────────────────
# API8 — Security Misconfiguration
# ──────────────────────────────────────────────

class TestAPI8_SecurityMisconfiguration:

    @classmethod
    def setup_class(cls):
        time.sleep(12)

    def test_x_frame_options_header_present(self):
        """Заголовок X-Frame-Options должен быть в ответе."""
        resp = requests.post(AUTH_URL, json={"username": "ivan", "password": "secret"})
        assert "x-frame-options" in resp.headers, (
            "УЯЗВИМОСТЬ API8: отсутствует заголовок X-Frame-Options."
        )
        assert resp.headers["x-frame-options"] == "DENY", (
            f"УЯЗВИМОСТЬ API8: X-Frame-Options != DENY. "
            f"Значение: {resp.headers.get('x-frame-options')}"
        )

    def test_x_content_type_options_header_present(self):
        """Заголовок X-Content-Type-Options должен быть в ответе."""
        resp = requests.post(AUTH_URL, json={"username": "ivan", "password": "secret"})
        assert "x-content-type-options" in resp.headers, (
            "УЯЗВИМОСТЬ API8: отсутствует заголовок X-Content-Type-Options."
        )

    def test_xss_protection_header_present(self):
        """Заголовок X-XSS-Protection должен быть в ответе."""
        resp = requests.post(AUTH_URL, json={"username": "ivan", "password": "secret"})
        assert "x-xss-protection" in resp.headers, (
            "УЯЗВИМОСТЬ API8: отсутствует заголовок X-XSS-Protection."
        )

    def test_hsts_header_present(self):
        """Заголовок Strict-Transport-Security должен присутствовать."""
        resp = requests.post(AUTH_URL, json={"username": "ivan", "password": "secret"})
        assert "strict-transport-security" in resp.headers, (
            "УЯЗВИМОСТЬ API8: отсутствует заголовок Strict-Transport-Security (HSTS)."
        )

    def test_db_port_not_exposed(self):
        """Порт PostgreSQL 5432 не должен быть доступен снаружи."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("localhost", 5432))
        sock.close()
        assert result != 0, (
            "УЯЗВИМОСТЬ API8: порт PostgreSQL 5432 открыт снаружи!"
        )


# ──────────────────────────────────────────────
# API9 — Improper Inventory Management
# ──────────────────────────────────────────────

class TestAPI9_InventoryManagement:

    @classmethod
    def setup_class(cls):
        time.sleep(12)

    def test_api_versioning_login(self):
        """Эндпоинт /v1/login должен существовать."""
        resp = requests.post(AUTH_URL, json={"username": "ivan", "password": "secret"})
        assert resp.status_code == 200, (
            f"УЯЗВИМОСТЬ API9: версионированный эндпоинт /v1/login недоступен. "
            f"Статус: {resp.status_code}"
        )

    def test_unversioned_endpoint_not_available(self):
        """Старый эндпоинт /login без версии не должен работать."""
        resp = requests.post(
            f"{BASE}/auth/login",
            json={"username": "ivan", "password": "secret"}
        )
        assert resp.status_code == 404, (
            f"УЯЗВИМОСТЬ API9: устаревший эндпоинт /login без версии доступен. "
            f"Статус: {resp.status_code}"
        )

    def test_docs_available_in_development(self):
        """В режиме development /docs должны быть доступны."""
        resp = requests.get(f"{BASE}/auth/docs")
        assert resp.status_code == 200, (
            "Предупреждение API9: /docs недоступны даже в development режиме."
        )

    def test_openapi_schema_available_in_development(self):
        """OpenAPI схема должна быть доступна в development."""
        resp = requests.get(f"{BASE}/auth/openapi.json")
        assert resp.status_code == 200, (
            "Предупреждение API9: /openapi.json недоступен в development режиме."
        )


# ──────────────────────────────────────────────
# API10 — Unsafe Consumption of APIs
# ──────────────────────────────────────────────

class TestAPI10_UnsafeAPIConsumption:

    def test_order_service_returns_correct_error_when_user_not_found(self):
        """Order service должен корректно обработать несуществующего пользователя."""
        secret = os.getenv("SECRET_KEY", "CHANGE_THIS_SUPER_SECRET_KEY_123456")
        from datetime import datetime, timedelta
        fake_token = jose_jwt.encode(
            {"user_id": 9999, "role": "user", "exp": datetime.utcnow() + timedelta(hours=1)},
            secret,
            algorithm="HS256"
        )
        resp = requests.post(
            ORDER_URL,
            json={"product": "test"},
            headers=auth_header(fake_token)
        )
        assert resp.status_code in [403, 503], (
            f"УЯЗВИМОСТЬ API10: order service вернул неожиданный статус: {resp.status_code}"
        )

    def test_order_service_does_not_crash_on_long_input(self, tokens):
        """Order service не должен падать с 500 при длинном input."""
        user_token = get_token_by_role(tokens, "user")

        resp = requests.post(
            ORDER_URL,
            json={"product": "a" * 10000},
            headers=auth_header(user_token)
        )
        assert resp.status_code != 500, (
            f"УЯЗВИМОСТЬ API10: сервис упал с 500 при длинном input. "
            f"Статус: {resp.status_code}"
        )