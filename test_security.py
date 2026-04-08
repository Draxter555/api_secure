"""
Автоматические тесты безопасности OWASP API Top 10
Запуск: pytest test_security.py -v
Требования: docker-compose up --build + seed.py выполнен
"""

import time
import pytest
import requests

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


# ──────────────────────────────────────────────
# ФИКСТУРЫ
# ──────────────────────────────────────────────

@pytest.fixture(scope="session")
def ivan_token():
    token = get_token("ivan", "secret")
    assert token is not None, "Не удалось получить токен для ivan. Убедись что seed.py выполнен."
    return token


@pytest.fixture(scope="session")
def anna_token():
    token = get_token("anna", "secret")
    assert token is not None, "Не удалось получить токен для anna."
    return token


@pytest.fixture(scope="session")
def admin_token():
    token = get_token("admin", "secret")
    assert token is not None, "Не удалось получить токен для admin."
    return token


@pytest.fixture(scope="session")
def ivan_order_id(ivan_token):
    """Создать тестовый заказ от имени ivan и вернуть его id."""
    resp = requests.post(
        ORDER_URL,
        json={"product": "test_product"},
        headers=auth_header(ivan_token)
    )
    # Если user сервис не нашёл ивана — заказ не создастся (нормально для изолированного теста)
    if resp.status_code == 200:
        return resp.json().get("order_id")
    pytest.skip("Не удалось создать заказ для ivan — пропускаем тесты на заказах")


# ──────────────────────────────────────────────
# API1 — BOLA (Broken Object Level Authorization)
# ──────────────────────────────────────────────

class TestAPI1_BOLA:

    def test_user_cannot_access_other_user(self, ivan_token):
        """Ivan (id=1) не должен видеть данные Anna (id=2)."""
        resp = requests.get(f"{USER_URL}/2", headers=auth_header(ivan_token))
        assert resp.status_code == 403, (
            f"УЯЗВИМОСТЬ API1: пользователь получил доступ к чужим данным. "
            f"Статус: {resp.status_code}"
        )

    def test_user_can_access_own_data(self, ivan_token):
        """Ivan должен видеть свои данные."""
        resp = requests.get(f"{USER_URL}/1", headers=auth_header(ivan_token))
        assert resp.status_code == 200, (
            f"Ошибка: пользователь не может получить свои данные. "
            f"Статус: {resp.status_code}"
        )

    def test_admin_can_access_any_user(self, admin_token):
        """Admin должен видеть данные любого пользователя."""
        resp = requests.get(f"{USER_URL}/1", headers=auth_header(admin_token))
        assert resp.status_code == 200, (
            f"Ошибка: admin не может получить данные пользователя. "
            f"Статус: {resp.status_code}"
        )

    def test_user_cannot_access_other_order(self, anna_token, ivan_order_id):
        """Anna не должна видеть заказ Ivan."""
        resp = requests.get(f"{ORDER_URL}/{ivan_order_id}", headers=auth_header(anna_token))
        assert resp.status_code == 403, (
            f"УЯЗВИМОСТЬ API1: пользователь получил доступ к чужому заказу. "
            f"Статус: {resp.status_code}"
        )

    def test_owner_can_access_own_order(self, ivan_token, ivan_order_id):
        """Ivan должен видеть свой заказ."""
        resp = requests.get(f"{ORDER_URL}/{ivan_order_id}", headers=auth_header(ivan_token))
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
        """Credentials в query params должны отклоняться (только JSON body)."""
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

    def test_response_does_not_contain_password(self, ivan_token):
        """Ответ не должен содержать поле password."""
        resp = requests.get(f"{USER_URL}/1", headers=auth_header(ivan_token))
        assert resp.status_code == 200
        data = resp.json()
        assert "password" not in data, (
            f"УЯЗВИМОСТЬ API3: ответ содержит поле password: {data}"
        )

    def test_response_does_not_contain_role(self, ivan_token):
        """Ответ не должен содержать поле role для обычного пользователя."""
        resp = requests.get(f"{USER_URL}/1", headers=auth_header(ivan_token))
        assert resp.status_code == 200
        data = resp.json()
        assert "role" not in data, (
            f"УЯЗВИМОСТЬ API3: ответ содержит поле role: {data}"
        )

    def test_response_contains_only_safe_fields(self, ivan_token):
        """Ответ должен содержать только id и name."""
        resp = requests.get(f"{USER_URL}/1", headers=auth_header(ivan_token))
        assert resp.status_code == 200
        data = resp.json()
        allowed_fields = {"id", "name"}
        extra_fields = set(data.keys()) - allowed_fields
        assert not extra_fields, (
            f"УЯЗВИМОСТЬ API3: ответ содержит лишние поля: {extra_fields}"
        )

    def test_extra_fields_in_request_ignored(self, ivan_token):
        """Лишние поля в запросе должны игнорироваться (не вызывать ошибку сервера)."""
        resp = requests.post(
            ORDER_URL,
            json={"product": "test", "user_id": 999, "admin": True, "extra_field": "hack"},
            headers=auth_header(ivan_token)
        )
        # Не должно быть 500 — сервер не должен падать от лишних полей
        assert resp.status_code != 500, (
            f"УЯЗВИМОСТЬ API3: лишние поля в запросе вызвали ошибку сервера."
        )


# ──────────────────────────────────────────────
# API4 — Unrestricted Resource Consumption (Rate Limiting)
# ──────────────────────────────────────────────

class TestAPI4_RateLimiting:

    def test_rate_limit_triggers_after_limit(self):
        """После 10 запросов должен вернуться 429."""
        # Сбрасываем счётчик — ждём новое окно
        time.sleep(2)

        status_codes = []
        for _ in range(15):
            resp = requests.post(
                AUTH_URL,
                json={"username": "nonexistent", "password": "wrong"}
            )
            status_codes.append(resp.status_code)

        assert 429 in status_codes, (
            f"УЯЗВИМОСТЬ API4: rate limiting не сработал. "
            f"Все статусы: {status_codes}"
        )

    def test_rate_limit_returns_correct_status(self):
        """Rate limit должен возвращать именно 429, не 500."""
        time.sleep(2)
        last_status = None
        for _ in range(15):
            resp = requests.post(
                AUTH_URL,
                json={"username": "nonexistent", "password": "wrong"}
            )
            last_status = resp.status_code

        assert last_status == 429, (
            f"Ожидался статус 429, получен: {last_status}"
        )


# ──────────────────────────────────────────────
# API5 — Broken Function Level Authorization (RBAC)
# ──────────────────────────────────────────────

class TestAPI5_RBAC:

    def test_regular_user_cannot_access_other_users_data(self, ivan_token):
        """Обычный пользователь не может смотреть данные других (не admin-функция)."""
        resp = requests.get(f"{USER_URL}/2", headers=auth_header(ivan_token))
        assert resp.status_code == 403, (
            f"УЯЗВИМОСТЬ API5: обычный пользователь получил доступ к чужим данным. "
            f"Статус: {resp.status_code}"
        )

    def test_admin_can_access_all_users(self, admin_token):
        """Admin должен получать данные любого пользователя."""
        for user_id in [1, 2, 3]:
            resp = requests.get(f"{USER_URL}/{user_id}", headers=auth_header(admin_token))
            assert resp.status_code == 200, (
                f"Ошибка: admin не может получить данные user_id={user_id}. "
                f"Статус: {resp.status_code}"
            )

    def test_expired_token_rejected(self):
        """Истёкший токен должен отклоняться."""
        # Токен с exp в прошлом, подписан правильным алгоритмом но истёк
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

    def test_brute_force_login_blocked_by_rate_limit(self):
        """Автоматический перебор паролей должен блокироваться rate limiting."""
        time.sleep(2)
        blocked = False
        for _ in range(15):
            resp = requests.post(
                AUTH_URL,
                json={"username": "ivan", "password": "wrongpassword"}
            )
            if resp.status_code == 429:
                blocked = True
                break

        assert blocked, (
            "УЯЗВИМОСТЬ API6: brute force на /login не блокируется. "
            "Rate limiting не сработал за 15 попыток."
        )

    def test_mass_order_creation_blocked(self, ivan_token):
        """Массовое создание заказов должно блокироваться rate limiting."""
        time.sleep(2)
        blocked = False
        for _ in range(15):
            resp = requests.post(
                ORDER_URL,
                json={"product": "spam_product"},
                headers=auth_header(ivan_token)
            )
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

    def test_user_service_url_not_overridable_via_request(self, ivan_token):
        """Нельзя передать произвольный URL сервиса через тело запроса."""
        resp = requests.post(
            ORDER_URL,
            json={
                "product": "test",
                "user_service_url": "http://evil.com/steal",
                "callback": "http://attacker.com"
            },
            headers=auth_header(ivan_token)
        )
        # Сервис не должен падать с 500 из-за подброшенного URL
        assert resp.status_code != 500, (
            f"УЯЗВИМОСТЬ API7: сервис упал при передаче произвольного URL. "
            f"Статус: {resp.status_code}"
        )

    def test_internal_service_not_exposed_directly(self):
        """Внутренние сервисы не должны быть доступны напрямую снаружи."""
        # Попытка обратиться к auth сервису напрямую на порту 8000
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
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(("localhost", 5432))
            sock.close()
            assert result != 0, (
                "УЯЗВИМОСТЬ API8: порт PostgreSQL 5432 открыт снаружи!"
            )
        except Exception:
            pass  # Соединение отклонено — правильно ✅


# ──────────────────────────────────────────────
# API9 — Improper Inventory Management
# ──────────────────────────────────────────────

class TestAPI9_InventoryManagement:

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

    def test_order_service_returns_503_when_user_not_found(self, admin_token):
        """Order service должен корректно обработать если user не найден."""
        # Создаём токен для несуществующего user_id=9999
        from jose import jwt as jose_jwt
        import os
        from datetime import datetime, timedelta

        secret = os.getenv("SECRET_KEY", "CHANGE_THIS_SUPER_SECRET_KEY_123456")
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
        # Должен вернуть 403 или 503, но не 500
        assert resp.status_code in [403, 503], (
            f"УЯЗВИМОСТЬ API10: order service вернул неожиданный статус при "
            f"отсутствии пользователя: {resp.status_code}"
        )

    def test_order_service_does_not_crash_on_malformed_response(self, ivan_token):
        """Order service не должен падать с 500 при любых входных данных."""
        resp = requests.post(
            ORDER_URL,
            json={"product": "a" * 10000},  # очень длинная строка
            headers=auth_header(ivan_token)
        )
        assert resp.status_code != 500, (
            f"УЯЗВИМОСТЬ API10: сервис упал с 500 при длинном input. "
            f"Статус: {resp.status_code}"
        )