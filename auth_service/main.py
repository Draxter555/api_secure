from fastapi import FastAPI, HTTPException, Header, Request
from jose import jwt
from datetime import datetime, timedelta
from typing import Optional
import time
import os
from passlib.context import CryptContext

# Секрет ключ через env
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Хранилище пользователей с ролями и хешированными паролями
users = {
    "ivan": {"password": pwd_context.hash("1234"), "id": 1, "role": "admin"},
    "anna": {"password": pwd_context.hash("1234"), "id": 2, "role": "user"}
}

# Простейший rate limit: не больше 5 попыток входа в минуту с одного IP
login_attempts: dict[str, list[float]] = {}

def check_rate_limit(ip: Optional[str], limit: int = 5, window: int = 60) -> bool:
    if not ip:
        return True
    now = time.time()
    login_attempts.setdefault(ip, [])
    # чистим старые попытки
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < window]
    if len(login_attempts[ip]) >= limit:
        return False
    login_attempts[ip].append(now)
    return True

# Middleware для rate limit на все endpoint'ы (при желании расширяем)
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    ip = request.client.host
    if not check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="Too many requests")
    return await call_next(request)

@app.post("/login")
def login(username: str, password: str, x_forwarded_for: Optional[str] = Header(None)):
    # Проверяем лимит запросов
    if not check_rate_limit(x_forwarded_for):
        raise HTTPException(status_code=429, detail="Too many attempts")
    
    user = users.get(username)
    if not user or not pwd_context.verify(password, user["password"]):
        # Не уточняем, что именно не так — чтобы не помогать злоумышленнику
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # В токен добавляем роль — пригодится для RBAC в других сервисах
    token = jwt.encode(
        {
            "user_id": user["id"],
            "role": user["role"],
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        SECRET_KEY,
        algorithm="HS256"
    )
    return {"access_token": token, "token_type": "bearer"}