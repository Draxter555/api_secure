from fastapi import FastAPI, HTTPException, Header
from jose import jwt
from datetime import datetime, timedelta
from typing import Optional
import time

SECRET_KEY = "supersecret"  # в продакшене — через env

app = FastAPI()

# Хранилище пользователей с ролями
users = {
    "ivan": {"password": "1234", "id": 1, "role": "admin"},
    "anna": {"password": "1234", "id": 2, "role": "user"}
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

@app.post("/login")
def login(username: str, password: str, x_forwarded_for: Optional[str] = Header(None)):
    # Проверяем лимит запросов
    if not check_rate_limit(x_forwarded_for):
        raise HTTPException(status_code=429, detail="Too many attempts")
    
    user = users.get(username)
    if not user or user["password"] != password:
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