from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from typing import Optional
import os

SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
app = FastAPI()
security = HTTPBearer(auto_error=False)

users = {
    1: {"id": 1, "name": "Ivan", "role": "admin"},
    2: {"id": 2, "name": "Anna", "role": "user"}
}

def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    """Получает пользователя строго из токена"""
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
        uid = payload.get("user_id")
        if not uid or uid not in users:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"id": uid, "role": payload.get("role", "user")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token decode failed")

def require_role(required: str):
    """Декоратор-проверка роли"""
    def checker(user: dict = Depends(get_current_user)):
        if required != "any" and user["role"] != required:
            raise HTTPException(status_code=403, detail="Access denied")
        return user
    return checker

@app.get("/users/{user_id}")
def get_user(
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    # Пользователь может смотреть только свой профиль, админ — любой
    if current_user["role"] != "admin" and current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    data = users.get(user_id)
    if not data:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Возвращаем только безопасные поля
    safe_fields = {"id", "name"}  # role скрываем
    return {k: v for k, v in data.items() if k in safe_fields}