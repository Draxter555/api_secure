from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import requests
from typing import Optional
from jose import jwt, JWTError
import os

app = FastAPI()
security = HTTPBearer(auto_error=False)
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")

orders = {
    1: {"id": 1, "user_id": 1, "product": "Laptop"},
    2: {"id": 2, "user_id": 2, "product": "Phone"}
}

USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "http://localhost:8001")

def get_token(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[str]:
    return creds.credentials if creds else None

@app.get("/orders/{order_id}")
def get_order(
    order_id: int,
    token: Optional[str] = Depends(get_token)
):
    order = orders.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        # Запрашиваем данные пользователя с теми же правами
        resp = requests.get(
            f"{USER_SERVICE_URL}/users/{order['user_id']}",
            headers=headers,
            timeout=5
        )
        resp.raise_for_status()
        user = resp.json()
    except requests.exceptions.RequestException:
        # Если пользователь-сервис недоступен — не раскрываем детали
        raise HTTPException(status_code=503, detail="User service unavailable")

    # Проверка BOLA: обычный пользователь может смотреть только свои заказы
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user_id = payload.get("user_id")
            if current_user_id != order["user_id"] and payload.get("role") != "admin":
                raise HTTPException(status_code=403, detail="Access denied")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    # Возвращаем только безопасные поля
    return {
        "order_id": order["id"],
        "product": order["product"],
        "user_name": user.get("name")
    }