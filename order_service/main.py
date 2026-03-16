from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import requests
from typing import Optional

app = FastAPI()
security = HTTPBearer(auto_error=False)

orders = {
    1: {"id": 1, "user_id": 1, "product": "Laptop"},
    2: {"id": 2, "user_id": 2, "product": "Phone"}
}

USER_SERVICE_URL = "http://localhost:8001"

def get_token(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[str]:
    return creds.credentials if creds else None

@app.get("/orders/{order_id}")
def get_order(
    order_id: int,
    token: Optional[str] = Depends(get_token),
    x_user_id: Optional[int] = Header(None)
):
    order = orders.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Готовим заголовки для внутреннего запроса
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if x_user_id:
        headers["x-user-id"] = str(x_user_id)
    
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
    
    # Возвращаем только то, что можно показывать
    return {
        "order_id": order["id"],
        "product": order["product"],
        "user_name": user.get("name"),
        "user_role": user.get("role")  # для отладки, в продакшене можно убрать
    }