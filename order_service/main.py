from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session
import requests
from typing import Optional
import os

# --- Конфигурация ---
DATABASE_URL = os.getenv("DATABASE_URL")
USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "http://user:8000")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

# --- База данных ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Модели ---
class OrderDB(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)  # Убрали ForeignKey для простоты инициализации
    product = Column(String)
    status = Column(String, default="new")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Приложение ---
app = FastAPI()
security = HTTPBearer(auto_error=False)

@app.on_event("startup")
def startup_event():
    # Сначала создаём таблицы
    Base.metadata.create_all(bind=engine)
    
    # Потом инициализируем тестовые данные
    db = SessionLocal()
    try:
        if db.query(OrderDB).count() == 0:
            db.add_all([
                OrderDB(id=1, user_id=1, product="Laptop"),
                OrderDB(id=2, user_id=2, product="Phone")
            ])
            db.commit()
    except Exception:
        # Если таблица users ещё не готова — не критично для демо
        db.rollback()
    finally:
        db.close()

def get_token(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[str]:
    return creds.credentials if creds else None

@app.get("/orders/{order_id}")
def get_order(
    order_id: int,
    token: Optional[str] = Depends(get_token),
    db: Session = Depends(get_db)
):
    order = db.query(OrderDB).filter(OrderDB.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        resp = requests.get(
            f"{USER_SERVICE_URL}/users/{order.user_id}",
            headers=headers,
            timeout=5
        )
        resp.raise_for_status()
        user = resp.json()
    except requests.exceptions.RequestException:
        raise HTTPException(status_code=503, detail="User service unavailable")
    
    return {
        "order_id": order.id,
        "product": order.product,
        "status": order.status,
        "user_name": user.get("name")
    }