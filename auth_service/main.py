from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext
import os
import time

# --- Конфигурация ---
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

# --- Безопасность паролей ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- База данных ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Модели ---
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")
    is_active = Column(Boolean, default=True)

# --- Зависимости ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_users(db: Session):
    """Создаёт тестовых пользователей, если их нет"""
    if db.query(UserDB).filter(UserDB.username == "ivan").first():
        return
    
    users_data = [
        {"username": "ivan", "password": "1234", "role": "admin"},
        {"username": "anna", "password": "1234", "role": "user"}
    ]
    
    for u in users_data:
        # bcrypt имеет лимит 72 байта на пароль — обрезаем на всякий случай
        pwd = u["password"][:72]
        hashed = pwd_context.hash(pwd)
        db.add(UserDB(username=u["username"], hashed_password=hashed, role=u["role"]))
    
    db.commit()

# --- Приложение ---
app = FastAPI()
security = HTTPBearer(auto_error=False)

@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine, checkfirst=True)
    db = SessionLocal()
    init_users(db)
    db.close()

# --- Rate Limiting ---
login_attempts: dict[str, list[float]] = {}

def check_rate_limit(ip: Optional[str], limit: int = 5, window: int = 60) -> bool:
    if not ip:
        return True
    now = time.time()
    login_attempts.setdefault(ip, [])
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < window]
    if len(login_attempts[ip]) >= limit:
        return False
    login_attempts[ip].append(now)
    return True

@app.post("/login")
def login(username: str, password: str, x_forwarded_for: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not check_rate_limit(x_forwarded_for):
        raise HTTPException(status_code=429, detail="Too many attempts")
    
    user = db.query(UserDB).filter(UserDB.username == username).first()
    
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User inactive")

    token = jwt.encode(
        {
            "user_id": user.id,
            "role": user.role,
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        SECRET_KEY,
        algorithm="HS256"
    )
    return {"access_token": token, "token_type": "bearer"}