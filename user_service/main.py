from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from typing import Optional
import os
from fastapi.middleware.cors import CORSMiddleware
import logging
import time
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy import Column, Integer, String

# --- Настройка ---
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
DB_USER = os.getenv("POSTGRES_USER")
DB_PASS = os.getenv("POSTGRES_PASSWORD")
DB_NAME = os.getenv("POSTGRES_DB")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_SSLMODE = os.getenv("DB_SSLMODE", "require")

DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?sslmode={DB_SSLMODE}"

engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Модель пользователя ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    role = Column(String, nullable=False)

# --- Инициализация FastAPI ---
app = FastAPI()
security = HTTPBearer(auto_error=False)

# --- Логирование ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# --- Rate Limiting ---
request_counts: dict[str, list[float]] = {}
RATE_LIMIT = int(os.getenv("RATE_LIMIT", 10))
WINDOW_SIZE = int(os.getenv("RATE_WINDOW", 60))

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.middleware("http")
async def rate_limit_and_logging(request: Request, call_next):
    ip = request.client.host
    now = time.time()
    request_counts.setdefault(ip, [])
    request_counts[ip] = [t for t in request_counts[ip] if now - t < WINDOW_SIZE]
    if len(request_counts[ip]) >= RATE_LIMIT:
        logging.warning(f"Rate limit exceeded for IP {ip} on path {request.url.path}")
        raise HTTPException(status_code=429, detail="Too many requests")
    request_counts[ip].append(now)
    logging.info(f"Incoming request {request.method} {request.url.path} from {ip}")
    response = await call_next(request)
    logging.info(f"Response {response.status_code} to {ip} for {request.url.path}")
    return response

# --- DB Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Auth + RBAC ---
def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
        return {"id": payload.get("user_id"), "role": payload.get("role", "user")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token decode failed")

def require_role(required: str):
    def checker(user: dict = Depends(get_current_user)):
        if required != "any" and user["role"] != required:
            raise HTTPException(status_code=403, detail="Access denied")
        return user
    return checker

# --- Endpoints ---
@app.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin" and current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    stmt = select(User).where(User.id == user_id)
    result = db.execute(stmt).scalar_one_or_none()
    if not result:
        raise HTTPException(status_code=404, detail="User not found")

    # Возвращаем только безопасные поля
    return {"id": result.id, "name": result.name}