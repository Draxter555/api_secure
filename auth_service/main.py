from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy import select
from jose import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os
import logging
import time

# --- Настройки ---
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

# --- Модель пользователя для auth ---
class AuthUser(Base):
    __tablename__ = "auth_users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)

# --- FastAPI ---
app = FastAPI()
security = HTTPBearer(auto_error=False)

# --- Логирование и Rate Limiting ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
request_counts: dict[str, list[float]] = {}
RATE_LIMIT = int(os.getenv("RATE_LIMIT", 10))
WINDOW_SIZE = int(os.getenv("RATE_WINDOW", 60))

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

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- DB Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Endpoints ---
@app.post("/login")
def login(username: str, password: str, db: Session = Depends(get_db)):
    stmt = select(AuthUser).where(AuthUser.username == username)
    user = db.execute(stmt).scalar_one_or_none()
    if not user or not pwd_context.verify(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
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