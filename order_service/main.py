from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from sqlalchemy import create_engine, Column, Integer, String, select
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from pydantic import BaseModel
import requests as http_requests
import os
import logging
import time

# --- Настройки ---
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set")

DB_USER = os.getenv("POSTGRES_USER")
DB_PASS = os.getenv("POSTGRES_PASSWORD")
DB_NAME = os.getenv("POSTGRES_DB")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_SSLMODE = os.getenv("DB_SSLMODE", "disable")

USER_SERVICE_URL = os.getenv("USER_SERVICE_URL")
if not USER_SERVICE_URL:
    raise RuntimeError("USER_SERVICE_URL environment variable is not set")

DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?sslmode={DB_SSLMODE}"

engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Модели ---
class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    product = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

# --- API9: отключаем docs в продакшне ---
ENV = os.getenv("APP_ENV", "development")
app = FastAPI(
    root_path="/order",
    docs_url="/docs" if ENV == "development" else None,
    redoc_url="/redoc" if ENV == "development" else None,
    openapi_url="/openapi.json" if ENV == "development" else None,
)

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
        logging.warning(f"Rate limit exceeded for IP {ip}")
        return JSONResponse(status_code=429, content={"detail": "Too many requests"})
    request_counts[ip].append(now)
    logging.info(f"{request.method} {request.url.path} from {ip}")
    response = await call_next(request)
    logging.info(f"Response {response.status_code} to {ip}")
    return response

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# --- DB Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Auth ---
def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
        return {"id": payload.get("user_id"), "role": payload.get("role", "user")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- Pydantic схема ---
class OrderCreate(BaseModel):
    product: str

# --- API9: версионирование ---
@app.get("/v1/orders/{order_id}")
def get_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    stmt = select(Order).where(Order.id == order_id)
    order = db.execute(stmt).scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if current_user["role"] != "admin" and current_user["id"] != order.user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return {"order_id": order.id, "product": order.product, "user_id": order.user_id}


@app.post("/v1/orders")
def create_order(
    data: OrderCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    creds: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        resp = http_requests.get(
            f"{USER_SERVICE_URL}/v1/users/{current_user['id']}",
            headers={"Authorization": f"Bearer {creds.credentials}"},
            timeout=3
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=403, detail="User not found in user service")
    except http_requests.exceptions.Timeout:
        raise HTTPException(status_code=503, detail="User service timeout")
    except http_requests.exceptions.RequestException:
        raise HTTPException(status_code=503, detail="User service unavailable")

    order = Order(user_id=current_user["id"], product=data.product)
    db.add(order)
    db.commit()
    db.refresh(order)
    return {"order_id": order.id, "product": order.product}