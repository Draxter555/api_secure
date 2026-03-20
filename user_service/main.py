from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from typing import Optional
import os

# --- Конфигурация ---
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

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
    # ИСПРАВЛЕНИЕ: checkfirst=True
    Base.metadata.create_all(bind=engine, checkfirst=True)

def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_user_id: Optional[int] = Header(None)
) -> dict:
    if creds and creds.credentials:
        try:
            payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
            uid = payload.get("user_id")
            if not uid:
                raise HTTPException(status_code=401, detail="Invalid token")
            return {"id": uid, "role": payload.get("role", "user")}
        except JWTError:
            raise HTTPException(status_code=401, detail="Token decode failed")
    
    if x_user_id:
        return {"id": x_user_id, "role": "service"}
        
    raise HTTPException(status_code=401, detail="Unauthorized")

@app.get("/users/{user_id}")
def get_user(user_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user["role"] != "admin" and current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "name": user.username,
        "role": user.role
    }