from fastapi import FastAPI, HTTPException, Header, Request
from jose import jwt
from datetime import datetime, timedelta
from typing import Optional
import time
import os
import uuid
import logging
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

logging.basicConfig(level=logging.INFO)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

users = {
    "ivan": {"password": pwd_context.hash("1234"), "id": 1, "role": "admin"},
    "anna": {"password": pwd_context.hash("1234"), "id": 2, "role": "user"}
}

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

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.post("/login")
def login(username: str, password: str, x_forwarded_for: Optional[str] = Header(None)):
    if not check_rate_limit(x_forwarded_for):
        raise HTTPException(status_code=429, detail="Too many attempts")

    user = users.get(username)
    if not user or not pwd_context.verify(password, user["password"]):
        logging.warning(f"Failed login attempt for {username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = jwt.encode(
        {
            "user_id": user["id"],
            "role": user["role"],
            "exp": datetime.utcnow() + timedelta(minutes=30),
            "jti": str(uuid.uuid4()),
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    logging.info(f"User {username} logged in")

    return {"access_token": token}