from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer
from jose import jwt

SECRET_KEY = "supersecret"

app = FastAPI()

security = HTTPBearer()

users = {
    1: {"id": 1, "name": "Ivan"},
    2: {"id": 2, "name": "Anna"}
}

@app.get("/users/{user_id}")
def get_user(user_id: int, token=Depends(security)):

    payload = jwt.decode(
        token.credentials,
        SECRET_KEY,
        algorithms=["HS256"]
    )

    if payload["user_id"] != user_id:
        return {"error": "access denied"}

    return users[user_id]