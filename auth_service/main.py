from fastapi import FastAPI
from jose import jwt
from datetime import datetime, timedelta

SECRET_KEY = "supersecret"

app = FastAPI()

users = {
    "ivan": {"password": "1234", "id": 1},
    "anna": {"password": "1234", "id": 2}
}

@app.post("/login")
def login(username: str, password: str):

    user = users.get(username)

    if not user or user["password"] != password:
        return {"error": "invalid credentials"}

    token = jwt.encode(
        {
            "user_id": user["id"],
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return {"access_token": token}