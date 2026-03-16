from fastapi import FastAPI

app = FastAPI()

users = {
    1: {"id": 1, "name": "Ivan", "email": "ivan@test.com"},
    2: {"id": 2, "name": "Anna", "email": "anna@test.com"}
}

@app.get("/users")
def get_users():
    return users

@app.get("/users/{user_id}")
def get_user(user_id: int):
    return users.get(user_id)