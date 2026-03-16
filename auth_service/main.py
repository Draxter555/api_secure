from fastapi import FastAPI

app = FastAPI()

users = {
    "ivan": "1234",
    "anna": "1234"
}

@app.post("/login")
def login(username: str, password: str):
    if users.get(username) == password:
        return {"message": "login successful"}
    return {"message": "invalid credentials"}