from fastapi import FastAPI
import requests

app = FastAPI()

orders = {
    1: {"id": 1, "user_id": 1, "product": "Laptop"},
    2: {"id": 2, "user_id": 2, "product": "Phone"}
}

@app.get("/orders/{order_id}")
def get_order(order_id: int):

    order = orders.get(order_id)

    user = requests.get(
        f"http://localhost:8001/users/{order['user_id']}"
    ).json()

    return {
        "order": order,
        "user": user
    }