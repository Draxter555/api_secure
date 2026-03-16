from fastapi import FastAPI

app = FastAPI()

orders = {
    1: {"id": 1, "user_id": 1, "product": "Laptop"},
    2: {"id": 2, "user_id": 2, "product": "Phone"}
}

@app.get("/orders")
def get_orders():
    return orders

@app.get("/orders/{order_id}")
def get_order(order_id: int):
    return orders.get(order_id)