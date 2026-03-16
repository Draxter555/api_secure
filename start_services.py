import subprocess
import sys

services = [
    ("auth_service", 8000),
    ("user_service", 8001),
    ("order_service", 8002)
]

processes = []

for service, port in services:
    p = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--port", str(port)],
        cwd=service
    )
    processes.append(p)

print("All services started!")

for p in processes:
    p.wait()