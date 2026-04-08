from passlib.context import CryptContext
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv(".env")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

conn = psycopg2.connect(
    host="localhost",
    port=5432,
    dbname=os.getenv("POSTGRES_DB"),
    user=os.getenv("POSTGRES_USER"),
    password=os.getenv("POSTGRES_PASSWORD"),
)
cur = conn.cursor()

users_auth = [
    ("ivan",  pwd_context.hash("1231"), "user"),
    ("anna",  pwd_context.hash("1232"), "user"),
    ("admin", pwd_context.hash("admin123"), "admin"),
]

users_user = [
    (1, "Ivan Ivanov",  "user"),
    (2, "Anna Petrova", "user"),
    (3, "Admin",        "admin"),
]

cur.execute("""
    CREATE TABLE IF NOT EXISTS auth_users (
        id SERIAL PRIMARY KEY,
        username VARCHAR UNIQUE NOT NULL,
        password VARCHAR NOT NULL,
        role VARCHAR NOT NULL
    )
""")

cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR NOT NULL,
        role VARCHAR NOT NULL
    )
""")

for username, hashed, role in users_auth:
    cur.execute("""
        INSERT INTO auth_users (username, password, role)
        VALUES (%s, %s, %s)
        ON CONFLICT (username) DO NOTHING
    """, (username, hashed, role))

for uid, name, role in users_user:
    cur.execute("""
        INSERT INTO users (id, name, role)
        VALUES (%s, %s, %s)
        ON CONFLICT (id) DO NOTHING
    """, (uid, name, role))

conn.commit()
cur.close()
conn.close()
print("Done! Users created.")