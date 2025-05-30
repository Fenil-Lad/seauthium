import sqlite3
import bcrypt
import os
from flask import g

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'db', 'users', 'users.db')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)
    db.commit()

def standard_signup(email: str, plain_password: str) -> tuple[bool, str]:
    db = get_db()
    hashed_password = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt())
    try:
        db.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            (email, hashed_password.decode())
        )
        db.commit()
        return True, "Signup successful"
    except sqlite3.IntegrityError:
        return False, "Email already registered"

def standard_login(email: str, plain_password: str) -> tuple[bool, str]:
    db = get_db()
    cursor = db.execute("SELECT password FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()

    if not result:
        return False, "Email not found"

    stored_hash = result["password"].encode()
    if bcrypt.checkpw(plain_password.encode(), stored_hash):
        return True, "Login successful"
    else:
        return False, "Incorrect password"
