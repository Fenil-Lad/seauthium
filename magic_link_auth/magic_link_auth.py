import sqlite3
from datetime import datetime, timedelta

def init_db():
    conn = sqlite3.connect('../magic_link_auth/db/magic_link_auth.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS magic_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()
