import sqlite3
import hashlib
import datetime

conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

# 🔹 HASH PASSWORD
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()


# 🔹 INIT DATABASE
def init_db():
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT,
        password TEXT,
        email TEXT UNIQUE,
        role TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        username TEXT,
        ip TEXT,
        device TEXT,
        location TEXT,
        status TEXT,
        time TEXT
    )
    """)

    # 🔹 Create default admin user
    cursor.execute("SELECT * FROM users WHERE email=?", ("admin@gmail.com",))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?)",
            ("admin", hash_password("123"), "admin@gmail.com", "admin")
        )
        conn.commit()


# 🔹 CREATE USER
def create_user(u, p, e):
    cursor.execute("SELECT * FROM users WHERE email=?", (e,))
    if cursor.fetchone():
        return False

    cursor.execute(
        "INSERT INTO users VALUES (?, ?, ?, ?)",
        (u, hash_password(p), e, "user")
    )
    conn.commit()
    return True


# 🔹 GET USER BY EMAIL
def get_user_by_email(email):
    cursor.execute("SELECT username FROM users WHERE email=?", (email,))
    return cursor.fetchone()


# 🔹 CHECK USER PASSWORD
def check_user(u, p):
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (u, hash_password(p))
    )
    return cursor.fetchone() is not None


# 🔹 GET USER EMAIL (for alert system)
def get_user_email(u):
    cursor.execute("SELECT email FROM users WHERE username=?", (u,))
    r = cursor.fetchone()
    return r[0] if r else None


# 🔹 GET USER ROLE
def get_user_role(u):
    cursor.execute("SELECT role FROM users WHERE username=?", (u,))
    r = cursor.fetchone()
    return r[0] if r else None


# 🔹 LOG LOGIN ATTEMPT
def log_attempt(u, ip, d, loc, v):
    status = "SUCCESS" if v else "FAILED"
    cursor.execute(
        "INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?)",
        (u, ip, d, loc, status, str(datetime.datetime.now()))
    )
    conn.commit()


# 🔹 GET FAILED ATTEMPTS
def get_failed_attempts(u):
    cursor.execute(
        "SELECT COUNT(*) FROM logs WHERE username=? AND status='FAILED'",
        (u,)
    )
    return cursor.fetchone()[0]


# 🔹 GET LAST IP
def get_last_ip(u):
    cursor.execute(
        "SELECT ip FROM logs WHERE username=? ORDER BY ROWID DESC LIMIT 1",
        (u,)
    )
    r = cursor.fetchone()
    return r[0] if r else None


# 🔹 GET LAST DEVICE
def get_last_device(u):
    cursor.execute(
        "SELECT device FROM logs WHERE username=? ORDER BY ROWID DESC LIMIT 1",
        (u,)
    )
    r = cursor.fetchone()
    return r[0] if r else None


# 🔹 GET LAST LOCATION
def get_last_location(u):
    cursor.execute(
        "SELECT location FROM logs WHERE username=? ORDER BY ROWID DESC LIMIT 1",
        (u,)
    )
    r = cursor.fetchone()
    return r[0] if r else None


# 🔹 GET ALL LOGS
def get_logs():
    cursor.execute("SELECT * FROM logs ORDER BY ROWID DESC")
    return cursor.fetchall()