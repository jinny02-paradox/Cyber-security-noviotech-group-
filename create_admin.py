
import bcrypt
import sqlite3
from getpass import getpass
from database import execute_db

username = input("Enter admin username: ").strip()
password = getpass("Enter admin password: ")

if not username or len(password) < 12:
    print("Username is required and password must be at least 12 characters.")
else:
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    try:
        execute_db(
            "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        print("Admin account created successfully!")

    except sqlite3.IntegrityError:
        print("This admin username already exists.")
