"""
Database management module for PhishShield Phishing Awareness Simulation.
Handles SQLite connection pooling, schema migrations, and query execution.
"""

import sqlite3
import os
from typing import Dict, Any, List, Optional
from datetime import datetime

# Path to SQLite database file
DB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
DB_PATH = os.path.join(DB_DIR, "phishing_simulation.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_db_connection() -> sqlite3.Connection:
    """Creates a connection to the SQLite database with dict-like row access."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """Initializes tables using schema.sql."""
    conn = get_db_connection()
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_sql = f.read()
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()


def query_db(query: str, args: tuple = (), one: bool = False) -> Any:
    """Executes a SELECT query and returns list of dictionaries or single dictionary."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(query, args)
        rv = cur.fetchall()
        if one:
            return dict(rv[0]) if rv else None
        return [dict(row) for row in rv]
    finally:
        conn.close()


def execute_db(query: str, args: tuple = ()) -> int:
    """Executes an INSERT/UPDATE/DELETE statement and returns the lastrowid or affected rows."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(query, args)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def execute_many(query: str, seq_of_args: List[tuple]) -> int:
    """Executes batch queries within a single transaction."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.executemany(query, seq_of_args)
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
