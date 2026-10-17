"""Shared database setup for both versions of the club portal.

The vulnerable app stores plaintext passwords (hashed=False).
The secured app stores salted hashes (hashed=True).
"""
import sqlite3

from werkzeug.security import generate_password_hash

SCHEMA = """
DROP TABLE IF EXISTS registrations;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    full_name TEXT,
    email TEXT,
    bio TEXT
);
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    event_date TEXT
);
CREATE TABLE registrations (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    note TEXT
);
"""

# (id, username, password, role, full_name, email, bio)
USERS = [
    (1, "alice", "alice123", "member", "Alice Sharma", "alice@club.test",
     "2nd year, likes web dev"),
    (2, "bob", "bob123", "member", "Bob Verma", "bob@club.test",
     "Private phone: 98765 43210"),
    (3, "admin", "admin@123", "admin", "Club Admin", "admin@club.test",
     "Keeps the club treasury sheet link"),
]

EVENTS = [
    (1, "DevSOC Hackathon", "2026-11-02"),
    (2, "Intro to Web Security", "2026-11-09"),
]

REGISTRATIONS = [
    (1, 1, 1, "Need a power socket near my seat"),
    (2, 2, 1, "Peanut allergy, please call 98765 43210"),
]


def init_db(path, hashed):
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    for uid, name, pw, role, full, email, bio in USERS:
        stored = generate_password_hash(pw) if hashed else pw
        conn.execute(
            "INSERT INTO users VALUES (?,?,?,?,?,?,?)",
            (uid, name, stored, role, full, email, bio),
        )
    conn.executemany("INSERT INTO events VALUES (?,?,?)", EVENTS)
    conn.executemany("INSERT INTO registrations VALUES (?,?,?,?)", REGISTRATIONS)
    conn.commit()
    conn.close()
