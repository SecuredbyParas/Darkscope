"""
database.py
Handles SQLite schema creation and seeding of the simulated breach dataset.

IMPORTANT (educational project):
All "leaked" records in the breach_dataset table are entirely synthetic.
No real credentials, real people, or real breach data are used anywhere
in this project. The dataset exists only to let the app demonstrate, in a
safe sandbox, how a credential *would* appear inside a leaked dataset.
"""

import sqlite3
import os
import hashlib
import random

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "app.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            mfa_secret TEXT,
            mfa_enabled INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS breach_dataset (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            source_name TEXT NOT NULL,
            breach_year INTEGER NOT NULL,
            exposed_fields TEXT NOT NULL,
            mitre_techniques TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scanned_email TEXT NOT NULL,
            result TEXT NOT NULL,
            matched_sources TEXT,
            scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    conn.commit()

    cur.execute("SELECT COUNT(*) AS c FROM breach_dataset")
    if cur.fetchone()["c"] == 0:
        _seed_breach_dataset(conn)

    conn.close()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _seed_breach_dataset(conn):
    """
    Populate breach_dataset with synthetic, clearly-fake leaked records.
    Each record is tagged with the MITRE ATT&CK technique(s) most relevant
    to that style of exposure, so the dashboard / warning pages can teach
    the connection between a leak and real-world attacker behavior.
    """
    fake_sources = [
        ("CollectionX-Demo", 2019, "T1589.001,T1110.001"),
        ("RetailBreachSim-Demo", 2021, "T1589.002,T1078"),
        ("SocialLeakSim-Demo", 2020, "T1589.001,T1566.002"),
        ("ForumDumpSim-Demo", 2022, "T1110.003,T1078.004"),
        ("CloudMisconfigSim-Demo", 2023, "T1530,T1078"),
    ]

    sample_emails = [
        "demo.user1@example.com",
        "demo.user2@example.com",
        "test.account@example.com",
        "student.demo@example.com",
        "alice.demo@example.com",
        "bob.demo@example.com",
        "krishna.demo@example.com",
        "paras.demo@example.com",
        "kanika.demo@example.com",
        "devender.demo@example.com",
        "sample.victim@example.com",
        "leaked.sample01@example.com",
    ]

    rows = []
    for email in sample_emails:
        # Each fake email shows up in 1-3 of the simulated breach sources
        n_sources = random.randint(1, 3)
        chosen = random.sample(fake_sources, n_sources)
        for source_name, year, techniques in chosen:
            fake_password = f"DemoPass{random.randint(100,999)}!"
            exposed = random.choice([
                "email,password",
                "email,password,username",
                "email,password,phone",
                "email,password,full_name",
            ])
            rows.append((
                email,
                _hash(fake_password),
                source_name,
                year,
                exposed,
                techniques,
            ))

    conn.executemany(
        """INSERT INTO breach_dataset
           (email, password_hash, source_name, breach_year, exposed_fields, mitre_techniques)
           VALUES (?, ?, ?, ?, ?, ?)""",
        rows,
    )
    conn.commit()


if __name__ == "__main__":
    init_db()
    print(f"Database initialised at {DB_PATH}")
