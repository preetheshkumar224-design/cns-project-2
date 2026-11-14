import argparse
import os
import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('doctor', 'patient')),
    patient_id TEXT
);
CREATE TABLE IF NOT EXISTS patients (
    id TEXT PRIMARY KEY,
    encrypted_record BYTEA NOT NULL
);
"""


def migrate(source_path, database_url):
    source_path = Path(source_path)
    if not source_path.is_file():
        raise FileNotFoundError(f"SQLite database not found: {source_path}")

    source = sqlite3.connect(source_path)
    try:
        accounts = source.execute(
            "SELECT id, username, password_hash, role, patient_id FROM accounts"
        ).fetchall()
        patients = source.execute(
            "SELECT id, encrypted_record FROM patients"
        ).fetchall()
    finally:
        source.close()

    from psycopg import connect
    from psycopg.conninfo import make_conninfo

    conninfo = make_conninfo(database_url, sslmode="require", connect_timeout=10)
    with connect(conninfo) as destination:
        with destination.cursor() as cursor:
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    cursor.execute(statement)
            cursor.executemany(
                """
                INSERT INTO patients (id, encrypted_record)
                VALUES (%s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                patients,
            )
            cursor.executemany(
                """
                INSERT INTO accounts (id, username, password_hash, role, patient_id)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                accounts,
            )

    return len(accounts), len(patients)


def main():
    parser = argparse.ArgumentParser(
        description="Copy existing encrypted SQLite records into Neon PostgreSQL."
    )
    parser.add_argument(
        "--source",
        default=str(Path(__file__).resolve().parent / "instance" / "patients.sqlite3"),
        help="Path to the existing SQLite database.",
    )
    args = parser.parse_args()
    database_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
    if not database_url:
        parser.error("Set DATABASE_URL (or POSTGRES_URL) to the Neon connection string.")
    accounts, patients = migrate(args.source, database_url)
    print(f"Processed {accounts} account rows and {patients} encrypted patient rows.")


if __name__ == "__main__":
    main()
