"""SQLite persistence (swap for Postgres in production; the SQL is portable enough)."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS protected_images(
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, label TEXT, phash TEXT NOT NULL, dhash TEXT NOT NULL,
  sha256 TEXT NOT NULL, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_protected_owner ON protected_images(owner);

CREATE TABLE IF NOT EXISTS watermarks(
  wm_id TEXT PRIMARY KEY, owner TEXT NOT NULL, label TEXT, created TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS cases(
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL, platform TEXT, content_type TEXT,
  is_minor INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'open', created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_cases_owner ON cases(owner);

CREATE TABLE IF NOT EXISTS evidence(
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), owner TEXT NOT NULL, seq INTEGER NOT NULL,
  kind TEXT, mime TEXT, size INTEGER NOT NULL DEFAULT 0, sha256 TEXT, stored_name TEXT,
  source_url TEXT, platform TEXT, note TEXT, captured_at TEXT NOT NULL, analysis_json TEXT,
  analysis_sha256 TEXT, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL,
  UNIQUE(case_id, seq));

CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, level TEXT, code TEXT, title TEXT,
  message TEXT, action TEXT, created TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_alerts_owner ON alerts(owner, is_read);
"""


def _connect() -> sqlite3.Connection:
    c = sqlite3.connect(config.DB_PATH, timeout=30, isolation_level=None)  # manual transactions
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    return c


@contextmanager
def tx():
    """BEGIN IMMEDIATE so concurrent writers (e.g. evidence hash chain) are serialised."""
    c = _connect()
    try:
        c.execute("BEGIN IMMEDIATE")
        yield c
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    finally:
        c.close()


def query(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    c = _connect()
    try:
        return c.execute(sql, params).fetchall()
    finally:
        c.close()


def init_db() -> None:
    c = _connect()
    try:
        c.executescript(SCHEMA)
    finally:
        c.close()
