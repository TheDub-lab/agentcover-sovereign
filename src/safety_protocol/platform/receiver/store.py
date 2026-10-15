# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Michael / TheDub-lab
"""
SQLite store for the log receiver.

Append-only by construction: the only write paths are ``append_*`` inserts.
Nothing in this module issues UPDATE or DELETE against ``events`` or
``receipts`` — the chain and the receipts are immutable once written. Back up
the database file nightly, off the VPS.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone

from ...shipping import ZERO_HASH, verify_event_hash

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id  TEXT PRIMARY KEY,
    name       TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    agent_id     TEXT PRIMARY KEY,
    client_id    TEXT,
    api_key_hash TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    agent_id    TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    event_id    TEXT,
    hash        TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    ts          TEXT,
    decision    TEXT,
    received_at TEXT NOT NULL,
    payload     TEXT NOT NULL,
    PRIMARY KEY (agent_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_events_agent_ts ON events (agent_id, ts);
CREATE TABLE IF NOT EXISTS receipts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT NOT NULL,
    head_seq    INTEGER NOT NULL,
    head_hash   TEXT NOT NULL,
    received_at TEXT NOT NULL,
    sig         TEXT NOT NULL,
    sig_alg     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS heartbeats (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      TEXT NOT NULL,
    ts            TEXT,
    head_seq      INTEGER,
    head_hash     TEXT,
    mode          TEXT,
    config_hash   TEXT,
    guard_version TEXT,
    received_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Store:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # -- clients -------------------------------------------------------
    def create_client(self, client_id: str, name: str) -> dict:
        self.conn.execute(
            "INSERT OR IGNORE INTO clients (client_id, name, created_at) VALUES (?,?,?)",
            (client_id, name, _now()))
        self.conn.commit()
        return self.get_client(client_id)

    def get_client(self, client_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM clients WHERE client_id=?", (client_id,)).fetchone()
        return dict(row) if row else None

    # -- agents --------------------------------------------------------
    def create_agent(self, agent_id: str, client_id: str, api_key_hash: str) -> dict:
        self.conn.execute(
            "INSERT INTO agents (agent_id, client_id, api_key_hash, created_at) "
            "VALUES (?,?,?,?)",
            (agent_id, client_id, api_key_hash, _now()))
        self.conn.commit()
        return self.get_agent(agent_id)

    def get_agent(self, agent_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return dict(row) if row else None

    def get_agent_by_key_hash(self, api_key_hash: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM agents WHERE api_key_hash=?", (api_key_hash,)).fetchone()
        return dict(row) if row else None

    def list_agents(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM agents ORDER BY created_at").fetchall()
        return [dict(r) for r in rows]

    # -- events --------------------------------------------------------
    def head(self, agent_id: str) -> tuple[int, str]:
        row = self.conn.execute(
            "SELECT hash, seq FROM events WHERE agent_id=? ORDER BY seq DESC LIMIT 1",
            (agent_id,)).fetchone()
        if not row:
            return 0, ZERO_HASH
        return row["seq"], row["hash"]

    def get_event(self, agent_id: str, seq: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM events WHERE agent_id=? AND seq=?", (agent_id, seq)).fetchone()
        return dict(row) if row else None

    def append_event(self, agent_id: str, event: dict) -> None:
        self.conn.execute(
            "INSERT INTO events (agent_id, seq, event_id, hash, prev_hash, ts, "
            "decision, received_at, payload) VALUES (?,?,?,?,?,?,?,?,?)",
            (agent_id, event["seq"], event.get("event_id"), event["hash"],
             event["prev_hash"], event.get("ts"), event.get("decision"),
             _now(), json.dumps(event, sort_keys=True)))
        self.conn.commit()

    def events(self, agent_id: str, from_seq: int | None = None,
               to_seq: int | None = None, decision: str | None = None,
               limit: int = 1000) -> list[dict]:
        q = "SELECT payload FROM events WHERE agent_id=?"
        args: list = [agent_id]
        if from_seq is not None:
            q += " AND seq>=?"
            args.append(from_seq)
        if to_seq is not None:
            q += " AND seq<=?"
            args.append(to_seq)
        if decision is not None:
            q += " AND decision=?"
            args.append(decision)
        q += " ORDER BY seq LIMIT ?"
        args.append(limit)
        rows = self.conn.execute(q, args).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def count_events(self, agent_id: str) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM events WHERE agent_id=?", (agent_id,)).fetchone()[0]

    def verify_chain(self, agent_id: str) -> dict:
        """Recompute the stored chain. Returns {ok, head_seq, head_hash, first_break}."""
        rows = self.conn.execute(
            "SELECT payload FROM events WHERE agent_id=? ORDER BY seq", (agent_id,)
        ).fetchall()
        prev = ZERO_HASH
        expected_seq = 1
        first_break = None
        head_seq, head_hash = 0, ZERO_HASH
        for r in rows:
            ev = json.loads(r["payload"])
            if first_break is None and (
                    ev.get("seq") != expected_seq
                    or ev.get("prev_hash") != prev
                    or not verify_event_hash(ev)):
                first_break = ev.get("seq")
            prev = ev.get("hash")
            expected_seq = ev.get("seq", expected_seq) + 1
            head_seq, head_hash = ev.get("seq"), ev.get("hash")
        return {
            "ok": first_break is None,
            "head_seq": head_seq,
            "head_hash": head_hash,
            "first_break": first_break,
        }

    # -- receipts ------------------------------------------------------
    def append_receipt(self, receipt: dict) -> None:
        self.conn.execute(
            "INSERT INTO receipts (agent_id, head_seq, head_hash, received_at, "
            "sig, sig_alg, created_at) VALUES (?,?,?,?,?,?,?)",
            (receipt["agent_id"], receipt["head_seq"], receipt["head_hash"],
             receipt["received_at"], receipt["sig"], receipt.get("sig_alg", ""),
             _now()))
        self.conn.commit()

    def latest_receipt(self, agent_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM receipts WHERE agent_id=? ORDER BY id DESC LIMIT 1",
            (agent_id,)).fetchone()
        return dict(row) if row else None

    def receipts(self, agent_id: str, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM receipts WHERE agent_id=? ORDER BY id DESC LIMIT ?",
            (agent_id, limit)).fetchall()
        return [dict(r) for r in rows]

    # -- heartbeats ----------------------------------------------------
    def append_heartbeat(self, agent_id: str, hb: dict) -> None:
        self.conn.execute(
            "INSERT INTO heartbeats (agent_id, ts, head_seq, head_hash, mode, "
            "config_hash, guard_version, received_at) VALUES (?,?,?,?,?,?,?,?)",
            (agent_id, hb.get("ts"), hb.get("head_seq"), hb.get("head_hash"),
             hb.get("mode"), hb.get("config_hash"), hb.get("guard_version"),
             _now()))
        self.conn.commit()

    def latest_heartbeat(self, agent_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM heartbeats WHERE agent_id=? ORDER BY id DESC LIMIT 1",
            (agent_id,)).fetchone()
        return dict(row) if row else None

    # -- meta (signing key persistence) --------------------------------
    def meta_get(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def meta_set(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        self.conn.commit()
