import json
import sqlite3
import time
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from cicflowmeter.schema import Flow


SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY,
    source     TEXT NOT NULL,
    started_at REAL NOT NULL,
    ended_at   REAL
);

CREATE TABLE IF NOT EXISTS flows (
    id            INTEGER PRIMARY KEY,
    session_id    INTEGER NOT NULL REFERENCES sessions(id),
    captured_at   REAL NOT NULL,
    transport     TEXT NOT NULL,
    src_ip        TEXT NOT NULL,
    dst_ip        TEXT NOT NULL,
    src_port      INTEGER NOT NULL,
    dst_port      INTEGER NOT NULL,
    features      TEXT NOT NULL,
    probabilities TEXT NOT NULL
);

CREATE VIEW IF NOT EXISTS classified_flow AS
SELECT
    f.id,
    f.session_id,
    f.captured_at,
    f.src_ip,
    f.dst_ip,
    f.src_port,
    f.dst_port,
    f.transport,
    (
        SELECT key
        FROM json_each(f.probabilities)
        ORDER BY value DESC, key
        LIMIT 1
    ) AS label,
    (SELECT MAX(value) FROM json_each(f.probabilities)) AS confidence
FROM flows AS f;

CREATE INDEX IF NOT EXISTS idx_flows_captured_at
ON flows(captured_at);

CREATE INDEX IF NOT EXISTS idx_flows_session_id
ON flows(session_id);
"""

RECENT_FLOWS_QUERY = """
SELECT captured_at, src_ip, dst_ip, dst_port, transport, label, confidence
FROM classified_flow
ORDER BY captured_at DESC
LIMIT ?
"""

SESSIONS_QUERY = """
SELECT
    s.id,
    s.source,
    s.started_at,
    s.ended_at,
    COUNT(f.id) AS flows,
    COALESCE(SUM(f.label != ?), 0) AS attacks
FROM sessions AS s
LEFT JOIN classified_flow AS f ON f.session_id = s.id
GROUP BY s.id
ORDER BY s.id DESC
"""


def _initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.commit()


@dataclass(frozen=True)
class FlowStore:
    _connection: sqlite3.Connection
    _session_id: int

    def write(
        self,
        flow: Flow,
        probabilities: Mapping[str, float],
    ) -> None:
        key = flow.key
        self._connection.execute(
            "INSERT INTO flows "
            "(session_id, captured_at, transport, src_ip, dst_ip, "
            "src_port, dst_port, features, probabilities) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                self._session_id,
                flow.captured_at,
                key.transport,
                key.src_ip,
                key.dst_ip,
                key.src_port,
                key.dst_port,
                _json(flow.features),
                _json(probabilities),
            ),
        )
        self._connection.commit()


def _json(value: Mapping[str, object]) -> str:
    return json.dumps(value, allow_nan=False, separators=(",", ":"))


@contextmanager
def open_flow_store(db_path: Path, source: str) -> Iterator[FlowStore]:
    with closing(sqlite3.connect(db_path)) as connection:
        _initialize(connection)
        cursor = connection.execute(
            "INSERT INTO sessions (source, started_at) VALUES (?, ?)",
            (source, time.time()),
        )
        session_id = cast(int, cursor.lastrowid)
        connection.commit()

        try:
            yield FlowStore(connection, session_id)
        finally:
            connection.execute(
                "UPDATE sessions SET ended_at = ? WHERE id = ?",
                (time.time(), session_id),
            )
            connection.commit()
