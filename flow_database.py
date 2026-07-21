import json
import sqlite3
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any


Flow = Mapping[str, Any]
Prediction = Mapping[str, float]

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY,
    source     TEXT NOT NULL,
    started_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS session_ends (
    session_id INTEGER PRIMARY KEY REFERENCES sessions(id),
    ended_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY,
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    recorded_at REAL NOT NULL,
    flow        TEXT NOT NULL,
    prediction  TEXT NOT NULL
);

DROP VIEW IF EXISTS classified_flow;

CREATE VIEW classified_flow AS
SELECT
    f.id,
    f.session_id,
    f.recorded_at,
    json_extract(f.flow, '$.src_ip') AS src_ip,
    json_extract(f.flow, '$.dst_ip') AS dst_ip,
    json_extract(f.flow, '$.src_port') AS src_port,
    json_extract(f.flow, '$.dst_port') AS dst_port,
    json_extract(f.flow, '$.protocol') AS protocol,
    (
        SELECT key
        FROM json_each(f.prediction)
        ORDER BY value DESC, key
        LIMIT 1
    ) AS label,
    (SELECT MAX(value) FROM json_each(f.prediction)) AS confidence
FROM flows AS f;

CREATE INDEX IF NOT EXISTS idx_flows_recorded_at
ON flows(recorded_at);

CREATE INDEX IF NOT EXISTS idx_flows_session_id
ON flows(session_id);
"""

RECENT_FLOWS_QUERY = """
SELECT recorded_at, src_ip, dst_ip, dst_port, protocol, label, confidence
FROM classified_flow
ORDER BY recorded_at DESC
LIMIT ?
"""

SESSIONS_QUERY = """
SELECT
    s.id,
    s.source,
    s.started_at,
    e.ended_at,
    COUNT(f.id) AS flows,
    COALESCE(SUM(f.label != ?), 0) AS attacks
FROM sessions AS s
LEFT JOIN session_ends AS e ON e.session_id = s.id
LEFT JOIN classified_flow AS f ON f.session_id = s.id
GROUP BY s.id
ORDER BY s.id DESC
"""


@dataclass(frozen=True)
class Classified:
    flow: Flow
    prediction: Prediction


def initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.commit()


@dataclass(frozen=True)
class FlowStore:
    _connection: sqlite3.Connection
    _session_id: int

    def write_all(self, classified: Iterable[Classified]) -> None:
        for item in classified:
            self._connection.execute(
                "INSERT INTO flows "
                "(session_id, recorded_at, flow, prediction) "
                "VALUES (?, ?, ?, ?)",
                (
                    self._session_id,
                    time.time(),
                    _json(item.flow),
                    _json(item.prediction),
                ),
            )
            self._connection.commit()


def _json(value: Mapping[str, object]) -> str:
    return json.dumps(value, allow_nan=False, separators=(",", ":"))


@contextmanager
def open_flow_store(db_path: Path, source: str) -> Iterator[FlowStore]:
    with closing(sqlite3.connect(db_path)) as connection:
        initialize(connection)
        cursor = connection.execute(
            "INSERT INTO sessions (source, started_at) VALUES (?, ?)",
            (source, time.time()),
        )
        session_id = cursor.lastrowid
        if session_id is None:
            raise sqlite3.DatabaseError("SQLite did not create a session")
        connection.commit()

        try:
            yield FlowStore(connection, session_id)
        finally:
            connection.execute(
                "INSERT INTO session_ends (session_id, ended_at) "
                "VALUES (?, ?)",
                (session_id, time.time()),
            )
            connection.commit()
