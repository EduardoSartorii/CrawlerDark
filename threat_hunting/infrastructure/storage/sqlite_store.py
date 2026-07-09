"""SQLite storage backend.

Responsibility
--------------
Durable persistence using the standard-library ``sqlite3`` module (no external
dependency). Findings are stored as JSON documents in a single table with a
denormalised ``indicator_keys`` column for indicator lookups. Real transactions
are used so ``commit``/``rollback`` behave exactly as the port promises.

A Postgres adapter would swap ``sqlite3`` for SQLAlchemy while keeping this same
public shape — no business rule changes.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Sequence

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.exceptions import StorageError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id             TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL,
    score          REAL NOT NULL,
    severity       TEXT NOT NULL,
    connector      TEXT NOT NULL,
    indicator_keys TEXT NOT NULL,
    document       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_score ON findings(score);
"""


class _SqliteFindingRepository:
    """Finding repository backed by a SQLite connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    def add(self, finding: Finding) -> None:
        """Insert or replace the finding as a JSON document."""
        self._conn.execute(
            "INSERT OR REPLACE INTO findings "
            "(id, created_at, score, severity, connector, indicator_keys, document) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                finding.id,
                finding.created_at.isoformat(),
                finding.score.value,
                finding.severity.value,
                finding.connector,
                " ".join(sorted(finding.indicator_keys)),
                json.dumps(finding.model_dump(mode="json")),
            ),
        )

    def get(self, finding_id: str) -> Finding | None:
        row = self._conn.execute(
            "SELECT document FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        return Finding.model_validate_json(row[0]) if row else None

    def list(self, limit: int | None = None) -> Sequence[Finding]:
        sql = "SELECT document FROM findings ORDER BY created_at DESC"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        return [Finding.model_validate_json(r[0]) for r in self._conn.execute(sql)]

    def find_by_indicator(self, indicator_key: str) -> Sequence[Finding]:
        rows = self._conn.execute(
            "SELECT document FROM findings WHERE indicator_keys LIKE ?",
            (f"%{indicator_key}%",),
        )
        results = [Finding.model_validate_json(r[0]) for r in rows]
        # LIKE can over-match substrings; verify exact membership.
        return [f for f in results if indicator_key in f.indicator_keys]

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])


class SqliteUnitOfWork:
    """Unit of Work over a SQLite database file (or ``:memory:``)."""

    def __init__(self, path: str | os.PathLike[str] = ":memory:") -> None:
        self._path = str(path)
        self._conn: sqlite3.Connection | None = None
        self.findings: _SqliteFindingRepository | None = None  # set on __enter__

    def _connect(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(self._path)
            conn.executescript(_SCHEMA)
            return conn
        except sqlite3.Error as exc:
            raise StorageError(f"failed to open sqlite db {self._path}: {exc}") from exc

    def __enter__(self) -> "SqliteUnitOfWork":
        self._conn = self._connect()
        self.findings = _SqliteFindingRepository(self._conn)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def commit(self) -> None:
        """Commit the SQLite transaction."""
        if self._conn is not None:
            self._conn.commit()

    def rollback(self) -> None:
        """Roll back the SQLite transaction."""
        if self._conn is not None:
            self._conn.rollback()
