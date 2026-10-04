
"""SQLite persistence for security audit events."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.schemas.decisions import AuditEventResponse


class AuditRepository:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database_path),
            timeout=10,
        )
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK (
                        decision IN ('allow', 'deny')
                    ),
                    reason TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_created
                ON audit_events(id DESC)
                """
            )

    def record(
        self,
        *,
        request_id: str,
        agent_id: str,
        tool_name: str,
        decision: str,
        reason: str,
    ) -> int:
        if decision not in {"allow", "deny"}:
            raise ValueError("Unsupported audit decision.")

        timestamp = datetime.now(timezone.utc).isoformat()

        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO audit_events (
                    timestamp, request_id, agent_id,
                    tool_name, decision, reason
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    request_id,
                    agent_id,
                    tool_name,
                    decision,
                    reason,
                ),
            )
            return int(cursor.lastrowid)

    def list_events(self, limit: int = 50) -> list[AuditEventResponse]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, timestamp, request_id, agent_id,
                       tool_name, decision, reason
                FROM audit_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            AuditEventResponse(**dict(row))
            for row in rows
        ]
