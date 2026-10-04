"""Persistent approval requests with atomic one-time consumption."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.schemas.approvals import ApprovalResponse


def canonical_json(value: object) -> str:
	return json.dumps(
		value,
		sort_keys=True,
		separators=(",", ":"),
		ensure_ascii=False,
		allow_nan=False,
	)


def arguments_digest(arguments: dict) -> str:
	return hashlib.sha256(
		canonical_json(arguments).encode("utf-8")
	).hexdigest()


def redact_arguments(value: object) -> object:
	"""Redact common secret fields from reviewer-facing arguments."""
	secret_names = (
		"password", "secret", "token", "api_key",
		"apikey", "credential", "private_key",
	)

	if isinstance(value, dict):
		return {
			str(key): (
				"[REDACTED]"
				if any(
					word in str(key).casefold()
					for word in secret_names
				)
				else redact_arguments(item)
			)
			for key, item in value.items()
		}

	if isinstance(value, list):
		return [redact_arguments(item) for item in value]

	return value


class ApprovalRepository:
	def __init__(self, database_path: Path) -> None:
		self.database_path = database_path
		self.database_path.parent.mkdir(parents=True, exist_ok=True)
		self._initialize()

	def _connect(self) -> sqlite3.Connection:
		connection = sqlite3.connect(
			str(self.database_path),
			timeout=10,
			isolation_level="IMMEDIATE",
		)
		connection.row_factory = sqlite3.Row
		return connection

	@staticmethod
	def _create_table(
		connection: sqlite3.Connection,
		table_name: str,
	) -> None:
		# table_name is selected internally, never supplied by a caller.
		connection.execute(
			f"""
			CREATE TABLE {table_name} (
				id TEXT PRIMARY KEY,
				request_id TEXT NOT NULL,
				agent_id TEXT NOT NULL,
				tool_name TEXT NOT NULL,
				arguments_json TEXT NOT NULL,
				arguments_sha256 TEXT NOT NULL,
				status TEXT NOT NULL CHECK (
					status IN (
						'pending', 'approved', 'rejected', 'consumed'
					)
				),
				created_at TEXT NOT NULL,
				decided_at TEXT,
				reviewer TEXT,
				reviewer_note TEXT
			)
			"""
		)

	def _initialize(self) -> None:
		with self._connect() as connection:
			row = connection.execute(
				"""
				SELECT sql FROM sqlite_master
				WHERE type = 'table' AND name = 'approval_requests'
				"""
			).fetchone()

			if row is None:
				self._create_table(connection, "approval_requests")
			elif "'consumed'" not in (row["sql"] or ""):
				self._create_table(connection, "approval_requests_new")
				connection.execute(
					"""
					INSERT INTO approval_requests_new (
						id, request_id, agent_id, tool_name,
						arguments_json, arguments_sha256, status,
						created_at, decided_at, reviewer, reviewer_note
					)
					SELECT
						id, request_id, agent_id, tool_name,
						arguments_json, arguments_sha256, status,
						created_at, decided_at, reviewer, reviewer_note
					FROM approval_requests
					"""
				)
				connection.execute("DROP TABLE approval_requests")
				connection.execute(
					"""
					ALTER TABLE approval_requests_new
					RENAME TO approval_requests
					"""
				)

			connection.execute(
				"""
				CREATE INDEX IF NOT EXISTS idx_approval_status
				ON approval_requests(status, created_at)
				"""
			)

	def create(
		self,
		*,
		request_id: str,
		agent_id: str,
		tool_name: str,
		arguments: dict,
	) -> ApprovalResponse:
		approval_id = str(uuid4())
		now = datetime.now(timezone.utc).isoformat()

		# Store only the redacted copy; bind execution to the original digest.
		review_copy = canonical_json(redact_arguments(arguments))
		digest = arguments_digest(arguments)

		with self._connect() as connection:
			connection.execute(
				"""
				INSERT INTO approval_requests (
					id, request_id, agent_id, tool_name,
					arguments_json, arguments_sha256, status, created_at
				)
				VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
				""",
				(
					approval_id, request_id, agent_id, tool_name,
					review_copy, digest, now,
				),
			)

		record = self.get(approval_id)
		if record is None:
			raise RuntimeError("Created approval could not be retrieved.")
		return record

	def get(self, approval_id: str) -> ApprovalResponse | None:
		with self._connect() as connection:
			row = connection.execute(
				"SELECT * FROM approval_requests WHERE id = ?",
				(approval_id,),
			).fetchone()

		return self._to_model(row) if row else None

	def list(
		self,
		*,
		status: str | None = "pending",
		limit: int = 50,
	) -> list[ApprovalResponse]:
		with self._connect() as connection:
			if status is None:
				rows = connection.execute(
					"""
					SELECT * FROM approval_requests
					ORDER BY created_at DESC LIMIT ?
					""",
					(limit,),
				).fetchall()
			else:
				rows = connection.execute(
					"""
					SELECT * FROM approval_requests
					WHERE status = ?
					ORDER BY created_at DESC LIMIT ?
					""",
					(status, limit),
				).fetchall()

		return [self._to_model(row) for row in rows]

	def decide(
		self,
		*,
		approval_id: str,
		action: str,
		reviewer: str,
		note: str | None,
	) -> ApprovalResponse | None:
		if action not in {"approve", "reject"}:
			raise ValueError("Invalid approval action.")

		new_status = "approved" if action == "approve" else "rejected"
		now = datetime.now(timezone.utc).isoformat()

		with self._connect() as connection:
			cursor = connection.execute(
				"""
				UPDATE approval_requests
				SET status = ?, decided_at = ?,
					reviewer = ?, reviewer_note = ?
				WHERE id = ? AND status = 'pending'
				""",
				(new_status, now, reviewer, note, approval_id),
			)
			if cursor.rowcount != 1:
				return None

		return self.get(approval_id)

	def consume(
		self,
		*,
		approval_id: str,
		agent_id: str,
		tool_name: str,
		arguments: dict,
	) -> bool:
		"""Atomically claim one matching, approved operation exactly once."""
		digest = arguments_digest(arguments)

		with self._connect() as connection:
			cursor = connection.execute(
				"""
				UPDATE approval_requests
				SET status = 'consumed'
				WHERE id = ?
				  AND agent_id = ?
				  AND tool_name = ?
				  AND arguments_sha256 = ?
				  AND status = 'approved'
				""",
				(approval_id, agent_id, tool_name, digest),
			)
			return cursor.rowcount == 1

	@staticmethod
	def _to_model(row: sqlite3.Row) -> ApprovalResponse:
		return ApprovalResponse(
			id=row["id"],
			request_id=row["request_id"],
			agent_id=row["agent_id"],
			tool_name=row["tool_name"],
			arguments=json.loads(row["arguments_json"]),
			arguments_sha256=row["arguments_sha256"],
			status=row["status"],
			created_at=row["created_at"],
			decided_at=row["decided_at"],
			reviewer=row["reviewer"],
			reviewer_note=row["reviewer_note"],
		)
