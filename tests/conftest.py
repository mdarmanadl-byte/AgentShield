
"""Shared test fixtures."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def client(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "example.txt").write_text(
        "safe test content",
        encoding="utf-8",
    )

    policy_file = tmp_path / "policies.json"
    policy_file.write_text(
        json.dumps({
            "version": 1,
            "agents": {
                "demo-agent": {
                    "allowed_tools": [
                        "list_project_files",
                        "read_project_file",
                    ],
                    "denied_tools": ["execute_shell"],
                }
            },
            "path_argument_tools": ["read_project_file"],
            "blocked_path_parts": [
                ".env", ".git", ".ssh", "secrets", "credentials"
            ],
        }),
        encoding="utf-8",
    )

    settings = Settings(
        workspace_root=workspace,
        policy_file=policy_file,
        audit_db=tmp_path / "data" / "audit.sqlite",
    )

    application = create_app(settings)

    with TestClient(application) as test_client:
        yield test_client
