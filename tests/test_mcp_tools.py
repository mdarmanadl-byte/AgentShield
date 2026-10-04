
"""Security tests for MCP tool operations."""

import json
from pathlib import Path

import pytest

from app.core.config import Settings
from app.mcp.tool_service import ToolService


@pytest.fixture
def service(tmp_path: Path) -> ToolService:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "example.txt").write_text(
        "safe project content",
        encoding="utf-8",
    )
    (workspace / ".env").write_text(
        "SECRET=do-not-expose",
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

    return ToolService(
        Settings(
            workspace_root=workspace,
            policy_file=policy_file,
            audit_db=tmp_path / "data" / "audit.sqlite",
        )
    )


def test_lists_project_files(service: ToolService) -> None:
    result = service.list_project_files(agent_id="demo-agent")

    assert result["ok"] is True
    assert "example.txt" in result["files"]
    assert ".env" not in result["files"]


def test_reads_allowed_file(service: ToolService) -> None:
    result = service.read_project_file(
        agent_id="demo-agent",
        path="example.txt",
    )

    assert result["ok"] is True
    assert result["content"] == "safe project content"


def test_rejects_sensitive_file(service: ToolService) -> None:
    result = service.read_project_file(
        agent_id="demo-agent",
        path=".env",
    )

    assert result["ok"] is False
    assert "SECRET=" not in json.dumps(result)


def test_rejects_path_traversal(service: ToolService) -> None:
    result = service.read_project_file(
        agent_id="demo-agent",
        path="../outside.txt",
    )

    assert result["ok"] is False


def test_rejects_unknown_agent(service: ToolService) -> None:
    result = service.read_project_file(
        agent_id="unknown-agent",
        path="example.txt",
    )

    assert result["ok"] is False


def test_rejects_invalid_result_limit(service: ToolService) -> None:
    result = service.list_project_files(
        agent_id="demo-agent",
        max_results=1000,
    )

    assert result["ok"] is False


def test_audit_failure_prevents_file_read(
    service: ToolService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_record(**kwargs):
        raise OSError("simulated database failure")

    monkeypatch.setattr(service.audit, "record", fail_record)

    with pytest.raises(OSError):
        service.read_project_file(
            agent_id="demo-agent",
            path="example.txt",
        )
