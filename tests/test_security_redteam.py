
import json
from pathlib import Path

import pytest

from app.core.config import Settings
from app.mcp.tool_service import ToolService


@pytest.fixture
def security_env(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "public.txt").write_text(
        "public content", encoding="utf-8"
    )
    (workspace / ".env").write_text(
        "SECRET=must-not-leak", encoding="utf-8"
    )

    outside = tmp_path / "outside.txt"
    outside.write_text("EXTERNAL_SECRET", encoding="utf-8")

    policy_file = tmp_path / "policies.json"
    policy_file.write_text(
        json.dumps(
            {
                "version": 1,
                "agents": {
                    "demo-agent": {
                        "allowed_tools": [
                            "list_project_files",
                            "read_project_file",
                        ],
                        "approval_required_tools": [
                            "create_patch",
                            "run_targeted_tests",
                        ],
                        "denied_tools": [
                            "execute_shell",
                            "read_secret_file",
                            "delete_file",
                        ],
                    }
                },
                "path_argument_tools": ["read_project_file"],
                "blocked_path_parts": [
                    ".env",
                    ".git",
                    ".ssh",
                    ".agentshield-proposals",
                    "secrets",
                    "credentials",
                    "id_rsa",
                    "id_ed25519",
                ],
            }
        ),
        encoding="utf-8",
    )

    settings = Settings(
        workspace_root=workspace,
        policy_file=policy_file,
        audit_db=tmp_path / "audit.db",
    )

    return {
        "service": ToolService(settings),
        "workspace": workspace,
        "outside": outside,
    }


def test_normal_file_read_is_supported(security_env):
    service = security_env["service"]

    result = service.read_project_file(
        agent_id="demo-agent",
        path="public.txt",
    )

    assert "public content" in str(result)


@pytest.mark.parametrize(
    "path",
    [
        "../outside.txt",
        "../../outside.txt",
        ".env",
        "/etc/passwd",
        r"..\outside.txt",
    ],
)
def test_hostile_paths_never_disclose_contents(security_env, path):
    service = security_env["service"]

    try:
        result = service.read_project_file(
            agent_id="demo-agent",
            path=path,
        )
    except (ValueError, OSError, PermissionError):
        # An explicit rejection is acceptable.
        return

    rendered = str(result)
    assert "must-not-leak" not in rendered
    assert "EXTERNAL_SECRET" not in rendered


def test_symlink_cannot_escape_workspace(security_env):
    workspace = security_env["workspace"]
    outside = security_env["outside"]
    link = workspace / "external-link.txt"

    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this system")

    result = security_env["service"].read_project_file(
        agent_id="demo-agent",
        path="external-link.txt",
    )

    assert "EXTERNAL_SECRET" not in str(result)


def test_directory_cannot_be_read_as_a_file(security_env):
    workspace = security_env["workspace"]
    (workspace / "folder").mkdir()

    result = security_env["service"].read_project_file(
        agent_id="demo-agent",
        path="folder",
    )

    assert "public content" not in str(result)
    assert "EXTERNAL_SECRET" not in str(result)


def test_denied_tool_is_not_executed(security_env):
    service = security_env["service"]

    allowed, _reason = service._authorize(
        agent_id="demo-agent",
        tool_name="execute_shell",
        arguments={"command": "whoami"},
    )

    assert allowed is False


def test_unknown_agent_is_denied(security_env):
    service = security_env["service"]

    allowed, _reason = service._authorize(
        agent_id="unknown-agent",
        tool_name="read_project_file",
        arguments={"path": "public.txt"},
    )

    assert allowed is False
