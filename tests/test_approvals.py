
"""Approval workflow and security regression tests."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def approval_client(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    policy_file = tmp_path / "policies.json"
    policy_file.write_text(
        json.dumps({
            "version": 1,
            "agents": {
                "demo-agent": {
                    "allowed_tools": ["read_project_file"],
                    "approval_required_tools": ["create_patch"],
                    "denied_tools": ["execute_shell"],
                }
            },
            "path_argument_tools": ["read_project_file"],
            "blocked_path_parts": [".env", ".git", ".ssh", "secrets"],
        }),
        encoding="utf-8",
    )

    monkeypatch.setenv("AGENTSHIELD_REVIEWER_TOKEN", "test-token")

    application = create_app(
        Settings(
            workspace_root=workspace,
            policy_file=policy_file,
            audit_db=tmp_path / "data" / "audit.sqlite",
        )
    )

    with TestClient(application) as client:
        yield client


def reviewer_headers() -> dict[str, str]:
    return {
        "Authorization": "Bearer test-token",
        "X-Reviewer": "test-reviewer",
    }


def create_request(client: TestClient) -> dict:
    response = client.post(
        "/v1/approvals",
        json={
            "agent_id": "demo-agent",
            "tool_name": "create_patch",
            "arguments": {"description": "Fix validation"},
        },
    )
    assert response.status_code == 201
    return response.json()


def test_approval_requires_review(
    approval_client: TestClient,
) -> None:
    record = create_request(approval_client)

    assert record["status"] == "pending"
    assert record["arguments_sha256"]


def test_unapproved_tool_cannot_be_approved_without_auth(
    approval_client: TestClient,
) -> None:
    record = create_request(approval_client)

    response = approval_client.post(
        f"/v1/approvals/{record['id']}/decision",
        json={"action": "approve"},
    )

    assert response.status_code == 401


def test_reviewer_can_approve_once(
    approval_client: TestClient,
) -> None:
    record = create_request(approval_client)

    response = approval_client.post(
        f"/v1/approvals/{record['id']}/decision",
        headers=reviewer_headers(),
        json={"action": "approve", "note": "Reviewed"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "approved"

    duplicate = approval_client.post(
        f"/v1/approvals/{record['id']}/decision",
        headers=reviewer_headers(),
        json={"action": "reject"},
    )

    assert duplicate.status_code == 409


def test_rejected_request_cannot_be_reapproved(
    approval_client: TestClient,
) -> None:
    record = create_request(approval_client)

    response = approval_client.post(
        f"/v1/approvals/{record['id']}/decision",
        headers=reviewer_headers(),
        json={"action": "reject"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"

    again = approval_client.post(
        f"/v1/approvals/{record['id']}/decision",
        headers=reviewer_headers(),
        json={"action": "approve"},
    )
    assert again.status_code == 409


def test_execution_verification_binds_exact_arguments(
    approval_client: TestClient,
) -> None:
    record = create_request(approval_client)

    response = approval_client.post(
        f"/v1/approvals/{record['id']}/decision",
        headers=reviewer_headers(),
        json={"action": "approve"},
    )
    assert response.status_code == 200

    service = approval_client.app.state.container.approval_service

    assert service.verify_for_execution(
        approval_id=record["id"],
        agent_id="demo-agent",
        tool_name="create_patch",
        arguments={"description": "Fix validation"},
    )

    assert not service.verify_for_execution(
        approval_id=record["id"],
        agent_id="demo-agent",
        tool_name="create_patch",
        arguments={"description": "Delete validation"},
    )

    assert not service.verify_for_execution(
        approval_id=record["id"],
        agent_id="unknown-agent",
        tool_name="create_patch",
        arguments={"description": "Fix validation"},
    )


def test_ordinary_tool_cannot_request_approval(
    approval_client: TestClient,
) -> None:
    response = approval_client.post(
        "/v1/approvals",
        json={
            "agent_id": "demo-agent",
            "tool_name": "read_project_file",
            "arguments": {"path": "example.txt"},
        },
    )

    assert response.status_code == 422
