
"""Tests for one-time approval consumption."""

from pathlib import Path

from app.repositories.approval_repository import ApprovalRepository


def make_repository(tmp_path: Path) -> ApprovalRepository:
    return ApprovalRepository(tmp_path / "approvals.db")


def create_approved_request(
    repository: ApprovalRepository,
    *,
    agent_id: str = "demo-agent",
    tool_name: str = "create_patch",
    arguments: dict | None = None,
) -> str:
    arguments = arguments or {"path": "src/example.py", "patch": "safe"}
    record = repository.create(
        request_id="request-001",
        agent_id=agent_id,
        tool_name=tool_name,
        arguments=arguments,
    )

    approved = repository.decide(
        approval_id=record.id,
        action="approve",
        reviewer="reviewer-1",
        note="Approved for testing",
    )

    assert approved is not None
    assert approved.status == "approved"
    return record.id


def test_approval_can_be_consumed_only_once(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    approval_id = create_approved_request(repository)
    arguments = {"path": "src/example.py", "patch": "safe"}

    assert repository.consume(
        approval_id=approval_id,
        agent_id="demo-agent",
        tool_name="create_patch",
        arguments=arguments,
    )

    assert not repository.consume(
        approval_id=approval_id,
        agent_id="demo-agent",
        tool_name="create_patch",
        arguments=arguments,
    )

    record = repository.get(approval_id)
    assert record is not None
    assert record.status == "consumed"


def test_consumption_rejects_changed_arguments(
    tmp_path: Path,
) -> None:
    repository = make_repository(tmp_path)
    approval_id = create_approved_request(repository)

    assert not repository.consume(
        approval_id=approval_id,
        agent_id="demo-agent",
        tool_name="create_patch",
        arguments={"path": "src/other.py", "patch": "safe"},
    )


def test_consumption_rejects_wrong_agent(
    tmp_path: Path,
) -> None:
    repository = make_repository(tmp_path)
    approval_id = create_approved_request(repository)

    assert not repository.consume(
        approval_id=approval_id,
        agent_id="another-agent",
        tool_name="create_patch",
        arguments={"path": "src/example.py", "patch": "safe"},
    )


def test_consumption_rejects_wrong_tool(
    tmp_path: Path,
) -> None:
    repository = make_repository(tmp_path)
    approval_id = create_approved_request(repository)

    assert not repository.consume(
        approval_id=approval_id,
        agent_id="demo-agent",
        tool_name="run_targeted_tests",
        arguments={"path": "src/example.py", "patch": "safe"},
    )


def test_pending_approval_cannot_be_consumed(
    tmp_path: Path,
) -> None:
    repository = make_repository(tmp_path)
    record = repository.create(
        request_id="request-pending",
        agent_id="demo-agent",
        tool_name="create_patch",
        arguments={"path": "src/example.py", "patch": "safe"},
    )

    assert not repository.consume(
        approval_id=record.id,
        agent_id="demo-agent",
        tool_name="create_patch",
        arguments={"path": "src/example.py", "patch": "safe"},
    )


def test_rejected_approval_cannot_be_consumed(
    tmp_path: Path,
) -> None:
    repository = make_repository(tmp_path)
    record = repository.create(
        request_id="request-rejected",
        agent_id="demo-agent",
        tool_name="create_patch",
        arguments={"path": "src/example.py", "patch": "safe"},
    )

    repository.decide(
        approval_id=record.id,
        action="reject",
        reviewer="reviewer-1",
        note="Not safe",
    )

    assert not repository.consume(
        approval_id=record.id,
        agent_id="demo-agent",
        tool_name="create_patch",
        arguments={"path": "src/example.py", "patch": "safe"},
    )
