

"""Business logic for approval requests and execution-time checks."""

from uuid import uuid4

from app.repositories.approval_repository import (
    ApprovalRepository,
    arguments_digest,
)
from app.repositories.audit_repository import AuditRepository
from app.schemas.approvals import ApprovalResponse
from app.schemas.decisions import ToolCallRequest
from app.security.policy_engine import PolicyEngine


class ApprovalService:
    def __init__(
        self,
        policy: PolicyEngine,
        approvals: ApprovalRepository,
        audit: AuditRepository,
    ) -> None:
        self.policy = policy
        self.approvals = approvals
        self.audit = audit

    def create_request(
        self,
        *,
        agent_id: str,
        tool_name: str,
        arguments: dict,
        request_id: str | None = None,
    ) -> ApprovalResponse:
        request_id = request_id or str(uuid4())
        request = ToolCallRequest(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            request_id=request_id,
        )

        decision, reason = self.policy.evaluate(request)

        if decision != "approval_required":
            raise ValueError(
                f"Cannot create approval request: {decision}. {reason}"
            )

        record = self.approvals.create(
            request_id=request_id,
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
        )

        self.audit.record(
            request_id=request_id,
            agent_id=agent_id,
            tool_name=tool_name,
            decision="approval_required",
            reason=f"Approval request created: {record.id}",
        )
        return record

    def decide(
        self,
        *,
        approval_id: str,
        action: str,
        reviewer: str,
        note: str | None,
    ) -> ApprovalResponse | None:
        record = self.approvals.decide(
            approval_id=approval_id,
            action=action,
            reviewer=reviewer,
            note=note,
        )

        if record is None:
            return None

        # The audit decision describes the review outcome. It does not
        # authorize execution of a tool by itself.
        self.audit.record(
            request_id=record.request_id,
            agent_id=record.agent_id,
            tool_name=record.tool_name,
            decision=(
                "allow" if record.status == "approved" else "deny"
            ),
            reason=(
                f"Reviewer decision recorded for approval {record.id}: "
                f"{record.status}. No tool was executed."
            ),
        )
        return record

    def verify_for_execution(
        self,
        *,
        approval_id: str,
        agent_id: str,
        tool_name: str,
        arguments: dict,
    ) -> bool:
        """Verify a specific approved operation immediately before use."""
        record = self.approvals.get(approval_id)
        if record is None or record.status != "approved":
            return False

        if record.agent_id != agent_id or record.tool_name != tool_name:
            return False

        if record.arguments_sha256 != arguments_digest(arguments):
            return False

        request = ToolCallRequest(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
        )
        decision, _ = self.policy.evaluate(request)

        # The current policy must still require approval for this operation.
        return decision == "approval_required"
