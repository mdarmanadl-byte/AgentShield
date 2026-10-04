
"""Application service for tool-call authorization."""

from uuid import uuid4

from app.repositories.audit_repository import AuditRepository
from app.schemas.decisions import DecisionResponse, ToolCallRequest
from app.security.policy_engine import PolicyEngine


class DecisionService:
    def __init__(
        self,
        policy_engine: PolicyEngine,
        audit_repository: AuditRepository,
    ) -> None:
        self.policy_engine = policy_engine
        self.audit_repository = audit_repository

    def evaluate(self, request: ToolCallRequest) -> DecisionResponse:
        request_id = request.request_id or str(uuid4())

        decision, reason = self.policy_engine.evaluate(request)

        event_id = self.audit_repository.record(
            request_id=request_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            decision=decision,
            reason=reason,
        )

        return DecisionResponse(
            request_id=request_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            decision=decision,
            reason=reason,
            audit_event_id=event_id,
        )
