
"""Validated API request and response contracts."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


Decision = Literal["allow", "deny", "approval_required"]


class ToolCallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = Field(default=None, max_length=128)


class DecisionResponse(BaseModel):
    request_id: str
    agent_id: str
    tool_name: str
    decision: Decision
    reason: str
    audit_event_id: int


class AuditEventResponse(BaseModel):
    id: int
    timestamp: str
    request_id: str
    agent_id: str
    tool_name: str
    decision: Decision
    reason: str
