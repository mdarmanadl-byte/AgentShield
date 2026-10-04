"""Approval API contracts."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ApprovalStatus = Literal[
	"pending",
	"approved",
	"rejected",
	"consumed",
]


class ApprovalCreateRequest(BaseModel):
	model_config = ConfigDict(extra="forbid")

	agent_id: str = Field(min_length=1, max_length=128)
	tool_name: str = Field(min_length=1, max_length=128)
	arguments: dict = Field(default_factory=dict)
	request_id: str | None = Field(default=None, max_length=128)


class ApprovalDecisionRequest(BaseModel):
	model_config = ConfigDict(extra="forbid")

	action: Literal["approve", "reject"]
	note: str | None = Field(default=None, max_length=1000)


class ApprovalResponse(BaseModel):
	id: str
	request_id: str
	agent_id: str
	tool_name: str
	arguments: dict
	arguments_sha256: str
	status: ApprovalStatus
	created_at: str
	decided_at: str | None
	reviewer: str | None
	reviewer_note: str | None
