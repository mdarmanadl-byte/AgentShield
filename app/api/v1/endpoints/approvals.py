
"""Approval request and reviewer decision endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import get_container
from app.container import ServiceContainer
from app.core.reviewer_auth import require_reviewer
from app.schemas.approvals import (
    ApprovalCreateRequest,
    ApprovalDecisionRequest,
    ApprovalResponse,
)

router = APIRouter(prefix="/approvals", tags=["approvals"])


@router.post("", response_model=ApprovalResponse, status_code=201)
def create_approval(
    request: ApprovalCreateRequest,
    container: ServiceContainer = Depends(get_container),
) -> ApprovalResponse:
    try:
        return container.approval_service.create_request(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            arguments=request.arguments,
            request_id=request.request_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not persist approval request and audit event.",
        ) from exc


@router.get("", response_model=list[ApprovalResponse])
def list_approvals(
    status_filter: str | None = Query(
        default="pending",
        alias="status",
        pattern="^(pending|approved|rejected|consumed)$",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    _reviewer: str = Depends(require_reviewer),
    container: ServiceContainer = Depends(get_container),
) -> list[ApprovalResponse]:
    return container.approval_repository.list(
        status=status_filter,
        limit=limit,
    )


@router.get("/{approval_id}", response_model=ApprovalResponse)
def get_approval(
    approval_id: str,
    _reviewer: str = Depends(require_reviewer),
    container: ServiceContainer = Depends(get_container),
) -> ApprovalResponse:
    record = container.approval_repository.get(approval_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Approval not found.")
    return record


@router.post("/{approval_id}/decision", response_model=ApprovalResponse)
def decide_approval(
    approval_id: str,
    request: ApprovalDecisionRequest,
    reviewer: str = Depends(require_reviewer),
    container: ServiceContainer = Depends(get_container),
) -> ApprovalResponse:
    try:
        record = container.approval_service.decide(
            approval_id=approval_id,
            action=request.action,
            reviewer=reviewer,
            note=request.note,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not persist the review decision and audit event.",
        ) from exc

    if record is not None:
        return record

    existing = container.approval_repository.get(approval_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Approval not found.")

    raise HTTPException(
        status_code=409,
        detail="Approval has already been decided.",
    )
