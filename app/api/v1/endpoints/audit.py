
"""Audit query endpoint."""

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import get_container
from app.container import ServiceContainer
from app.schemas.decisions import AuditEventResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditEventResponse])
def list_audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    container: ServiceContainer = Depends(get_container),
) -> list[AuditEventResponse]:
    try:
        return container.audit_repository.list_events(limit=limit)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Audit storage is unavailable.",
        ) from exc
