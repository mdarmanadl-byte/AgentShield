
"""Authorization decision endpoint."""

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import get_container
from app.container import ServiceContainer
from app.schemas.decisions import DecisionResponse, ToolCallRequest

router = APIRouter(prefix="/decisions", tags=["decisions"])


@router.post("", response_model=DecisionResponse)
def evaluate_decision(
    request: ToolCallRequest,
    container: ServiceContainer = Depends(get_container),
) -> DecisionResponse:
    try:
        return container.decision_service.evaluate(request)
    except Exception as exc:
        # Fail closed when the decision cannot be audited.
        raise HTTPException(
            status_code=503,
            detail="Authorization unavailable; audit persistence failed.",
        ) from exc
