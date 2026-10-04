
"""Version 1 API router."""

from fastapi import APIRouter

from app.api.v1.endpoints import approvals, audit, decisions, health

router = APIRouter()
router.include_router(health.router)
router.include_router(decisions.router, prefix="/v1")
router.include_router(audit.router, prefix="/v1")
router.include_router(approvals.router, prefix="/v1")
