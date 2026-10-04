
"""Authentication dependency for approval reviewers."""

import hmac
import os

from fastapi import Header, HTTPException, status


def require_reviewer(
    authorization: str | None = Header(default=None),
    x_reviewer: str | None = Header(default=None),
) -> str:
    configured_token = os.getenv("AGENTSHIELD_REVIEWER_TOKEN")

    if not configured_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Reviewer authentication is not configured.",
        )

    expected = f"Bearer {configured_token}"

    if not authorization or not hmac.compare_digest(
        authorization,
        expected,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Reviewer authentication failed.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    reviewer = (x_reviewer or "").strip()
    if not reviewer or len(reviewer) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid X-Reviewer header is required.",
        )

    return reviewer
