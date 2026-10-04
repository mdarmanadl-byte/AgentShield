
"""AgentShield application entry point."""

from fastapi import FastAPI

from app.api.router import router
from app.container import build_container
from app.core.config import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    effective_settings = settings or Settings.from_env()
    container = build_container(effective_settings)

    application = FastAPI(
        title="AgentShield",
        description="Deterministic security gateway for AI-agent tool calls.",
        version="0.1.0",
    )

    application.state.container = container
    application.include_router(router)

    return application


app = create_app()
