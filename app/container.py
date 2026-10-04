
"""Application dependency construction."""

from dataclasses import dataclass

from app.core.config import Settings
from app.repositories.audit_repository import AuditRepository
from app.security.policy_engine import PolicyEngine
from app.services.decision_service import DecisionService


@dataclass
class ServiceContainer:
    decision_service: DecisionService
    audit_repository: AuditRepository


def build_container(settings: Settings) -> ServiceContainer:
    settings.workspace_root.mkdir(parents=True, exist_ok=True)

    policy_engine = PolicyEngine(
        policy_file=settings.policy_file,
        workspace_root=settings.workspace_root,
    )

    audit_repository = AuditRepository(settings.audit_db)

    decision_service = DecisionService(
        policy_engine=policy_engine,
        audit_repository=audit_repository,
    )

    return ServiceContainer(
        decision_service=decision_service,
        audit_repository=audit_repository,
    )
