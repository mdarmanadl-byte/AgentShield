
"""Application dependency construction."""

from dataclasses import dataclass

from app.core.config import Settings
from app.repositories.approval_repository import ApprovalRepository
from app.repositories.audit_repository import AuditRepository
from app.security.policy_engine import PolicyEngine
from app.services.approval_service import ApprovalService
from app.services.decision_service import DecisionService


@dataclass
class ServiceContainer:
    decision_service: DecisionService
    audit_repository: AuditRepository
    approval_repository: ApprovalRepository
    approval_service: ApprovalService


def build_container(settings: Settings) -> ServiceContainer:
    settings.workspace_root.mkdir(parents=True, exist_ok=True)

    policy_engine = PolicyEngine(
        policy_file=settings.policy_file,
        workspace_root=settings.workspace_root,
    )

    audit_repository = AuditRepository(settings.audit_db)
    approval_repository = ApprovalRepository(settings.audit_db)

    decision_service = DecisionService(
        policy_engine=policy_engine,
        audit_repository=audit_repository,
    )
    approval_service = ApprovalService(
        policy=policy_engine,
        approvals=approval_repository,
        audit=audit_repository,
    )

    return ServiceContainer(
        decision_service=decision_service,
        audit_repository=audit_repository,
        approval_repository=approval_repository,
        approval_service=approval_service,
    )
