
"""Central application configuration."""

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def resolve_path(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


@dataclass(frozen=True)
class Settings:
    workspace_root: Path
    policy_file: Path
    audit_db: Path

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            workspace_root=resolve_path(
                os.getenv(
                    "AGENTSHIELD_WORKSPACE",
                    str(PROJECT_ROOT / "workspace"),
                )
            ),
            policy_file=resolve_path(
                os.getenv(
                    "AGENTSHIELD_POLICY_FILE",
                    str(PROJECT_ROOT / "policies.json"),
                )
            ),
            audit_db=resolve_path(
                os.getenv(
                    "AGENTSHIELD_AUDIT_DB",
                    str(PROJECT_ROOT / "data" / "agentshield.db"),
                )
            ),
        )
