
"""Policy-enforced MCP tool operations."""

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.config import Settings
from app.repositories.approval_repository import ApprovalRepository
from app.repositories.audit_repository import AuditRepository
from app.schemas.decisions import ToolCallRequest
from app.security.policy_engine import PolicyEngine
from app.services.approval_service import ApprovalService


class ToolService:
    MAX_READ_BYTES = 64_000
    MAX_RESULTS = 100
    MAX_PATCH_BYTES = 32_000
    PROPOSAL_DIRECTORY = ".agentshield-proposals"

    def __init__(
        self,
        settings: Settings | None = None,
    ) -> None:
        settings = settings or Settings.from_env()

        self.workspace = settings.workspace_root.resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)

        self.policy = PolicyEngine(
            policy_file=settings.policy_file,
            workspace_root=self.workspace,
        )
        self.audit = AuditRepository(settings.audit_db)
        self.approvals = ApprovalRepository(settings.audit_db)
        self.approval_service = ApprovalService(
            policy=self.policy,
            approvals=self.approvals,
            audit=self.audit,
        )

    def _authorize(
        self,
        *,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, str]:
        request = ToolCallRequest(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            request_id=str(uuid4()),
        )

        decision, reason = self.policy.evaluate(request)

        # Persist the decision before allowing the operation to run.
        # If persistence fails, the operation must not execute.
        self.audit.record(
            request_id=request.request_id or str(uuid4()),
            agent_id=agent_id,
            tool_name=tool_name,
            decision=decision,
            reason=reason,
        )

        return decision == "allow", reason

    def list_project_files(
        self,
        *,
        agent_id: str,
        max_results: int = 100,
    ) -> dict[str, Any]:
        if (
            isinstance(max_results, bool)
            or not isinstance(max_results, int)
            or not 1 <= max_results <= self.MAX_RESULTS
        ):
            return {
                "ok": False,
                "error": "max_results must be an integer from 1 to 100.",
            }

        allowed, reason = self._authorize(
            agent_id=agent_id,
            tool_name="list_project_files",
            arguments={"max_results": max_results},
        )

        if not allowed:
            return {"ok": False, "error": reason}

        results: list[str] = []
        blocked = self.policy.blocked_path_parts

        try:
            for path in sorted(self.workspace.rglob("*")):
                relative = path.relative_to(self.workspace)

                if any(
                    part.casefold() in blocked
                    for part in relative.parts
                ):
                    continue

                # Never enumerate symlinks or traverse a symlinked
                # directory as if it were a normal project directory.
                if path.is_symlink() or not path.is_file():
                    continue

                try:
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(self.workspace)
                except (OSError, ValueError, RuntimeError):
                    continue

                results.append(relative.as_posix())

                if len(results) >= max_results:
                    break

        except OSError:
            return {
                "ok": False,
                "error": "Could not list workspace files.",
            }

        return {"ok": True, "files": results}

    def read_project_file(
        self,
        *,
        agent_id: str,
        path: str,
    ) -> dict[str, Any]:
        allowed, reason = self._authorize(
            agent_id=agent_id,
            tool_name="read_project_file",
            arguments={"path": path},
        )

        if not allowed:
            return {"ok": False, "error": reason}

        supplied = Path(path)
        candidate = (
            supplied
            if supplied.is_absolute()
            else self.workspace / supplied
        )

        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self.workspace)

            if candidate.is_symlink() or not resolved.is_file():
                return {
                    "ok": False,
                    "error": "Only regular project files can be read.",
                }

            if resolved.stat().st_size > self.MAX_READ_BYTES:
                return {
                    "ok": False,
                    "error": "File exceeds the 64 KB read limit.",
                }

            content = resolved.read_text(encoding="utf-8")

        except (
            OSError,
            ValueError,
            RuntimeError,
            UnicodeDecodeError,
        ):
            return {
                "ok": False,
                "error": "File is missing, inaccessible, or not UTF-8 text.",
            }

        return {
            "ok": True,
            "path": resolved.relative_to(self.workspace).as_posix(),
            "content": content,
        }

    def _validate_patch_target(self, path: str) -> str | None:
        """Validate a target path without modifying the target file."""
        if not isinstance(path, str) or not path.strip():
            return "A non-empty target path is required."

        if "\x00" in path or "\\" in path:
            return "Invalid target path."

        supplied = Path(path)

        if supplied.is_absolute() or ".." in supplied.parts:
            return "Absolute paths and path traversal are prohibited."

        try:
            resolved = (self.workspace / supplied).resolve(strict=False)
            resolved.relative_to(self.workspace)
        except (OSError, ValueError, RuntimeError):
            return "Target path escapes the authorized workspace."

        blocked = self.policy.blocked_path_parts
        if any(part.casefold() in blocked for part in supplied.parts):
            return "Target path references a protected resource."

        if any(
            part.casefold() in blocked
            for part in resolved.relative_to(self.workspace).parts
        ):
            return "Resolved target path references a protected resource."

        if resolved.exists() and not resolved.is_file():
            return "The target must be a file path."

        return None

    def create_patch(
        self,
        *,
        agent_id: str,
        approval_id: str,
        path: str,
        patch: str,
    ) -> dict[str, Any]:
        """Save an approved patch proposal; never modify source files."""
        if not isinstance(approval_id, str) or not approval_id.strip():
            return {"ok": False, "error": "approval_id is required."}

        if not isinstance(patch, str) or not patch.strip():
            return {"ok": False, "error": "Patch content cannot be empty."}

        if "\x00" in patch:
            return {"ok": False, "error": "Patch contains a NUL character."}

        if len(patch.encode("utf-8")) > self.MAX_PATCH_BYTES:
            return {
                "ok": False,
                "error": "Patch exceeds the 32 KB limit.",
            }

        path_error = self._validate_patch_target(path)
        if path_error:
            return {"ok": False, "error": path_error}

        operation_arguments = {"path": path, "patch": patch}

        try:
            consumed = self.approval_service.consume_for_execution(
                approval_id=approval_id,
                agent_id=agent_id,
                tool_name="create_patch",
                arguments=operation_arguments,
            )
        except Exception:
            # Fail closed: never proceed after an authorization/audit error.
            return {
                "ok": False,
                "error": "Approval verification failed; no proposal was created.",
            }

        if not consumed:
            return {
                "ok": False,
                "error": "Approval is invalid, mismatched, or already consumed.",
            }

        proposal_dir = self.workspace / self.PROPOSAL_DIRECTORY

        try:
            proposal_dir.mkdir(mode=0o700, exist_ok=True)

            # Reject a symlinked proposal directory and check its location.
            if proposal_dir.is_symlink():
                raise OSError("Proposal directory must not be a symlink.")

            resolved_dir = proposal_dir.resolve(strict=True)
            resolved_dir.relative_to(self.workspace)

            proposal_id = str(uuid4())
            proposal_path = resolved_dir / f"{proposal_id}.json"

            payload = {
                "proposal_id": proposal_id,
                "agent_id": agent_id,
                "target_path": path,
                "patch": patch,
                "approval_id": approval_id,
                "status": "pending_manual_application",
            }

            # Exclusive creation prevents accidental overwrite.
            with proposal_path.open("x", encoding="utf-8") as file:
                json.dump(
                    payload,
                    file,
                    ensure_ascii=False,
                    indent=2,
                    allow_nan=False,
                )

            self.audit.record(
                request_id=str(uuid4()),
                agent_id=agent_id,
                tool_name="create_patch",
                decision="allow",
                reason=f"Approved patch proposal created: {proposal_id}",
            )

            return {
                "ok": True,
                "proposal_id": proposal_id,
                "status": "pending_manual_application",
                "message": "Proposal saved. No source file was modified.",
            }

        except Exception:
            # Approval stays consumed. Do not retry automatically.
            return {
                "ok": False,
                "error": (
                    "Proposal creation failed. Approval remains consumed; "
                    "inspect the workspace before requesting another approval."
                ),
            }
