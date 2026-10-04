
"""Deterministic, default-deny authorization engine."""

import json
from pathlib import Path
from typing import Any

from app.schemas.decisions import ToolCallRequest


class PolicyLoadError(RuntimeError):
    """The security policy is missing or invalid."""


class PolicyEngine:
    def __init__(
        self,
        policy_file: Path,
        workspace_root: Path,
    ) -> None:
        self.workspace_root = workspace_root.resolve()

        try:
            with policy_file.open("r", encoding="utf-8") as file:
                policy = json.load(file)
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyLoadError(
                f"Cannot load policy file: {policy_file}"
            ) from exc

        if not isinstance(policy, dict) or policy.get("version") != 1:
            raise PolicyLoadError("Unsupported policy version.")

        agents = policy.get("agents")
        path_tools = policy.get("path_argument_tools")
        blocked_parts = policy.get("blocked_path_parts")

        if not isinstance(agents, dict):
            raise PolicyLoadError("'agents' must be an object.")

        if not self._string_list(path_tools):
            raise PolicyLoadError(
                "'path_argument_tools' must be a string list."
            )

        if not self._string_list(blocked_parts):
            raise PolicyLoadError(
                "'blocked_path_parts' must be a string list."
            )

        for agent_id, config in agents.items():
            if not isinstance(agent_id, str) or not isinstance(config, dict):
                raise PolicyLoadError("Invalid agent policy.")

            for key in (
                "allowed_tools",
                "approval_required_tools",
                "denied_tools",
            ):
                values = config.get(key, [])
                if not self._string_list(values):
                    raise PolicyLoadError(
                        f"Agent '{agent_id}': '{key}' must be a string list."
                    )
                config[key] = values

            allowed = set(config["allowed_tools"])
            approval = set(config["approval_required_tools"])
            denied = set(config["denied_tools"])

            if allowed & approval or allowed & denied or approval & denied:
                raise PolicyLoadError(
                    f"Agent '{agent_id}' has conflicting tool rules."
                )

        self.agents: dict[str, Any] = agents
        self.path_argument_tools = set(path_tools)
        self.blocked_path_parts = {
            part.casefold() for part in blocked_parts
        }

    @staticmethod
    def _string_list(value: object) -> bool:
        return isinstance(value, list) and all(
            isinstance(item, str) for item in value
        )

    def evaluate(self, request: ToolCallRequest) -> tuple[str, str]:
        agent = self.agents.get(request.agent_id)

        if agent is None:
            return "deny", "Unknown agent; default-deny policy."

        if request.tool_name in agent["denied_tools"]:
            return "deny", "Tool is explicitly prohibited."

        if request.tool_name in agent["approval_required_tools"]:
            return (
                "approval_required",
                "Tool requires a persisted human approval.",
            )

        if request.tool_name not in agent["allowed_tools"]:
            return "deny", "Tool is not in the agent's allowlist."

        if request.tool_name in self.path_argument_tools:
            error = self._validate_path(request.arguments)
            if error:
                return "deny", error

        return "allow", "Tool is explicitly allowed by policy."

    def _validate_path(self, arguments: dict) -> str | None:
        raw_path = arguments.get("path")

        if not isinstance(raw_path, str) or not raw_path.strip():
            return "A non-empty string 'path' is required."

        supplied = Path(raw_path)

        if ".." in supplied.parts:
            return "Path traversal is prohibited."

        candidate = (
            supplied
            if supplied.is_absolute()
            else self.workspace_root / supplied
        )

        try:
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(self.workspace_root)
        except (OSError, ValueError, RuntimeError):
            return "Path escapes the authorized workspace."

        checked_parts = {
            part.casefold()
            for part in (*supplied.parts, *resolved.relative_to(
                self.workspace_root
            ).parts)
        }

        if checked_parts.intersection(self.blocked_path_parts):
            return "Path references a protected resource."

        return None
