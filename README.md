
# AgentShield

**Security Gateway for AI Agents and MCP Tools**

AgentShield is a security platform designed to control, monitor, and audit AI agent interactions with tools and local project resources.

The goal is to provide a deterministic security layer between AI agents and the tools they use, with policy enforcement, approval workflows, protected filesystem access, and auditable execution decisions.

## Key Goals

- Enforce explicit tool-access policies.
- Apply default-deny authorization.
- Protect workspace files from unauthorized access.
- Require human approval for sensitive operations.
- Prevent approval reuse through atomic, one-time consumption.
- Maintain an audit trail of security decisions.
- Support Model Context Protocol (MCP) tool integration.
- Keep security enforcement independent of LLM output.

## Architecture

```text
AI Agent
   |
   v
MCP Server
   |
   v
Tool Service
   |
   +----> Policy Engine
   |
   +----> Safe Filesystem
   |
   +----> Approval Service
   |          |
   |          v
   |     Approval Repository
   |
   v
Audit Repository
   |
   v
SQLite Database
```

## Planned Security Features

### Policy Enforcement

- Allow, deny, or require approval for tool calls.
- Restrict tools by agent identity.
- Validate tool arguments and file paths.
- Deny unrecognized or unauthorized operations.

### Filesystem Protection

- Restrict access to a configured workspace.
- Reject path traversal attempts.
- Prevent access to protected files and directories.
- Reject unsafe symbolic-link traversal.
- Apply file-size and encoding limits.

### Approval Workflow

- Persist approval requests.
- Support reviewer decisions.
- Bind approvals to an agent, tool, and argument digest.
- Consume approved requests atomically and only once.
- Fail closed when approval verification fails.

### Audit Logging

- Record security decisions and their reasons.
- Associate events with request identifiers.
- Persist audit events for later inspection.
- Avoid exposing sensitive arguments in reviewer-facing records.

### MCP Integration

The intended MCP interface includes:

- `list_project_files`
- `read_project_file`
- `create_patch`

Patch proposals are intended to be stored separately for manual review rather than directly modifying source files.

Arbitrary shell execution is outside the intended default security boundary.

## Technology Stack

- Python
- FastAPI
- Model Context Protocol (MCP)
- SQLite
- Pydantic
- Pytest
- Docker (planned deployment support)

## LLM API Key

An LLM API key is **not required** for deterministic policy enforcement, filesystem protection, approval validation, or audit logging.

An API key may be added later for optional AI-powered code analysis or patch generation. Model output must never replace the security policy engine.

## Project Status

**Development status: In progress.**

The design and code for several backend components have been discussed. Integration, end-to-end behavior, security test results, and deployment readiness have not been independently verified.

Do not treat the planned features above as proof that they are fully implemented.

## Development Setup

Use Python 3.11 or a compatible version supported by the project's dependencies.

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies if a project requirements file is available:

```powershell
pip install -r requirements.txt
```

Run tests, when the project and dependencies are ready:

```powershell
python -m pytest -v
```

The exact startup command depends on the implemented application entry point.

## Security Principles

1. Default deny.
2. Least privilege.
3. Explicit authorization for sensitive operations.
4. One-time approval consumption.
5. Fail-closed behavior.
6. Auditable security decisions.
7. No direct source modification through patch proposals.
8. LLM output is not a security boundary.

## Roadmap

- [ ] Complete SafeWorkspace integration.
- [ ] Integrate policy enforcement into every MCP tool.
- [ ] Complete approval-gated execution.
- [ ] Harden audit logging and failure handling.
- [ ] Run integration and adversarial security tests.
- [ ] Add authentication and reviewer authorization.
- [ ] Containerize the application.
- [ ] Configure automated CI testing.
- [ ] Verify deployment and document operational security.

## License

Choose and add an appropriate open-source license before public distribution.
```

**Important:** Save this as `README.md` in the repository root. It documents the intended architecture honestly; it does not claim the application is complete or production-ready.