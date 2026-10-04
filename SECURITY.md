
# AgentShield Security Model

## 1. Security objectives

AgentShield aims to:
- Enforce deterministic authorization for agent tool calls.
- Deny unknown agents and unlisted tools by default.
- Require human approval for designated sensitive operations.
- Bind approvals to a specific agent, tool, and argument digest.
- Record authorization decisions in a persistent audit database.
- Restrict filesystem access to a configured workspace.
- Prevent an approval from being consumed more than once.

## 2. Trust boundaries

### Agent / LLM
The agent is untrusted. Its plans, tool arguments, and explanations
must never determine whether an operation is authorized.

### Policy engine
The policy engine is responsible for deterministic allow, deny,
and approval-required decisions.

### Approval service
Approval grants permission for one exact operation. It does not
override policy restrictions or make an unsafe operation safe.

### MCP tool service
Every tool must enforce its own argument validation and authorization.
The MCP transport is not itself an authorization boundary.

### Filesystem
Workspace restrictions must account for absolute paths, traversal,
symbolic links, and races between validation and file access.

### Audit database
Audit events are security-relevant records. A failed audit write must
not silently permit a sensitive operation.

## 3. Current safety restrictions

- Arbitrary shell execution is disabled.
- Automatic patch application is not enabled.
- Patch proposals must not modify source files.
- Targeted test execution must remain disabled until a sandbox exists.
- Reviewer authentication currently uses a shared development token.
- Approval consumption and audit persistence are not yet one transaction.

These restrictions must not be removed merely to make a test pass.

## 4. Required controls before production

- Strong reviewer identities and role-based authorization.
- Secret management outside source code and configuration files.
- Atomic approval-state changes and audit persistence.
- Replay and concurrent-request testing.
- Safe filesystem operations resistant to symlink races.
- Bounded request sizes, argument schemas, and execution timeouts.
- Isolated execution for any future test runner.
- Structured audit events with appropriate retention and access controls.
- Dependency pinning and vulnerability scanning.
- Backup, recovery, and database migration procedures.
- Integration tests against the actual MCP SDK and transport.

## 5. Security testing

Run the full test suite:

    python -m pytest -q

A passing test suite is evidence for the tested cases only. It does
not prove that the application is secure against every attack.

Run the MCP server only in a controlled development environment:

    python -m app.mcp.server

Do not expose development reviewer credentials or the local MCP
server to untrusted clients.

## 6. Incident response

If an approval is consumed but the corresponding operation's outcome
is uncertain:

1. Do not automatically retry the operation.
2. Inspect the approval record and audit history.
3. Inspect the workspace for a partially created artifact.
4. Verify whether the operation occurred before requesting new approval.
5. Preserve relevant logs for investigation.

## 7. Release criteria

Do not enable a new sensitive tool until:
- Its argument schema is strict and bounded.
- Its policy is explicit.
- Its approval requirements are tested.
- Replay and concurrent execution are tested.
- Failure behavior is fail-closed.
- Its side effects are limited and documented.
- Its tests pass in the intended deployment environment.
