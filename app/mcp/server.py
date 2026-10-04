
"""MCP stdio server for AgentShield-protected tools."""

import os

from mcp.server.fastmcp import FastMCP

from app.mcp.tool_service import ToolService


mcp = FastMCP("AgentShield")
service = ToolService()

# Development identity only. This is not client authentication.
# Do not expose this identity-controlled server to untrusted clients.
AGENT_ID = os.getenv(
    "AGENTSHIELD_MCP_AGENT_ID",
    "demo-agent",
)


@mcp.tool()
def list_project_files(max_results: int = 100) -> dict:
    """List regular files within the configured project workspace."""
    return service.list_project_files(
        agent_id=AGENT_ID,
        max_results=max_results,
    )


@mcp.tool()
def read_project_file(path: str) -> dict:
    """Read a permitted UTF-8 text file within the workspace."""
    return service.read_project_file(
        agent_id=AGENT_ID,
        path=path,
    )


@mcp.tool()
def create_patch(
    approval_id: str,
    path: str,
    patch: str,
) -> dict:
    """Create a patch proposal after verifying one-time human approval.

    This tool never applies the patch to the source file.
    """
    return service.create_patch(
        agent_id=AGENT_ID,
        approval_id=approval_id,
        path=path,
        patch=patch,
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
