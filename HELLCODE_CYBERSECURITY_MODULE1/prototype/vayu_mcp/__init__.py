"""VAYU Model Context Protocol (MCP) Server.

Enables AI coding assistants (Claude Desktop, Claude Code, Cursor, Windsurf)
to autonomously run VAYU security scans, guarded reasoning, constrained patch synthesis,
and isolated 4-gate verification via standard MCP stdio transport.
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "VAYU Development Team"

from vayu_mcp.config import MCPConfig, load_mcp_config
from vayu_mcp.session import SessionManager, RunState

__all__ = [
    "__version__",
    "MCPConfig",
    "load_mcp_config",
    "SessionManager",
    "RunState",
]
