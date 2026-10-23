from __future__ import annotations
import pytest

from vayu_mcp.config import MCPConfig
from vayu_mcp.server import create_server


def test_fastmcp_server_initialization():
    config = MCPConfig(mode="offline")
    server = create_server(config)
    assert server.name == "VAYU"

    tool_names = [t.name for t in server._tool_manager.list_tools()]
    expected_tools = [
        "vayu_get_status",
        "vayu_scan_repository",
        "vayu_get_findings",
        "vayu_analyze_finding",
        "vayu_propose_patch",
        "vayu_verify_patch",
        "vayu_get_run_status",
        "vayu_export_sarif",
        "vayu_get_provenance",
    ]
    for expected in expected_tools:
        assert expected in tool_names, f"Expected tool '{expected}' not registered on FastMCP server"


def test_fastmcp_call_status_tool():
    import asyncio
    config = MCPConfig(mode="offline")
    server = create_server(config)

    # Call tool through FastMCP public call_tool method
    result = asyncio.run(server.call_tool("vayu_get_status", {}))
    assert result is not None
    assert len(result) >= 1
    text = result[0].text
    assert "online" in text
    assert "vayu_engine" in text
