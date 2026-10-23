---
name: mcp-development
description: Develop and integrate Model Context Protocol (MCP) tools safely over stdio transport.
category: Developer Tooling
version: 1.0.0
author: VAYU Development Team
---

# MCP Server Development

## Objective
Implement, test, and expose secure local tools for AI coding assistants using the official Model Context Protocol (MCP) Python SDK (`FastMCP`).

## Core Invariants
1. **Stdio Stream Hygiene**:
   - `sys.stdout` is strictly reserved for JSON-RPC protocol frames.
   - All application logs, diagnostics, and warnings MUST route to `sys.stderr`.
   - Any print to stdout will corrupt the client's JSON-RPC stream parser.
2. **Workspace Boundary Enforcement**:
   - Never allow MCP tool arguments to access arbitrary filesystem locations.
   - Validate all target paths against configured `allowed_roots`.
   - Reject path traversal (`..`), null bytes, and symlinks resolving outside the root.
3. **Session & Run Isolation**:
   - Maintain run state in an authoritative thread-safe manager (`SessionManager`).
   - Prevent cross-contamination between concurrent client sessions.
4. **Typed Schemas & Output Bounding**:
   - Use clear type annotations and descriptive docstrings for tool parameters.
   - Return bounded results; never dump entire source trees or unpaginated logs.
