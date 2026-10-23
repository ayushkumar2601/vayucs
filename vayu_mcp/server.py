from __future__ import annotations
"""FastMCP Server for VAYU Autonomous Cyber Reasoning System."""

import argparse
import logging
import os
from pathlib import Path
import sys
import warnings

# Suppress benign pydantic-settings IncompleteFieldDefinitionWarning
warnings.filterwarnings("ignore", category=UserWarning)

from mcp.server.fastmcp import FastMCP

from vayu_mcp.config import MCPConfig, load_mcp_config
from vayu_mcp.session import session_manager
from vayu_mcp.tools import (
    tool_analyze_finding,
    tool_export_sarif,
    tool_get_findings,
    tool_get_provenance,
    tool_get_run_status,
    tool_get_status,
    tool_propose_patch,
    tool_scan_repository,
    tool_verify_patch,
    tool_trace_taint_path,
    tool_get_blast_radius,
)

# Configure logging strictly to stderr to prevent polluting the stdio transport on stdout
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [vayu-mcp] %(message)s",
)
logger = logging.getLogger("vayu_mcp")


def create_server(config: MCPConfig | None = None) -> FastMCP:
    """Create and configure the VAYU FastMCP server instance."""
    cfg = config or load_mcp_config()

    mcp = FastMCP(
        name="VAYU",
        instructions=(
            "VAYU is an Autonomous Cyber Reasoning System (CRS). "
            "Use these tools to inspect system status, scan repositories for vulnerabilities, "
            "perform guarded root-cause analysis, generate minimal constrained patches with "
            "indentation normalization locks, and run isolated 4-gate verification harnesses "
            "with SLSA v1.0 cryptographic attestations."
        ),
    )

    @mcp.tool(
        name="vayu_get_status",
        description=(
            "Inspect VAYU engine health, Semgrep static analysis availability, "
            "local Ollama reasoning status, verification sandbox environment, "
            "and active workspace security policies."
        ),
    )
    def vayu_get_status() -> dict:
        """Inspect VAYU engine health and tool capabilities."""
        return tool_get_status(cfg)

    @mcp.tool(
        name="vayu_scan_repository",
        description=(
            "Scan an authorized local codebase for vulnerabilities using deterministic "
            "Semgrep AST rules. Returns a unique run_id, composite repository SHA-256, "
            "findings count, and severity distribution without modifying the target repository."
        ),
    )
    def vayu_scan_repository(target_path: str, timeout_seconds: int = 60) -> dict:
        """Scan a local repository for security vulnerabilities.
        
        Args:
            target_path: Absolute or relative directory path to the target repository.
            timeout_seconds: Maximum scan duration in seconds (default 60).
        """
        return tool_scan_repository(target_path, timeout_seconds=timeout_seconds, config=cfg)

    @mcp.tool(
        name="vayu_get_findings",
        description=(
            "Retrieve normalized vulnerability findings from an active scan run. "
            "Supports pagination and severity filtering (e.g., HIGH, CRITICAL). "
            "Returns finding IDs, rule IDs, affected files, line intervals, and evidence summaries."
        ),
    )
    def vayu_get_findings(
        run_id: str,
        severity: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """Retrieve findings from a previous scan run.
        
        Args:
            run_id: The run identifier returned by vayu_scan_repository.
            severity: Optional filter (CRITICAL, HIGH, MEDIUM, LOW, INFO).
            limit: Maximum findings to return (1-100, default 50).
            offset: Zero-based pagination offset.
        """
        sev = severity if severity.strip() else None
        return tool_get_findings(run_id, severity=sev, limit=limit, offset=offset)

    @mcp.tool(
        name="vayu_analyze_finding",
        description=(
            "Perform guarded root-cause analysis on a specific vulnerability finding. "
            "Context is strictly bounded to ±5 lines and isolated via prompt firewalling. "
            "Returns root cause, security impact, remediation strategy, and assumptions."
        ),
    )
    def vayu_analyze_finding(run_id: str, finding_id: str) -> dict:
        """Perform guarded AI root-cause analysis for a vulnerability finding.
        
        Args:
            run_id: Active scan run identifier.
            finding_id: Vulnerability finding identifier to analyze.
        """
        return tool_analyze_finding(run_id, finding_id, config=cfg)

    @mcp.tool(
        name="vayu_propose_patch",
        description=(
            "Synthesize a minimal, single-line candidate patch proposal with indentation "
            "normalization lock. Validates single-file boundaries, valid hunk offsets, and "
            "rejects file creation/deletion. Does NOT apply the patch to the target repository."
        ),
    )
    def vayu_propose_patch(run_id: str, finding_id: str) -> dict:
        """Synthesize a constrained candidate patch proposal.
        
        Args:
            run_id: Active scan run identifier.
            finding_id: Vulnerability finding identifier to remediate.
        """
        return tool_propose_patch(run_id, finding_id, config=cfg)

    @mcp.tool(
        name="vayu_verify_patch",
        description=(
            "Verify a candidate patch proposal inside an isolated, disposable sandbox (/tmp). "
            "Executes all 4 fail-closed gates: Gate 1 (Build/Syntax AST), Gate 2 (Unit Tests), "
            "Gate 3 (Security Invariant AST), Gate 4 (Static Rescan). "
            "Original target repository is completely untouched."
        ),
    )
    def vayu_verify_patch(run_id: str, finding_id: str) -> dict:
        """Verify candidate patch in isolated sandbox across 4 fail-closed gates.
        
        Args:
            run_id: Active scan run identifier.
            finding_id: Finding identifier whose candidate patch should be verified.
        """
        return tool_verify_patch(run_id, finding_id, config=cfg)

    @mcp.tool(
        name="vayu_get_run_status",
        description=(
            "Retrieve complete end-to-end execution status for a scan run, "
            "including findings progress, analyzed count, patch proposal count, "
            "and gate verification decisions."
        ),
    )
    def vayu_get_run_status(run_id: str) -> dict:
        """Retrieve complete status and summary for a scan run.
        
        Args:
            run_id: Active scan run identifier.
        """
        return tool_get_run_status(run_id)

    @mcp.tool(
        name="vayu_export_sarif",
        description=(
            "Export scan findings and verified remediation outcomes in OASIS SARIF v2.1.0 "
            "format for GitHub Security Tab and CI/CD pipelines. Can return JSON or write to "
            "a validated output file."
        ),
    )
    def vayu_export_sarif(run_id: str, output_path: str = "") -> dict:
        """Export run findings and remediation decisions in SARIF v2.1.0 format.
        
        Args:
            run_id: Active scan run identifier.
            output_path: Optional file path destination to save SARIF JSON.
        """
        out = output_path if output_path.strip() else None
        return tool_export_sarif(run_id, output_path=out, config=cfg)

    @mcp.tool(
        name="vayu_get_provenance",
        description=(
            "Generate and cryptographically verify an in-toto SLSA v1.0 provenance "
            "attestation signed with ECDSA (P-256) over repository and patch SHA-256 digests."
        ),
    )
    def vayu_get_provenance(run_id: str, finding_id: str = "") -> dict:
        """Retrieve signed SLSA v1.0 provenance attestation.
        
        Args:
            run_id: Active scan run identifier.
            finding_id: Optional specific finding identifier (defaults to first verified finding).
        """
        fid = finding_id if finding_id.strip() else None
        return tool_get_provenance(run_id, finding_id=fid, config=cfg)

    @mcp.tool(
        name="vayu_trace_taint_path",
        description=(
            "Trace inter-procedural taint reachability paths from sources to sinks "
            "across repository files using the Code Property Graph (CPG) & Neo4j."
        ),
    )
    def vayu_trace_taint_path(target_path: str) -> dict:
        """Trace cross-file taint flows using the Code Property Graph."""
        return tool_trace_taint_path(target_path, config=cfg)

    @mcp.tool(
        name="vayu_get_blast_radius",
        description=(
            "Compute the call dependency blast radius and identify affected functions/files "
            "prior to applying a candidate patch."
        ),
    )
    def vayu_get_blast_radius(target_path: str, target_file: str, function_name: str) -> dict:
        """Compute caller blast radius for a target function."""
        return tool_get_blast_radius(target_path, target_file, function_name, config=cfg)

    return mcp


def main() -> None:
    """Console script entry point for `vayu-mcp`."""
    parser = argparse.ArgumentParser(
        description="VAYU Autonomous Cyber Reasoning System (CRS) MCP Server"
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default=None,
        help="Path to vayu-config.toml configuration file",
    )
    parser.add_argument(
        "--mode",
        "-m",
        type=str,
        choices=["auto", "ollama", "offline"],
        default=None,
        help="Reasoning mode (auto, ollama, offline)",
    )
    parser.add_argument(
        "--allowed-root",
        "-r",
        action="append",
        dest="allowed_roots",
        help="Authorized workspace root path (can be specified multiple times)",
    )
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport protocol (default: stdio)",
    )

    args = parser.parse_args()

    cfg = load_mcp_config(args.config)
    if args.mode:
        cfg.mode = args.mode
    if args.allowed_roots:
        cfg.allowed_roots = [Path(r).expanduser().resolve() for r in args.allowed_roots]

    logger.info("Initializing VAYU MCP Server (mode=%s, transport=%s)...", cfg.mode, args.transport)
    server = create_server(cfg)

    try:
        server.run(transport=args.transport)
    except KeyboardInterrupt:
        logger.info("VAYU MCP Server stopped by operator.")
    except Exception as exc:
        logger.error("VAYU MCP Server encountered fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
