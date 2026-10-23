from __future__ import annotations
"""Core implementation of the 9 VAYU Model Context Protocol (MCP) tools."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.request

from crs.cicd.ci_runner import export_sarif_report
from crs.core.schemas import (
    CRSRunResult,
    PatchProposal,
    ReasoningResult,
    VerificationResult,
    VulnerabilityFinding,
)
from crs.ingestion.repository_loader import RepositoryLoader
from crs.patching.patch_generator import PatchGenerator
from crs.patching.patch_validator import PatchValidator
from crs.reasoning.evidence_builder import EvidenceBuilder
from crs.reasoning.offline_client import OfflineRulesClient
from crs.reasoning.ollama_client import OllamaLLMClient
from crs.reasoning.reasoning_engine import ReasoningEngine
from crs.reporting.provenance import build_run_provenance
from crs.reporting.slsa_provenance import (
    build_slsa_attestation,
    generate_keypair,
    verify_provenance_signature,
)
from crs.static_analysis.scanner import StaticScanner
from crs.verification.verification_engine import VerificationEngine
from vayu_mcp.config import MCPConfig, SecurityBoundaryError
from vayu_mcp.session import RunState, SessionManager, session_manager


def is_ollama_reachable(base_url: str, timeout: float = 1.5) -> bool:
    """Check if the local Ollama HTTP endpoint is responding."""
    try:
        url = f"{base_url.rstrip('/')}/api/tags"
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def is_semgrep_available() -> tuple[bool, str]:
    """Check if the semgrep CLI executable is installed and runnable."""
    import shutil
    semgrep_bin = "semgrep"
    if not shutil.which("semgrep"):
        venv_bin = Path(sys.executable).parent / "semgrep"
        if venv_bin.is_file():
            semgrep_bin = str(venv_bin)
    try:
        res = subprocess.run(
            [semgrep_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        if res.returncode == 0:
            return True, res.stdout.strip().split("\n")[0]
        return False, f"semgrep exited with code {res.returncode}"
    except Exception as exc:
        return False, str(exc)


def resolve_clients(config: MCPConfig) -> tuple[Any, Any, str]:
    """Resolve reasoning and patch client based on configuration and availability."""
    if config.mode == "offline":
        client = OfflineRulesClient()
        return client, client, "offline-rules"

    if config.mode == "ollama":
        client = OllamaLLMClient(
            base_url=config.ollama_url,
            model=config.ollama_model,
            timeout=config.default_timeout,
        )
        return client, client, f"ollama ({config.ollama_model})"

    # Auto mode: try Ollama first, fallback to offline rules
    if is_ollama_reachable(config.ollama_url):
        client = OllamaLLMClient(
            base_url=config.ollama_url,
            model=config.ollama_model,
            timeout=config.default_timeout,
        )
        return client, client, f"ollama ({config.ollama_model})"

    print(
        f"[vayu-mcp] Ollama unreachable at {config.ollama_url}; falling back to offline rules",
        file=sys.stderr,
    )
    client = OfflineRulesClient()
    return client, client, "offline-rules (fallback)"


# ============================================================================
# TOOL 1: vayu_get_status
# ============================================================================
def tool_get_status(config: MCPConfig) -> dict[str, Any]:
    """Inspect environment, dependencies, reasoning backends, and verification capabilities."""
    ollama_ok = is_ollama_reachable(config.ollama_url)
    semgrep_ok, semgrep_ver = is_semgrep_available()

    missing = []
    guidance = []
    if not semgrep_ok:
        missing.append("semgrep")
        guidance.append("Install Semgrep via 'pip install semgrep' or brew install semgrep.")
    if not ollama_ok and config.mode != "offline":
        missing.append("ollama")
        guidance.append(
            f"Ollama is unreachable at {config.ollama_url}. Run 'ollama serve' or set VAYU_MCP_MODE=offline."
        )

    return {
        "mcp_server": {
            "status": "online",
            "version": "0.1.0",
            "protocol": "mcp/stdio",
        },
        "vayu_engine": {
            "available": True,
            "version": "1.0.0",
            "supported_gates": ["build", "functional_tests", "security_property_ast", "static_rescan"],
        },
        "reasoning": {
            "configured_mode": config.mode,
            "ollama_endpoint": config.ollama_url,
            "ollama_model": config.ollama_model,
            "ollama_available": ollama_ok,
            "active_client": resolve_clients(config)[2],
        },
        "static_analysis": {
            "engine": "semgrep",
            "available": semgrep_ok,
            "version_info": semgrep_ver,
        },
        "verification_sandbox": {
            "available": True,
            "python_executable": sys.executable,
            "disposable_workspace": "tempfile.TemporaryDirectory",
        },
        "workspace_policy": {
            "allowed_roots": [str(r) for r in config.allowed_roots],
            "boundary_enforcement": "strict",
        },
        "missing_dependencies": missing,
        "setup_guidance": guidance,
    }


# ============================================================================
# TOOL 2: vayu_scan_repository
# ============================================================================
def tool_scan_repository(
    target_path: str,
    timeout_seconds: int = 60,
    config: MCPConfig | None = None,
    mgr: SessionManager | None = None,
) -> dict[str, Any]:
    """Scan an authorized local codebase with Semgrep AST rules and register a run session."""
    cfg = config or MCPConfig()
    manager = mgr or session_manager

    # 1. Enforce path security
    resolved_path = cfg.validate_target_path(target_path)

    # 2. Ingest repository metadata and compute SHA-256 fingerprint
    loader = RepositoryLoader()
    target = loader.load(str(resolved_path))

    # 3. Execute deterministic static analysis
    scanner = StaticScanner()
    findings = scanner.scan(target.path)

    # 4. Initialize authoritative run state
    run_state = manager.create_run(target, findings)

    # Severity tally
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = getattr(f.severity, "value", str(f.severity)).upper()
        if sev in counts:
            counts[sev] += 1

    return {
        "run_id": run_state.run_id,
        "repository_name": target.name,
        "repository_path": target.path,
        "repository_sha256": target.repository_hash,
        "file_count": target.file_count,
        "total_findings": len(findings),
        "by_severity": counts,
        "finding_ids": [f.finding_id for f in findings],
        "summary": f"Discovered {len(findings)} vulnerabilities in {target.name} across {target.file_count} files.",
        "next_actions": [
            f"Call 'vayu_get_findings' with run_id='{run_state.run_id}' to inspect finding details.",
            f"Call 'vayu_analyze_finding' with run_id='{run_state.run_id}' and a finding_id for root cause analysis.",
        ],
    }


# ============================================================================
# TOOL 3: vayu_get_findings
# ============================================================================
def tool_get_findings(
    run_id: str,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
    mgr: SessionManager | None = None,
) -> dict[str, Any]:
    """Retrieve normalized vulnerability findings for an existing scan run."""
    manager = mgr or session_manager
    run = manager.require_run(run_id)

    findings = run.findings
    if severity:
        sev_upper = severity.upper()
        findings = [
            f for f in findings if getattr(f.severity, "value", str(f.severity)).upper() == sev_upper
        ]

    limit = min(100, max(1, limit))
    offset = max(0, offset)
    sliced = findings[offset : offset + limit]

    results = []
    for f in sliced:
        evidence_summary = (
            f.evidence[0].description if f.evidence else "Static AST rule pattern match"
        )
        results.append({
            "finding_id": f.finding_id,
            "title": f.title,
            "vulnerability_type": f.vulnerability_type,
            "severity": getattr(f.severity, "value", str(f.severity)),
            "file": f.file,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "evidence_summary": evidence_summary,
            "analyzed": f.finding_id in run.reasonings,
            "patch_proposed": f.finding_id in run.patches,
            "verified": (
                run.verifications[f.finding_id].approved
                if f.finding_id in run.verifications
                else None
            ),
        })

    return {
        "run_id": run_id,
        "total_matching": len(findings),
        "offset": offset,
        "limit": limit,
        "findings": results,
    }


# ============================================================================
# TOOL 4: vayu_analyze_finding
# ============================================================================
def tool_analyze_finding(
    run_id: str,
    finding_id: str,
    config: MCPConfig | None = None,
    mgr: SessionManager | None = None,
) -> dict[str, Any]:
    """Perform guarded AI root-cause and remediation reasoning on a vulnerability finding."""
    cfg = config or MCPConfig()
    manager = mgr or session_manager
    run = manager.require_run(run_id)

    finding = run.get_finding(finding_id)
    if not finding:
        raise ValueError(f"Finding ID '{finding_id}' does not exist in run '{run_id}'.")

    # Return cached reasoning if already computed
    if finding_id in run.reasonings:
        res = run.reasonings[finding_id]
        return {
            "run_id": run_id,
            "finding_id": finding_id,
            "cached": True,
            "vulnerability_class": res.vulnerability_class,
            "root_cause": res.root_cause,
            "security_impact": res.security_impact,
            "remediation_strategy": res.remediation_strategy,
            "assumptions": res.assumptions,
            "evidence_references": res.evidence_references,
            "confidence": res.confidence,
        }

    # Extract bounded context and package evidence with prompt firewall
    builder = EvidenceBuilder()
    evidence_package = builder.build(finding, run.target.path, run.target.repository_hash)

    # Resolve reasoning client
    client, _, provider_name = resolve_clients(cfg)
    engine = ReasoningEngine(client, evidence_builder=builder)

    # Execute guarded reasoning
    run.stage = "REASON"
    reasoning_result = engine.reason_from_evidence(evidence_package)
    run.reasonings[finding_id] = reasoning_result

    return {
        "run_id": run_id,
        "finding_id": finding_id,
        "cached": False,
        "provider": provider_name,
        "vulnerability_class": reasoning_result.vulnerability_class,
        "root_cause": reasoning_result.root_cause,
        "security_impact": reasoning_result.security_impact,
        "remediation_strategy": reasoning_result.remediation_strategy,
        "assumptions": reasoning_result.assumptions,
        "evidence_references": reasoning_result.evidence_references,
        "confidence": reasoning_result.confidence,
        "security_notice": "Repository code was bounded (±5 lines) and quarantined in UNTRUSTED_REPOSITORY_CONTENT tags.",
    }


# ============================================================================
# TOOL 5: vayu_propose_patch
# ============================================================================
def tool_propose_patch(
    run_id: str,
    finding_id: str,
    config: MCPConfig | None = None,
    mgr: SessionManager | None = None,
) -> dict[str, Any]:
    """Generate a constrained, single-line candidate patch proposal with indentation lock."""
    cfg = config or MCPConfig()
    manager = mgr or session_manager
    run = manager.require_run(run_id)

    finding = run.get_finding(finding_id)
    if not finding:
        raise ValueError(f"Finding ID '{finding_id}' does not exist in run '{run_id}'.")

    # Ensure reasoning exists first
    reasoning = run.reasonings.get(finding_id)
    if not reasoning:
        analysis = tool_analyze_finding(run_id, finding_id, config=cfg, mgr=manager)
        reasoning = run.reasonings[finding_id]

    builder = EvidenceBuilder()
    evidence_package = builder.build(finding, run.target.path, run.target.repository_hash)

    _, patch_client, provider_name = resolve_clients(cfg)
    validator = PatchValidator()
    generator = PatchGenerator(patch_client, validator=validator)

    run.stage = "PATCH"
    proposal = generator.generate(finding, reasoning, evidence_package.code_context)

    # Deterministic structural validation
    validation = validator.validate(
        proposal,
        finding,
        repository_root=run.target.path,
        intended_file=evidence_package.code_context.file,
    )

    run.patches[finding_id] = proposal

    return {
        "run_id": run_id,
        "finding_id": finding_id,
        "target_file": proposal.target_file,
        "rationale": proposal.rationale,
        "unified_diff": proposal.unified_diff,
        "validation": {
            "valid": validation.valid,
            "reason": validation.reason,
            "files_touched": validation.files_touched,
        },
        "confidence": proposal.confidence,
        "status": "CANDIDATE_UNVERIFIED",
        "notice": (
            "This patch is a candidate proposal only. It has NOT been applied to the target "
            "repository and MUST NOT be considered verified until passing 'vayu_verify_patch'."
        ),
    }


# ============================================================================
# TOOL 6: vayu_verify_patch
# ============================================================================
def tool_verify_patch(
    run_id: str,
    finding_id: str,
    config: MCPConfig | None = None,
    mgr: SessionManager | None = None,
) -> dict[str, Any]:
    """Verify a candidate patch proposal inside an ephemeral disposable sandbox across all 4 gates."""
    manager = mgr or session_manager
    run = manager.require_run(run_id)

    finding = run.get_finding(finding_id)
    if not finding:
        raise ValueError(f"Finding ID '{finding_id}' does not exist in run '{run_id}'.")

    patch = run.patches.get(finding_id)
    if not patch:
        raise ValueError(
            f"No candidate patch proposed for finding '{finding_id}'. Call 'vayu_propose_patch' first."
        )

    run.stage = "VERIFY"
    verifier = VerificationEngine()
    result = verifier.verify(run.target.path, finding, patch)
    run.verifications[finding_id] = result

    decision = "VERIFIED" if result.approved else "REJECTED"

    return {
        "run_id": run_id,
        "finding_id": finding_id,
        "decision": decision,
        "approved": result.approved,
        "gate_breakdown": {
            "gate_1_build": {
                "passed": result.build_passed,
                "name": "Build / Syntax AST Compilation Check",
            },
            "gate_2_functional_tests": {
                "passed": result.tests_passed,
                "name": "Functional Unit Test Suite",
            },
            "gate_3_security_ast": {
                "passed": result.security_test_passed,
                "name": "Security Invariant AST Inspection",
            },
            "gate_4_static_rescan": {
                "passed": result.static_rescan_clean,
                "name": "Independent Static Analysis Rescan",
            },
        },
        "reason": result.reason,
        "sandbox_isolation": (
            "Verification executed strictly inside a temporary workspace (/tmp). "
            "The original repository was never modified."
        ),
    }


# ============================================================================
# TOOL 7: vayu_get_run_status
# ============================================================================
def tool_get_run_status(run_id: str, mgr: SessionManager | None = None) -> dict[str, Any]:
    """Retrieve the authoritative end-to-end execution state and summary of a scan run."""
    manager = mgr or session_manager
    run = manager.require_run(run_id)
    return run.to_summary_dict()


# ============================================================================
# TOOL 8: vayu_export_sarif
# ============================================================================
def tool_export_sarif(
    run_id: str,
    output_path: str | None = None,
    config: MCPConfig | None = None,
    mgr: SessionManager | None = None,
) -> dict[str, Any]:
    """Export run findings and remediation decisions in OASIS SARIF v2.1.0 format."""
    cfg = config or MCPConfig()
    manager = mgr or session_manager
    run = manager.require_run(run_id)

    rules = []
    results = []

    for finding in run.findings:
        fid = finding.finding_id
        rule_id = finding.vulnerability_type.lower().replace(" ", "-")
        rules.append({
            "id": rule_id,
            "shortDescription": {"text": finding.vulnerability_type},
            "fullDescription": {"text": finding.title},
        })

        is_verified = run.verifications.get(fid) and run.verifications[fid].approved
        msg = f"Remediated by VAYU: {is_verified}" if fid in run.verifications else "Detected by VAYU static analysis"

        results.append({
            "ruleId": rule_id,
            "level": "error" if str(finding.severity).upper() in ("HIGH", "CRITICAL") else "warning",
            "message": {"text": msg},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file or "unknown"},
                        "region": {"startLine": finding.line_start or 1},
                    }
                }
            ],
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VAYU CRS MCP",
                        "version": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    if output_path:
        dest = cfg.validate_output_path(output_path)
        dest.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        return {
            "run_id": run_id,
            "status": "exported",
            "output_file": str(dest),
            "findings_exported": len(results),
        }

    return {
        "run_id": run_id,
        "status": "generated",
        "sarif": sarif_doc,
        "findings_exported": len(results),
    }


# ============================================================================
# TOOL 9: vayu_get_provenance
# ============================================================================
def tool_get_provenance(
    run_id: str,
    finding_id: str | None = None,
    config: MCPConfig | None = None,
    mgr: SessionManager | None = None,
) -> dict[str, Any]:
    """Retrieve in-toto SLSA v1.0 provenance attestation signed with ECDSA (P-256)."""
    cfg = config or MCPConfig()
    manager = mgr or session_manager
    run = manager.require_run(run_id)

    # Select finding
    fid = finding_id
    if not fid:
        # Prefer a verified finding, or first finding with verification, or first finding
        verified_fids = [k for k, v in run.verifications.items() if v.approved]
        if verified_fids:
            fid = verified_fids[0]
        elif run.verifications:
            fid = list(run.verifications.keys())[0]
        elif run.findings:
            fid = run.findings[0].finding_id
        else:
            raise ValueError(f"No findings exist in run '{run_id}'.")

    finding = run.get_finding(fid)
    if not finding:
        raise ValueError(f"Finding ID '{fid}' does not exist in run '{run_id}'.")

    reasoning = run.reasonings.get(fid)
    patch = run.patches.get(fid)
    verification = run.verifications.get(fid)

    if not reasoning or not patch or not verification:
        raise ValueError(
            f"Finding '{fid}' must have completed reasoning, patching, and verification before generating provenance. "
            f"Status: reasoning={bool(reasoning)}, patch={bool(patch)}, verification={bool(verification)}."
        )

    crs_result = CRSRunResult(
        target=run.target,
        finding=finding,
        reasoning=reasoning,
        patch=patch,
        verification=verification,
    )

    _, _, provider_name = resolve_clients(cfg)
    run_record = build_run_provenance(
        crs_result,
        model=cfg.ollama_model,
        provider=provider_name,
        run_id=run.run_id,
    )

    private_key, public_key = generate_keypair()
    statement = build_slsa_attestation(run_record, private_key=private_key)

    # Cryptographically verify the signature
    sig = statement.get("signatures", [{}])[0].get("sig", "")
    clean_statement = {k: v for k, v in statement.items() if k != "signatures"}
    sig_valid = verify_provenance_signature(clean_statement, sig, public_key) if sig else False

    patch_sha256 = hashlib.sha256(patch.unified_diff.encode("utf-8")).hexdigest()

    return {
        "run_id": run_id,
        "finding_id": fid,
        "decision": "VERIFIED" if verification.approved else "REJECTED",
        "repository_sha256": run.target.repository_hash,
        "patch_sha256": patch_sha256,
        "attestation": statement,
        "cryptographic_verification": {
            "signature_valid": sig_valid,
            "algorithm": "ECDSA-SHA256 (P-256 / SECP256R1)",
            "policy": "fail-closed",
        },
    }


def tool_trace_taint_path(
    target_path: str,
    config: MCPConfig | None = None,
) -> dict[str, Any]:
    """Analyze a repository using the Code Property Graph (CPG) & Neo4j to trace taint flows."""
    from crs.graph.neo4j_client import Neo4jClient
    from crs.static_analysis.taint_graph import TaintGraphAnalyzer

    cfg = config or MCPConfig()
    boundary = cfg.validate_target_path(target_path)

    neo4j_client = Neo4jClient()
    neo4j_client.connect()
    analyzer = TaintGraphAnalyzer(neo4j_client=neo4j_client)
    flows = analyzer.analyze_repository(boundary)

    return {
        "repository": str(boundary),
        "neo4j_connected": neo4j_client.is_available,
        "flow_count": len(flows),
        "flows": [
            {
                "source": {"file": f.source.file, "line": f.source.line, "name": f.source.name},
                "sink": {"file": f.sink.file, "line": f.sink.line, "name": f.sink.name},
                "call_stack": f.call_stack,
            }
            for f in flows
        ],
    }


def tool_get_blast_radius(
    target_path: str,
    target_file: str,
    function_name: str,
    config: MCPConfig | None = None,
) -> dict[str, Any]:
    """Compute call dependency blast radius for a target function in the repository."""
    from crs.graph.blast_radius import BlastRadiusAnalyzer
    from crs.graph.cpg_indexer import CPGIndexer
    from crs.graph.neo4j_client import Neo4jClient

    cfg = config or MCPConfig()
    boundary = cfg.validate_target_path(target_path)

    neo4j_client = Neo4jClient()
    neo4j_client.connect()

    indexer = CPGIndexer(neo4j_client=neo4j_client)
    cpg = indexer.index_repository(boundary)

    analyzer = BlastRadiusAnalyzer(cpg=cpg, neo4j_client=neo4j_client)
    res = analyzer.analyze(target_file, function_name)

    return {
        "repository": str(boundary),
        "neo4j_connected": neo4j_client.is_available,
        "target_file": res.target_file,
        "target_function": res.target_function,
        "affected_functions": res.affected_functions,
        "affected_files": res.affected_files,
        "prioritized_test_files": res.prioritized_test_files,
        "impact_score": res.impact_score,
    }
