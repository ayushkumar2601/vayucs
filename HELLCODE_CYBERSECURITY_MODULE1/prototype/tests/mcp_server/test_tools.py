from __future__ import annotations
import json
from pathlib import Path
import pytest

from vayu_mcp.config import MCPConfig
from vayu_mcp.session import SessionManager
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
)


@pytest.fixture
def repo_root():
    return Path(__file__).resolve().parents[2]


@pytest.fixture
def sample_target(repo_root):
    return repo_root / "samples" / "vulnerable" / "command_injection"


@pytest.fixture
def mcp_config(repo_root, tmp_path):
    return MCPConfig(
        allowed_roots=[repo_root, tmp_path],
        mode="offline",  # Offline mode guarantees deterministic tests without Ollama dependency
        artifacts_dir=tmp_path / "artifacts",
    )


@pytest.fixture
def mcp_session():
    return SessionManager()


def test_tool_get_status(mcp_config):
    status = tool_get_status(mcp_config)
    assert status["mcp_server"]["status"] == "online"
    assert status["vayu_engine"]["available"] is True
    assert "build" in status["vayu_engine"]["supported_gates"]
    assert status["reasoning"]["configured_mode"] == "offline"
    assert status["static_analysis"]["engine"] == "semgrep"
    assert status["verification_sandbox"]["available"] is True


def test_end_to_end_mcp_workflow(sample_target, mcp_config, mcp_session, tmp_path):
    # 1. Scan repository
    scan_res = tool_scan_repository(
        str(sample_target),
        timeout_seconds=60,
        config=mcp_config,
        mgr=mcp_session,
    )
    assert "run_id" in scan_res
    run_id = scan_res["run_id"]
    assert scan_res["total_findings"] >= 1
    assert len(scan_res["finding_ids"]) >= 1

    # Find the command injection finding for deterministic offline testing
    findings_res = tool_get_findings(run_id, mgr=mcp_session)
    assert findings_res["run_id"] == run_id
    assert len(findings_res["findings"]) >= 1

    target_finding_id = None
    for f in findings_res["findings"]:
        if "shell" in f["vulnerability_type"].lower() or "command" in f["title"].lower():
            target_finding_id = f["finding_id"]
            break
    if not target_finding_id:
        target_finding_id = findings_res["findings"][0]["finding_id"]

    # 2. Analyze finding
    analysis = tool_analyze_finding(
        run_id=run_id,
        finding_id=target_finding_id,
        config=mcp_config,
        mgr=mcp_session,
    )
    assert analysis["finding_id"] == target_finding_id
    assert len(analysis["root_cause"]) > 0
    assert len(analysis["remediation_strategy"]) > 0

    # 3. Propose patch
    patch_res = tool_propose_patch(
        run_id=run_id,
        finding_id=target_finding_id,
        config=mcp_config,
        mgr=mcp_session,
    )
    assert patch_res["finding_id"] == target_finding_id
    assert "--- a/" in patch_res["unified_diff"]
    assert "+++ b/" in patch_res["unified_diff"]
    assert patch_res["validation"]["valid"] is True
    assert patch_res["status"] == "CANDIDATE_UNVERIFIED"

    # 4. Verify patch
    verify_res = tool_verify_patch(
        run_id=run_id,
        finding_id=target_finding_id,
        config=mcp_config,
        mgr=mcp_session,
    )
    assert verify_res["finding_id"] == target_finding_id
    assert verify_res["approved"] is True
    assert verify_res["decision"] == "VERIFIED"
    assert verify_res["gate_breakdown"]["gate_1_build"]["passed"] is True
    assert verify_res["gate_breakdown"]["gate_2_functional_tests"]["passed"] is True
    assert verify_res["gate_breakdown"]["gate_3_security_ast"]["passed"] is True
    assert verify_res["gate_breakdown"]["gate_4_static_rescan"]["passed"] is True

    # 5. Get run status
    status_res = tool_get_run_status(run_id, mgr=mcp_session)
    assert status_res["run_id"] == run_id
    assert status_res["counts"]["verified"] == 1

    # 6. Export SARIF
    sarif_file = tmp_path / "results.sarif"
    sarif_res = tool_export_sarif(
        run_id=run_id,
        output_path=str(sarif_file),
        config=mcp_config,
        mgr=mcp_session,
    )
    assert sarif_res["status"] == "exported"
    assert sarif_file.is_file()
    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) >= 1

    # In-memory SARIF export
    sarif_mem = tool_export_sarif(run_id=run_id, output_path=None, config=mcp_config, mgr=mcp_session)
    assert sarif_mem["status"] == "generated"
    assert "sarif" in sarif_mem

    # 7. Get Provenance
    prov = tool_get_provenance(
        run_id=run_id,
        finding_id=target_finding_id,
        config=mcp_config,
        mgr=mcp_session,
    )
    assert prov["run_id"] == run_id
    assert prov["decision"] == "VERIFIED"
    assert prov["cryptographic_verification"]["signature_valid"] is True
    assert len(prov["attestation"]["signatures"]) == 1
