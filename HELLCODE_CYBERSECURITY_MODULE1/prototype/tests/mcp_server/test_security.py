from __future__ import annotations
from pathlib import Path
import pytest

from vayu_mcp.config import MCPConfig, SecurityBoundaryError
from vayu_mcp.session import SessionManager
from vayu_mcp.tools import (
    tool_analyze_finding,
    tool_get_provenance,
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


def test_reject_unauthorized_target_scan(sample_target, repo_root):
    # Only allow a specific subfolder, target is outside
    isolated_config = MCPConfig(allowed_roots=[repo_root / "crs"])
    mgr = SessionManager()

    with pytest.raises(SecurityBoundaryError, match="outside authorized workspace roots"):
        tool_scan_repository(str(sample_target), config=isolated_config, mgr=mgr)


def test_reject_unknown_run_id():
    with pytest.raises(ValueError, match="Run ID not found"):
        tool_verify_patch(run_id="fake-run-id", finding_id="F-1")


def test_reject_unknown_finding_id(sample_target, repo_root):
    config = MCPConfig(allowed_roots=[repo_root], mode="offline")
    mgr = SessionManager()
    scan = tool_scan_repository(str(sample_target), config=config, mgr=mgr)
    run_id = scan["run_id"]

    with pytest.raises(ValueError, match="does not exist in run"):
        tool_analyze_finding(run_id=run_id, finding_id="NONEXISTENT-FINDING", config=config, mgr=mgr)


def test_reject_verify_before_propose(sample_target, repo_root):
    config = MCPConfig(allowed_roots=[repo_root], mode="offline")
    mgr = SessionManager()
    scan = tool_scan_repository(str(sample_target), config=config, mgr=mgr)
    run_id = scan["run_id"]
    finding_id = scan["finding_ids"][0]

    with pytest.raises(ValueError, match="No candidate patch proposed"):
        tool_verify_patch(run_id=run_id, finding_id=finding_id, config=config, mgr=mgr)


def test_reject_provenance_before_verify(sample_target, repo_root):
    config = MCPConfig(allowed_roots=[repo_root], mode="offline")
    mgr = SessionManager()
    scan = tool_scan_repository(str(sample_target), config=config, mgr=mgr)
    run_id = scan["run_id"]
    finding_id = scan["finding_ids"][0]

    with pytest.raises(ValueError, match="must have completed reasoning, patching, and verification"):
        tool_get_provenance(run_id=run_id, finding_id=finding_id, config=config, mgr=mgr)


def test_target_repository_never_modified_during_run(sample_target, repo_root):
    app_py = sample_target / "app.py"
    original_content = app_py.read_text(encoding="utf-8")

    config = MCPConfig(allowed_roots=[repo_root], mode="offline")
    mgr = SessionManager()
    scan = tool_scan_repository(str(sample_target), config=config, mgr=mgr)
    run_id = scan["run_id"]

    # Pick command injection finding
    finding_id = None
    for fid in scan["finding_ids"]:
        finding = mgr.require_run(run_id).get_finding(fid)
        if finding and "shell" in finding.vulnerability_type.lower():
            finding_id = fid
            break
    if not finding_id:
        finding_id = scan["finding_ids"][0]

    tool_analyze_finding(run_id=run_id, finding_id=finding_id, config=config, mgr=mgr)
    tool_propose_patch(run_id=run_id, finding_id=finding_id, config=config, mgr=mgr)
    tool_verify_patch(run_id=run_id, finding_id=finding_id, config=config, mgr=mgr)

    # Confirm original file on disk is strictly unmodified
    current_content = app_py.read_text(encoding="utf-8")
    assert current_content == original_content, "Target repository file was unexpectedly modified!"
