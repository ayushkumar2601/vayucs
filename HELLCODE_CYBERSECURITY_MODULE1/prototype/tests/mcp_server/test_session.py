from __future__ import annotations
import pytest

from crs.core.schemas import (
    AnalysisTarget,
    PatchProposal,
    ReasoningResult,
    Severity,
    VerificationResult,
    VulnerabilityFinding,
)
from vayu_mcp.session import SessionManager


def test_session_manager_create_and_retrieve():
    mgr = SessionManager()
    target = AnalysisTarget(
        name="test_repo",
        path="/tmp/test_repo",
        languages=["python"],
        file_count=5,
        repository_hash="sha256_dummy",
    )
    finding = VulnerabilityFinding(
        finding_id="FIND-1",
        title="Command Injection",
        vulnerability_type="subprocess-shell-true",
        severity=Severity.HIGH,
        confidence=0.9,
        file="app.py",
        line_start=10,
        line_end=10,
        evidence=[],
    )

    run = mgr.create_run(target, [finding], run_id="run-123")
    assert run.run_id == "run-123"
    assert run.target.name == "test_repo"
    assert len(run.findings) == 1
    assert run.get_finding("FIND-1") == finding

    retrieved = mgr.get_run("run-123")
    assert retrieved == run

    with pytest.raises(ValueError, match="Run ID not found"):
        mgr.require_run("nonexistent")


def test_session_manager_run_summary():
    mgr = SessionManager()
    target = AnalysisTarget(
        name="test_repo",
        path="/tmp/test_repo",
        languages=["python"],
        file_count=2,
        repository_hash="abc",
    )
    finding = VulnerabilityFinding(
        finding_id="F-1",
        title="Hardcoded Secret",
        vulnerability_type="hardcoded-secret",
        severity=Severity.MEDIUM,
        confidence=0.8,
        file="config.py",
        line_start=5,
        evidence=[],
    )
    run = mgr.create_run(target, [finding], run_id="run-summary-test")

    # Before reasoning
    summary = run.to_summary_dict()
    assert summary["counts"]["total_findings"] == 1
    assert summary["counts"]["analyzed"] == 0
    assert summary["findings"][0]["status"] == "DISCOVERED"

    # Add reasoning
    run.reasonings["F-1"] = ReasoningResult(
        finding_id="F-1",
        vulnerability_class="Hardcoded Secret",
        root_cause="Secret literal in code",
        security_impact="Leaked credentials",
        remediation_strategy="Use os.getenv",
        assumptions=[],
        evidence_references=[],
        confidence=0.95,
    )
    assert run.to_summary_dict()["findings"][0]["status"] == "ANALYZED"

    # Add patch
    run.patches["F-1"] = PatchProposal(
        finding_id="F-1",
        target_file="config.py",
        rationale="Use os.getenv",
        unified_diff="--- a/config.py\n+++ b/config.py\n@@ -5,1 +5,1 @@\n-SECRET = '123'\n+SECRET = os.getenv('SECRET')",
        expected_security_effect="Safe",
        confidence=0.95,
    )
    assert run.to_summary_dict()["findings"][0]["status"] == "PROPOSED"

    # Add verification
    run.verifications["F-1"] = VerificationResult(
        build_passed=True,
        tests_passed=True,
        security_test_passed=True,
        static_rescan_clean=True,
        approved=True,
        reason=None,
    )
    summary = run.to_summary_dict()
    assert summary["counts"]["verified"] == 1
    assert summary["findings"][0]["status"] == "VERIFIED"
