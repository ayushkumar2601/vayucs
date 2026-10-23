from __future__ import annotations
"""In-memory session and run state manager for VAYU MCP tool invocations."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
import time
from typing import Any
import uuid

from crs.core.schemas import (
    AnalysisTarget,
    PatchProposal,
    ReasoningResult,
    VerificationResult,
    VulnerabilityFinding,
)


@dataclass
class RunState:
    """Authoritative state for a single repository scan and remediation run."""

    run_id: str
    target: AnalysisTarget
    created_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    findings_by_id: dict[str, VulnerabilityFinding] = field(default_factory=dict)
    reasonings: dict[str, ReasoningResult] = field(default_factory=dict)
    patches: dict[str, PatchProposal] = field(default_factory=dict)
    verifications: dict[str, VerificationResult] = field(default_factory=dict)
    stage: str = "FIND"
    errors: list[str] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)

    def get_finding(self, finding_id: str) -> VulnerabilityFinding | None:
        return self.findings_by_id.get(finding_id)

    def to_summary_dict(self) -> dict[str, Any]:
        """Produce a clean JSON-serializable overview of the run's progress."""
        verified_count = sum(1 for v in self.verifications.values() if v.approved)
        rejected_count = sum(1 for v in self.verifications.values() if not v.approved)

        findings_summary = []
        for f in self.findings:
            fid = f.finding_id
            status = "DISCOVERED"
            if fid in self.verifications:
                status = "VERIFIED" if self.verifications[fid].approved else "REJECTED"
            elif fid in self.patches:
                status = "PROPOSED"
            elif fid in self.reasonings:
                status = "ANALYZED"

            findings_summary.append({
                "finding_id": fid,
                "vulnerability_type": f.vulnerability_type,
                "severity": getattr(f.severity, "value", str(f.severity)),
                "location": f"{f.file}:{f.line_start}",
                "status": status,
            })

        return {
            "run_id": self.run_id,
            "created_at_utc": self.created_at_utc,
            "stage": self.stage,
            "target": {
                "name": self.target.name,
                "path": self.target.path,
                "file_count": self.target.file_count,
                "languages": self.target.languages,
                "repository_sha256": self.target.repository_hash,
            },
            "counts": {
                "total_findings": len(self.findings),
                "analyzed": len(self.reasonings),
                "patches_proposed": len(self.patches),
                "verified": verified_count,
                "rejected": rejected_count,
            },
            "findings": findings_summary,
            "errors": self.errors,
        }


class SessionManager:
    """Thread-safe manager associating run identifiers with active CRS session states."""

    def __init__(self) -> None:
        self._runs: dict[str, RunState] = {}
        self._lock = threading.Lock()

    def create_run(
        self,
        target: AnalysisTarget,
        findings: list[VulnerabilityFinding],
        run_id: str | None = None,
    ) -> RunState:
        """Initialize and register a new run state."""
        with self._lock:
            rid = run_id or f"vayu-run-{uuid.uuid4().hex[:12]}"
            findings_map = {f.finding_id: f for f in findings}
            state = RunState(
                run_id=rid,
                target=target,
                findings=findings,
                findings_by_id=findings_map,
                stage="FIND",
            )
            self._runs[rid] = state
            return state

    def get_run(self, run_id: str) -> RunState | None:
        """Retrieve a run state by run identifier, or None if not found."""
        with self._lock:
            return self._runs.get(run_id)

    def require_run(self, run_id: str) -> RunState:
        """Retrieve a run state or raise ValueError if the identifier is unknown."""
        run = self.get_run(run_id)
        if run is None:
            raise ValueError(f"Run ID not found: '{run_id}'. Run 'vayu_scan_repository' first.")
        return run

    def list_runs(self) -> list[str]:
        """List all active run IDs."""
        with self._lock:
            return list(self._runs.keys())

    def clear(self) -> None:
        """Reset all session states (primarily for testing)."""
        with self._lock:
            self._runs.clear()


# Global default session manager singleton for the MCP server process
session_manager = SessionManager()
