from __future__ import annotations
"""Remote Verification Runner executed on ephemeral cloud sandboxes."""

import argparse
import json
from pathlib import Path
import sys

from crs.core.schemas import Severity, VulnerabilityFinding
from crs.verification.security_verifier import SecurityVerifier
from crs.verification.test_runner import TestRunner


def run_remote_verification(
    workspace_root: str,
    target_file: str,
    vulnerability_type: str,
    finding_id: str = "REMOTE-001",
) -> dict:
    """Run all 4 verification gates within the sandbox and return structured result."""
    root = Path(workspace_root).resolve()
    test_runner = TestRunner()
    security_verifier = SecurityVerifier()

    finding = VulnerabilityFinding(
        finding_id=finding_id,
        title=f"Potential {vulnerability_type}",
        vulnerability_type=vulnerability_type,
        severity=Severity.HIGH,
        confidence=0.9,
        file=target_file,
        line_start=1,
        evidence=[],
    )

    # Gate 1: Build & Syntax Check
    build_result = test_runner.syntax_check(root, target_file)

    # Gate 2: Functional Regression
    tests_result = test_runner.run_tests(root)

    # Gate 3: Exploit Regression
    security_result = security_verifier.run_regression(root, target_file, finding)

    # Gate 4: Static Rescan
    rescan_result = security_verifier.rescan(root, target_file, finding)

    approved = (
        build_result.passed
        and tests_result.passed
        and security_result.passed
        and rescan_result.passed
    )

    return {
        "build_passed": build_result.passed,
        "build_reason": build_result.reason,
        "tests_passed": tests_result.passed,
        "tests_reason": tests_result.reason,
        "security_passed": security_result.passed,
        "security_reason": security_result.reason,
        "rescan_passed": rescan_result.passed,
        "rescan_reason": rescan_result.reason,
        "approved": approved,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="VAYU Remote Sandbox Verification Runner")
    parser.add_argument("--workspace", required=True, help="Path to workspace root inside sandbox")
    parser.add_argument("--target-file", required=True, help="Relative path to patched file")
    parser.add_argument("--vulnerability-type", default="Command Injection", help="Original finding vulnerability type")
    parser.add_argument("--finding-id", default="REMOTE-001", help="Original finding ID")

    args = parser.parse_args()
    results = run_remote_verification(
        args.workspace,
        args.target_file,
        args.vulnerability_type,
        args.finding_id,
    )

    print(json.dumps(results, indent=2))
    sys.exit(0 if results["approved"] else 1)


if __name__ == "__main__":
    main()
