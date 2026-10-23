---
name: sast-workflow
description: Work with Semgrep static analysis findings, AST rules, evidence extraction, and finding normalization.
category: Static Analysis
version: 1.0.0
author: VAYU Development Team
---

# SAST Workflow & AST Analysis

## Objective
Author, execute, and normalize static application security testing (SAST) rules using Semgrep's Abstract Syntax Tree (AST) pattern matching engine.

## Key Concepts
1. **Headless Execution**:
   - Run Semgrep in machine-readable JSON mode with safe subprocess bounds:
     `semgrep --config rules/semgrep/demo_rules.yml --json <target_dir>`
   - Enforce timeouts (default: 60s) to prevent infinite recursion on hostile codebases.
2. **Rule Design Best Practices**:
   - Prefer AST patterns (`pattern-either`, `pattern-inside`) over naive regexes.
   - Anchor function call signatures to avoid false positives (e.g., `subprocess.run($CMD, ..., shell=True, ...)`).
3. **Finding Normalization**:
   - Map raw scanner matches into strongly-typed `VulnerabilityFinding` models.
   - Extract source line intervals (`line_start`, `line_end`).
   - Populate traceable `Evidence` objects capturing rule IDs and source descriptions.
4. **Rescan Cleanliness**:
   - A remediation is only complete if re-scanning the patched code confirms the target rule ID no longer matches.
