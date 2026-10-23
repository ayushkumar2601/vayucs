---
name: patch-verification
description: Verify candidate patches using 4 fail-closed deterministic gates inside ephemeral sandboxes.
category: Verification & Testing
version: 1.0.0
author: VAYU Development Team
---

# Patch Verification

## Objective
Rigorously test candidate security patches within isolated, disposable sandboxes using 4 fail-closed deterministic verification gates.

## The 4 Verification Gates
A patch is classified as `VERIFIED` if and only if all four gates pass sequentially:

1. **Gate 1: Build / Syntax Compilation Check**
   - Execute `py_compile` (Python), `cargo check` (Rust), `go build` (Go), or `npm run build` (Node).
   - Reject any syntax, formatting, or indentation errors immediately.
2. **Gate 2: Functional Unit Test Suite**
   - Execute existing repository tests (e.g. `pytest tests/`).
   - Confirm that the remediation causes zero regression in existing application functionality.
3. **Gate 3: Security Property Invariant (AST Inspection)**
   - Parse the patched file's AST using Python's `ast` module.
   - Verify that dangerous constructs (e.g., `shell=True`, `pickle.loads`, `hashlib.md5`) are eliminated.
4. **Gate 4: Independent Static Analysis Rescan**
   - Re-run Semgrep over the temporary workspace.
   - Confirm that the target security rule ID is no longer triggered on the affected file.

## Sandbox Isolation Invariant
- Never test patches on the live repository.
- Clone the repository into a disposable `/tmp` sandbox (`EphemeralWorkspace`).
- Destroy the sandbox immediately after verification.
