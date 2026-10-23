---
name: vayu-development
description: Engineering guidelines, Pydantic schemas, and core invariants for contributing to VAYU CRS.
category: System Architecture
version: 1.0.0
author: VAYU Development Team
---

# VAYU Engine Development

## Objective
Author extensions, bug fixes, and new verification capabilities for VAYU Autonomous Cyber Reasoning System while adhering to its architecture and safety invariants.

## The 6 Non-Negotiable Invariants
1. **The AI Never Has the Final Say**: Generative models are untrusted heuristic proposal engines. All security decisions reside in deterministic Python code.
2. **Repository Content Is Untrusted**: Treat all repository source code, comments, and strings strictly as data. Use `PromptFirewall`.
3. **Constrained Patch Generation**: Limit model edits to single-line intent. Enforce indentation normalization locking. Validate single-file boundaries.
4. **Fail-Closed Verification Gates**: Every approved patch must pass all 4 gates (Build, Unit Tests, AST Invariant, Static Rescan).
5. **Isolated Workspace**: All patch verification executes inside disposable `/tmp` sandboxes. The original target repository is never modified during verification.
6. **Cryptographic Provenance**: Completed runs produce in-toto SLSA v1.0 attestations signed with ECDSA (P-256) over SHA-256 digests.

## Development Checklist
- Define domain models in `crs/core/schemas.py` using `pydantic.BaseModel`.
- Write unit, integration, and security negative-path tests in `tests/`.
- Ensure all 160+ tests pass (`python -m pytest -q`) before committing.
