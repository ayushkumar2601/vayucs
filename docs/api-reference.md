# 📚 VAYU Python API & Data Contracts Reference

This document provides a comprehensive API reference for the internal Python classes, methods, and Pydantic data contracts in the `crs/` and `vayu_mcp/` packages.

---

## 1. Domain Schemas (`crs.core.schemas`)

### `Severity(str, Enum)`
Enumeration of finding severity levels:
- `Severity.INFO`
- `Severity.LOW`
- `Severity.MEDIUM`
- `Severity.HIGH`
- `Severity.CRITICAL`

### `Evidence(BaseModel)`
Traceable scanner observation supporting a finding.
- `source: str` — Identifier of scanner (e.g., `"semgrep"`).
- `description: str` — Human-readable observation description.
- `file: str | None` — Affected file path.
- `line: int | None` — Line number in source code.
- `raw_reference: str | None` — Scanner rule ID or raw match snippet.

### `VulnerabilityFinding(BaseModel)`
Normalized security finding shared across all pipeline stages.
- `finding_id: str` — Unique finding identifier (e.g., `"find-a9b1c2"`).
- `title: str` — Summary title.
- `vulnerability_type: str` — CWE name (e.g., `"Command Injection"`).
- `severity: Severity` — Standardized severity level.
- `confidence: float` — Detection confidence (0.0 to 1.0).
- `file: str | None` — Target source file relative path.
- `line_start: int | None` — Starting line index (1-indexed).
- `line_end: int | None` — Ending line index (1-indexed).
- `evidence: list[Evidence]` — List of supporting scanner observations.
- `exploit_reproduced: bool` — Whether dynamic exploit was verified.
- `root_cause: str | None` — Model-generated root cause analysis.
- `proposed_fix: str | None` — Summary fix suggestion.

### `CodeContext(BaseModel)`
Bounded source code excerpt treated as untrusted data.
- `file: str` — File path.
- `start_line: int` — Context window start line ($\ge 1$).
- `end_line: int` — Context window end line ($\ge 1$).
- `content: str` — Bounded source text.
- `trust_level: str` — `"UNTRUSTED_REPOSITORY_CONTENT"`.

### `ReasoningResult(BaseModel)`
Schema-validated vulnerability analysis produced by a reasoning engine.
- `finding_id: str` — Associated finding ID.
- `vulnerability_class: str` — CWE classification.
- `root_cause: str` — Identified architectural root cause.
- `security_impact: str` — Exploitability and blast radius analysis.
- `remediation_strategy: str` — Safe remediation approach.
- `assumptions: list[str]` — Model assumptions about dependencies and runtime.
- `evidence_references: list[str]` — References to code lines or rules.
- `confidence: float` — Confidence rating (0.0 to 1.0).

### `PatchEdit(BaseModel)`
Minimal single-line model edit proposal intent before trusted synthesis.
- `replacement_line: str` — The single replacement string without indentation.

### `PatchProposal(BaseModel)`
Synthesized unified diff and expected security effect.
- `finding_id: str` — Associated finding ID.
- `target_file: str` — Target source file to patch.
- `rationale: str` — Rationale explaining why the change is secure.
- `unified_diff: str` — Canonical unified diff text.
- `expected_security_effect: str` — Expected behavior of the fix.
- `confidence: float` — Confidence score (0.0 to 1.0).

### `VerificationResult(BaseModel)`
Deterministic verification outcome from the 4-gate sandbox.
- `build_passed: bool` — Gate 1: Build / compilation AST status.
- `tests_passed: bool` — Gate 2: Functional test suite status.
- `security_test_passed: bool` — Gate 3: Security invariant AST status.
- `static_rescan_clean: bool` — Gate 4: Semgrep static rescan status.
- `approved: bool` — True if and only if all 4 gates passed.
- `reason: str | None` — Explanation if any gate failed.
- `sandbox_provider: str` — `"local"` or `"digitalocean"`.
- `sandbox_metadata: dict[str, Any] | None` — Cloud metadata (droplet ID, IP, region).

---

## 2. Ingestion & Static Analysis

### `RepositoryLoader` (`crs.ingestion.repository_loader`)
```python
class RepositoryLoader:
    def load(self, target_dir: str | Path) -> AnalysisTarget:
        """Traverse directory, prune build artifacts, and calculate composite SHA-256."""
```

### `StaticScanner` (`crs.static_analysis.scanner`)
```python
class StaticScanner:
    def scan(self, target_path: str | Path) -> list[VulnerabilityFinding]:
        """Execute Semgrep with isolated subprocess and return normalized findings."""
```

---

## 3. Reasoning & Patching Engines

### `ReasoningEngine` (`crs.reasoning.reasoning_engine`)
```python
class ReasoningEngine:
    def __init__(self, client: LLMClient, evidence_builder: EvidenceBuilder | None = None): ...
    
    def reason_from_evidence(self, evidence: EvidencePackage) -> ReasoningResult:
        """Analyze evidence package and return schema-validated reasoning."""
```

### `PatchGenerator` (`crs.patching.patch_generator`)
```python
class PatchGenerator:
    def __init__(self, client: LLMClient, validator: PatchValidator | None = None): ...
    
    def generate(
        self,
        finding: VulnerabilityFinding,
        reasoning: ReasoningResult,
        code_context: CodeContext,
    ) -> PatchProposal:
        """Lock indentation and synthesize canonical unified diff."""
```

### `PatchValidator` (`crs.patching.patch_validator`)
```python
class PatchValidator:
    def validate(
        self,
        patch: PatchProposal,
        finding: VulnerabilityFinding,
        repository_root: str | None = None,
        intended_file: str | None = None,
    ) -> PatchValidationResult:
        """Enforce single-file boundary, no file deletion, and valid hunk lines."""
```

---

## 4. Verification Engine & Cloud Sandboxing

### `VerificationEngine` (`crs.verification.verification_engine`)
```python
class VerificationEngine:
    def __init__(
        self,
        patch_validator: PatchValidator | None = None,
        sandbox_provider: str = "local",
    ): ...
    
    def verify(
        self,
        target_path: str | Path,
        finding: VulnerabilityFinding,
        patch: PatchProposal,
    ) -> VerificationResult:
        """Execute 4 fail-closed gates in local /tmp sandbox or DigitalOcean KVM droplet."""
```

### `DigitalOceanClient` (`crs.verification.cloud.do_client`)
```python
class DigitalOceanClient:
    def __init__(self, config: DigitalOceanConfig | None = None): ...
    def create_droplet(self, name: str, size: str, region: str, image: str, ssh_keys: list, user_data: str) -> dict: ...
    def get_droplet(self, droplet_id: int) -> dict: ...
    def delete_droplet(self, droplet_id: int) -> dict: ...
    def create_ssh_key(self, name: str, public_key: str) -> dict: ...
    def delete_ssh_key(self, key_id: int) -> dict: ...
```

---

## 5. Provenance & Cryptography

### `slsa_provenance` (`crs.reporting.slsa_provenance`)
```python
def generate_keypair() -> tuple[str, str]:
    """Generate ephemeral NIST P-256 (SECP256R1) ECDSA keypair in PEM format."""

def build_slsa_attestation(run_result: CRSRunResult) -> dict[str, Any]:
    """Build in-toto Statement v1 with SLSA Provenance v1.0 predicate."""

def sign_attestation(statement: dict[str, Any], private_key_pem: str) -> dict[str, Any]:
    """Sign canonical JSON statement with ECDSA (P-256) and return Base64 signature."""

def verify_provenance_signature(statement: dict, signature_base64: str, public_key_pem: str) -> bool:
    """Verify cryptographic authenticity of attestation signature."""
```
