# 🔐 Cryptographic Provenance (SLSA v1.0) & SARIF Export

Automated cyber reasoning demands cryptographic proof of code authenticity. Without verifiable provenance, an automated remediation agent could be compromised or impersonated to inject unauthorized code into production repositories.

VAYU incorporates **in-toto SLSA v1.0 Cryptographic Provenance** signed with **ECDSA (P-256)** digital signatures, combined with **OASIS SARIF v2.1.0** compliance for enterprise CI/CD integration.

---

## 1. In-Toto SLSA v1.0 Attestation Architecture

VAYU generates an **in-toto Statement v1** (`https://in-toto.io/Statement/v1`) using the **SLSA Provenance v1.0** predicate (`https://slsa.dev/provenance/v1`):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "repository-patch",
      "digest": {
        "sha256": "4a7f23c91a0b3e7d6f5c8e2b1a9c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://vayu.security/crs-remediation/v1",
      "externalParameters": {
        "repository_sha256": "8f3b17c9d0e1f2a3b4c5d6e7f8a9b0c4a7f23c91a0b3e7d6f5c8e2b1a9c3d4e5",
        "target_file": "samples/vulnerable/command_injection/app.py",
        "finding_id": "cwe-78-subprocess-shell-true"
      },
      "systemParameters": {
        "verification_policy": "4-gate-fail-closed",
        "final_decision": "VERIFIED",
        "sandbox_provider": "digitalocean",
        "gates_passed": [
          "syntax_ast_check",
          "functional_unit_tests",
          "security_invariant_ast",
          "semgrep_static_rescan"
        ]
      }
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/ayushkumar2601/vayu_hacktoberfest"
      },
      "metadata": {
        "invocationId": "crs-run-9f4a1c",
        "startedOn": "2026-10-14T12:00:00Z",
        "finishedOn": "2026-10-14T12:00:05Z"
      }
    }
  }
}
```

---

## 2. ECDSA (P-256) Digital Cryptographic Signing

The attestation statement is signed using elliptic curve digital signature algorithm (ECDSA) with the NIST P-256 (SECP256R1) curve:

$$\text{Canonical Payload} = \text{CanonicalJSON}(\text{Statement})$$
$$\text{Digest} = \text{SHA256}(\text{CanonicalPayload})$$
$$\text{Signature} = \text{ECDSA-Sign}_{K_{\text{private}}}(\text{Digest})$$

### In-Memory Keypair Generation & Verification
```python
from crs.reporting.slsa_provenance import (
    generate_keypair,
    build_slsa_attestation,
    sign_attestation,
    verify_provenance_signature,
)

# 1. Generate an ephemeral P-256 keypair
private_key_pem, public_key_pem = generate_keypair()

# 2. Build the in-toto statement
statement = build_slsa_attestation(run_result)

# 3. Digitally sign the statement
signed_payload = sign_attestation(statement, private_key_pem)

# 4. Verify cryptographic authenticity
is_authentic = verify_provenance_signature(
    statement=signed_payload["statement"],
    signature_base64=signed_payload["signature"],
    public_key_pem=public_key_pem,
)
assert is_authentic is True
```

The verifying public key and Base64-encoded signature are written alongside the attestation in `attestation.signed.json`, providing verifiable non-repudiation.

---

## 3. OASIS SARIF v2.1.0 Export

VAYU produces standard Static Analysis Results Interchange Format (SARIF v2.1.0) files natively ingested by:
- **GitHub Code Scanning & Security Tab**
- **GitLab Security Center**
- **SonarQube & DefectDojo**

### SARIF Generation
```python
from crs.cicd.ci_runner import export_sarif_report

sarif_report = export_sarif_report(
    findings=findings,
    patches=[patch],
    target_path=target.path,
    output_path="vayu-report.sarif",
)
```

### SARIF Structure Highlights
- **`tool.driver`**: Identifies VAYU CRS with engine version and rule taxonomies.
- **`rules`**: Maps finding IDs to CWE classifications and severity levels.
- **`results`**: Detailed finding locations with start/end lines and columns.
- **`fixes`**: Embeds the canonical unified diff replacement as an automated fix object.

---

## 4. GitHub Actions CI/CD Integration

VAYU includes a reusable GitHub Action (`action.yml`):

```yaml
name: VAYU Autonomous Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run VAYU Autonomous CRS
        uses: ayushkumar2601/vayu_hacktoberfest@main
        with:
          repository_path: '.'
          model: 'qwen2.5-coder:7b-instruct'

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vayu-report.sarif
```
