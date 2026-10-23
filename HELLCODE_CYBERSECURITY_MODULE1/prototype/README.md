# ⚡ VAYU — Autonomous Cyber Reasoning System (CRS)
## Prototype Implementation & Reproducible Setup Guide
**Team Name**: HELLCODE  
**Author**: Ayush Kumar  
**Innovation Theme**: Cybersecurity  
**Live Demo Video**: [https://youtu.be/crQhPqTmjKI](https://youtu.be/crQhPqTmjKI)  
**Project GitHub Repository**: [https://github.com/ayushkumar2601/vayu_hacktoberfest](https://github.com/ayushkumar2601/vayu_hacktoberfest)  

---

### 1. What the One Flow Does
> **The One Flow (`FIND -> REASON -> PATCH -> VERIFY -> SIGN`)**:  
> VAYU autonomously scans an untrusted repository with deterministic AST rules to detect an OS Command Injection (CWE-78), extracts quarantined context through a prompt firewall, prompts a guarded local LLM to emit a single-line patch intent, constructs an indentation-locked canonical diff, validates the patch inside a disposable sandbox across **4 Fail-Closed Verification Gates** (Syntax AST, `pytest` regressions, PoC exploit eradication, and static rescan), and cryptographically signs an **in-toto SLSA v1.0 attestation** with an **ECDSA (P-256)** digital signature.

---

### 2. Functional Status & Operational Boundaries (Honest Disclosure)
In accordance with the AI Builder Challenge guidelines, we clearly disclose what is fully production-functional versus what requires external configuration:

* **✅ Fully Functional Out-of-the-Box (No External Dependencies Needed)**:
  * Deterministic Semgrep AST vulnerability scanner ([crs/static_analysis/](crs/static_analysis/)).
  * Prompt firewall & delimited evidence packager ([crs/guardrails/](crs/guardrails/), [crs/reasoning/](crs/reasoning/)).
  * Indentation-locking engine & unified diff synthesizer ([crs/patching/](crs/patching/)).
  * Ephemeral local sandbox verification ([crs/verification/](crs/verification/)) with all 4 fail-closed gates.
  * Offline heuristic client ([crs/reasoning/offline_client.py](crs/reasoning/offline_client.py)) — runs with zero GPU, zero internet, and zero LLM API keys.
  * in-toto SLSA v1.0 attestation generator and ECDSA P-256 signer ([crs/reporting/](crs/reporting/)).
  * Complete 188-test automated regression suite (`pytest`).
  * FastMCP 9-tool server protocol over standard I/O ([vayu_mcp/](vayu_mcp/)).
  * Next.js 16 Web Dashboard with NDJSON streaming ([vayu-nextjs/](vayu-nextjs/)).

* **⚙️ Requires Optional Configuration / External Credentials**:
  * **DigitalOcean Cloud Sandboxing (`--sandbox digitalocean`)**: Requires a DigitalOcean API token (`export DIGITALOCEAN_TOKEN="dop_v1_..."`). If omitted, VAYU automatically falls back to local isolated `/tmp` sandboxes.
  * **Local Ollama LLM Reasoning (`--provider ollama`)**: Requires the Ollama daemon running locally (`ollama serve`). If Ollama is offline or not installed, VAYU automatically self-heals and activates the built-in offline rules engine without failing.

* **🔄 Actively Being Implemented in the Project**:
  * **Neo4j Code Property Graph (CPG) & Graph-RAG**: Connecting ASTs, CFGs, and PDGs to trace inter-procedural taint flow (`[:FLOWS_TO*]`), calculate patch blast radius, and inject causal subgraphs into reasoning.
  * **Multi-Language AST Rewriters**: Expanding single-line indentation locking across Go, Rust, and TypeScript (Phase 3 Roadmap).

---

### 3. Step-by-Step Setup Instructions

#### Prerequisites
* **Operating System**: macOS, Linux (Ubuntu 22.04+), or WSL2 on Windows.
* **Python**: Version `3.10`, `3.11`, or `3.12` installed.
* **Node.js** (Optional, only for Web Dashboard): Version `18.x` or `20.x`.

#### Step 1: Set Up Python Virtual Environment
Open your terminal in this `prototype/` directory:
```bash
python3 -m venv venv
source venv/bin/activate
```
*(On Windows: `venv\Scripts\activate`)*

#### Step 2: Install Core Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 3: Run the Verification Test Suite
Verify that all subsystems pass internal invariants:
```bash
pytest
```
*Expected output: `188 passed in ~23s`.*

---

### 4. Running the Canonical End-to-End One Flow

Run the autonomous Cyber Reasoning System on the included vulnerable sample repository (`samples/vulnerable/command_injection`):

```bash
python -m crs.vayu scan samples/vulnerable/command_injection --sandbox local
```

#### What happens during execution:
1. **Target Indexing**: VAYU indexes the target codebase and calculates its initial SHA-256 fingerprint.
2. **Deterministic Scan**: Semgrep AST rules locate the vulnerable `subprocess.run(..., shell=True)` call at line 23.
3. **Guarded Reasoning**: The Prompt Firewall isolates the snippet and prompts the engine (offline heuristic or local Ollama).
4. **Indentation-Locked Patching**: Synthesizes the minimal single-line fix:
   ```diff
   - subprocess.run(f"ping -c 1 {host}", shell=True, check=True)
   + subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
   ```
5. **4-Gate Verification**:
   * *Gate 1 (Syntax AST)*: Compiles with `py_compile` -> **PASSED**.
   * *Gate 2 (Functional Tests)*: Executes `pytest` -> **PASSED**.
   * *Gate 3 (PoC Exploit Eradication)*: Tests command injection exploit -> **PASSED**.
   * *Gate 4 (AST Rescan)*: Re-runs Semgrep AST rule -> **PASSED**.
6. **SLSA Provenance Generation**: Signs an in-toto SLSA v1.0 attestation with an ECDSA P-256 digital signature and writes `vayu-provenance.json`.
7. **Invariant Check**: Confirms the original `samples/vulnerable/command_injection` directory was untouched (SHA-256 identical).

---

### 5. (Optional) Launch the Next.js 16 Web Dashboard
To visualize real-time NDJSON streaming with 3D WebGL terrain and side-by-side diff review:

```bash
cd vayu-nextjs
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser, enter `samples/vulnerable/command_injection` in the scan input, and click **Launch CRS Loop**.

---

### 6. (Optional) Launch the Model Context Protocol (MCP) Server
To use VAYU as a tool server inside Claude Desktop, Cursor, or Windsurf:

```bash
python -m vayu_mcp.server
```
The server connects over standard I/O (`stdio`) exposing 9 security tools: `vayu_scan_repo`, `vayu_reason_finding`, `vayu_synthesize_patch`, `vayu_verify_patch`, and `vayu_export_sarif`.

---

### 7. Directory Structure
```
prototype/
├── crs/                     # Core Cyber Reasoning System Engine
│   ├── cicd/               # CI/CD runners and SARIF exporter
│   ├── core/               # Pydantic data schemas & invariants
│   ├── guardrails/         # Prompt firewall & delimited fencing
│   ├── ingestion/          # Repository loader & SHA-256 fingerprinting
│   ├── patching/           # Indentation lock & unified diff generator
│   ├── reasoning/          # Ollama client & offline heuristic engine
│   ├── reporting/          # SLSA v1.0 provenance & ECDSA digital signer
│   ├── static_analysis/    # Semgrep AST runner & taint graph analyzer
│   └── verification/       # 4-Gate Sandbox (local /tmp & DigitalOcean KVM)
├── vayu_mcp/                # Model Context Protocol (MCP) server & 9 tools
├── rules/                   # Deterministic Semgrep AST rule definitions
├── samples/                 # Reproducible vulnerable code test targets
├── tests/                   # 188-test automated pytest regression suite
├── vayu-nextjs/             # Next.js 16 Web Dashboard & NDJSON visualizer
├── pics/                    # Architectural diagrams & screenshots
├── pyproject.toml           # Python package metadata
├── requirements.txt         # Core dependencies
└── README.md                # This setup guide
```

---
*Created by Team HELLCODE for the AI Builder's Operating Kit Final Assessment.*
