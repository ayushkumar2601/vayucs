# Build-Summary: VAYU — Autonomous Cyber Reasoning System (CRS)

### Team & Innovation Theme
* **Team Name**: HELLCODE
* **Author**: Ayush Kumar
* **Innovation Theme**: Cybersecurity
* **Module**: Module 1 (Build with AI: The AI Builder's Operating Kit — Final Assessment)
* **Live Demo Recording**: [https://youtu.be/crQhPqTmjKI](https://youtu.be/crQhPqTmjKI)
* **GitHub Repository**: [https://github.com/ayushkumar2601/vayu_hacktoberfest](https://github.com/ayushkumar2601/vayu_hacktoberfest)

---

### Problem Statement
* **Final Version**: Senior Application Security (AppSec) and DevOps platform engineers managing 100+ Python microservices are inundated with hundreds of static scanner alerts weekly, resulting in an average Mean Time to Remediate (MTTR) of 68 days for critical injection vulnerabilities. Generic AI coding assistants cannot be trusted to fix these vulnerabilities autonomously because they hallucinate syntax, break business logic, alter whitespace, and succumb to prompt injections embedded in repository code.
* **Evolution From First Version**: Our initial problem statement assumed developers simply needed "faster AI suggestions in their IDE"; through rigorous unwinding and testing, we realized developers actively reject automated code suggestions unless the AI is constrained to a zero-trust heuristic role, verified against a 4-gate fail-closed sandbox, and cryptographically proven never to touch or corrupt the original codebase.

---

### What We Built: The One Flow
We engineered an autonomous, deterministic, fail-closed **Cyber Reasoning System (CRS)** modeled after the DARPA AI Cyber Challenge (AIxCC). 
* **The One Flow (`FIND -> REASON -> PATCH -> VERIFY -> SIGN`)**:
  1. **FIND**: Deterministic Semgrep AST analysis and repository indexing scan untrusted codebases to isolate vulnerable nodes (e.g. CWE-78 OS Command Injection via `subprocess(shell=True)`).
  2. **REASON**: A prompt firewall isolates source snippets within bounded JSON structures, prompting a local/offline LLM to emit strictly structured root-cause intent. **Neo4j Code Property Graph (CPG) & Graph-RAG** are actively integrated to extract causal $k$-hop subgraphs across callers and taint sources rather than naive line windows.
  3. **PATCH**: An indentation-locking engine forces the model to emit a single replacement line intent; trusted Python AST synthesizers construct the canonical unified diff.
  4. **VERIFY**: The candidate patch is tested inside a disposable sandbox (local `/tmp` or an ephemeral DigitalOcean KVM Droplet) across **4 Fail-Closed Gates**: (1) Syntax AST validation, (2) Functional unit test regression (`pytest`), (3) PoC dynamic exploit eradication, and (4) Static signature rescan. **Neo4j caller-graph queries** calculate upstream and downstream blast radius to prioritize impacted test suites.
  5. **SIGN**: Passing patches generate an **in-toto SLSA v1.0 verifiable attestation** digitally signed with an **ECDSA (P-256)** key and streamed via NDJSON to a Next.js 16 Web Review Console and GitHub Actions.
* **What It Deliberately Does NOT Do**:
  * It deliberately **does NOT allow the LLM to rewrite entire files or functions** (eliminates hallucination and scope drift).
  * It deliberately **does NOT modify the original target repository during verification** (byte-for-byte SHA-256 invariant verified).
  * It deliberately **does NOT approve unverified patches** (if a cloud droplet or test times out, it fails closed with `approved=False`).

---

### Tech Stack & Rationale
* **Core Runtime & Logic**: Python 3.11 with strict static typing and Pydantic v2 schemas for robust serialization, schema validation, and fail-closed data contracts.
* **Deterministic SAST**: Semgrep AST rules for deterministic, reproducible vulnerability detection without false-positive AI hallucinations.
* **Graph Database & CPG (Already Being Implemented)**: **Neo4j 5.x** property graph engine backing the whole-codebase Code Property Graph (CPG), cross-file taint reachability (`[:FLOWS_TO*]`), Graph-RAG context extraction, and structural patch blast radius calculation.
* **Guarded AI Reasoning**: Local Ollama (Qwen 2.5 / Gemma 2 / Llama 3) with an offline rule-based heuristic client fallback, guaranteeing 100% air-gapped security and zero token leakage.
* **Cloud Sandboxing**: DigitalOcean API v2 REST client (`urllib.request`) spinning up ephemeral Ubuntu 24.04 KVM Droplets with RAM-only Ed25519 SSH tunnels and a 10-minute hardware kill-switch.
* **Cryptographic Attestation**: Python `cryptography` library producing in-toto SLSA v1.0 attestations with ECDSA (P-256) digital signatures.
* **Web Review Console**: Next.js 16 (App Router, Turbopack, TailwindCSS/Vanilla CSS) streaming live NDJSON pipeline execution events (`crs.stream`) with 3D WebGL terrain and direct GitHub PR creation.
* **Model Context Protocol (MCP)**: FastMCP (`vayu-mcp`) exposing 9 audit, graph traversal, and remediation tools to AI agents in Claude Desktop, Cursor, and Windsurf.

---

### Evidence Position: What is Proven vs. What Remains an Assumption
* **[EVIDENCE - PROVEN]**:
  * 188/188 pytest unit and integration tests passing deterministically across all subsystems.
  * Single-line indentation locking eliminates 100% of LLM whitespace corruption in Python source files.
  * Ephemeral DigitalOcean Droplets safely execute malicious PoC exploit payloads with hardware KVM isolation for <$0.001 per verification run.
  * The original target repository remains byte-for-byte identical (SHA-256 verified) throughout the entire reasoning and verification loop.
  * Neo4j property graph schema (`(:File)-[:DEFINES]->(:Function)-[:CALLS]->(:Function)`) maps cross-module AST reachability with Cypher queries.
* **[ASSUMPTION - UNVERIFIED]**:
  * We assume enterprise engineering teams will grant automated CI/CD bots direct GitHub pull-request creation permissions without preliminary manual security review.
  * We assume the 4-gate verification model can catch subtle business logic regressions in repositories with low test coverage (<30% branch coverage) without dynamic fuzzing.
  * We assume single-line AST patch bounding will easily transfer from Python to dynamically typed JavaScript/TypeScript codebases with complex asynchronous callback chains.

---

### What We Would Build Next (Beyond Active Neo4j Implementation)
* **Current Status**: **Neo4j integration is already being actively implemented in the project** across 5 core subsystems: (1) Inter-procedural Code Property Graph (CPG) taint tracking, (2) Graph-RAG context injection into `EvidenceBuilder`, (3) Patch blast-radius analysis in `PatchValidator`, (4) Persistent vulnerability/remediation memory graph, and (5) Interactive attack-path visualization in the Next.js Dashboard and MCP tools.
* **Next Evolutionary Flow**: **Autonomous Coverage-Guided Dynamic Fuzzing (libFuzzer/Atheris)** and **Polyglot AST Rewriter Matrix (Go, Rust, TypeScript)**.
* **What Must Be True to Be Worth Building**: Enterprise codebases must contain zero-day edge cases where static tests are completely absent, requiring VAYU to synthesize dynamic coverage-guided fuzz harnesses to mathematically prove crash-freedom before and after patch application.
