# 📚 VAYU Documentation Hub

Welcome to the comprehensive documentation suite for **VAYU — Autonomous Cyber Reasoning System (CRS)**.

VAYU is an autonomous cyber reasoning system inspired by DARPA's AI Cyber Challenge (AIxCC), designed to detect, reason about, synthesize minimal patches for, and deterministically verify security vulnerabilities with zero human intervention.

---

## 🗺️ Documentation Directory

| Document | Description | Target Audience |
|---|---|---|
| **[Master Technical Documentation](../TECHNICAL_DOCUMENTATION.md)** | Unified, monolithic technical manual covering the complete system architecture, mathematical invariants, data contracts, and threat models. | Architects, Security Researchers, Core Contributors |
| **[Architecture & Design Specification](../ARCHITECTURE.md)** | Deep architectural analysis, the 7-layer subsystem breakdown, and DARPA AIxCC design philosophy. | Systems Engineers & Architects |
| **[Formal Security Invariants](../DESIGN.md)** | Formal safety invariants, mathematical models, and zero-trust LLM boundary definitions. | Security Engineers & Cryptographers |
| **[Verification & Cloud Sandboxing](cloud-and-local-sandboxing.md)** | Dual-mode verification: Local ephemeral `/tmp` sandboxes vs **DigitalOcean Cloud KVM Droplets** with RAM-only Ed25519 tunnels and 10m TTL kill switch. | DevOps, Cloud Engineers, SREs |
| **[CLI & Operational Reference](cli-reference.md)** | Complete CLI reference for `vayu`, `vayu scan`, `vayu skills`, and `vayu-mcp`, flags, arguments, and exit codes. | Operators & Developers |
| **[Model Context Protocol (MCP) Server](mcp-server.md)** | Architectural guide and complete reference for the 9 core MCP tools running over JSON-RPC `stdio`. | AI Assistant Integrators |
| **[MCP Client Configuration Guide](mcp-clients.md)** | Step-by-step configuration for Claude Desktop, Cursor, Windsurf, Claude Code, and Goose. | Developers using AI IDEs |
| **[MCP Security Architecture](mcp-security.md)** | Security boundary enforcement, session isolation, and filesystem traversal defenses for MCP. | AppSec & Security Auditors |
| **[VAYU Skills Ecosystem](skills-ecosystem.md)** | Agent Skills architecture (`.agents/skills/`), catalog of 8 bundled skills, and `vayu skills` CLI workflows. | Agent Tooling Developers |
| **[Real-Time Streaming & Web Review Console](web-review-console.md)** | Next.js 16 Web Dashboard, NDJSON streaming wire protocol (`crs.stream`), 3D WebGL terrain, and direct GitHub commit/PR push. | Frontend & Fullstack Engineers |
| **[SLSA Provenance & SARIF Export](slsa-and-sarif.md)** | in-toto SLSA v1.0 attestations, ECDSA (P-256) cryptographic signatures, and OASIS SARIF v2.1.0 reporting. | Supply Chain & Compliance Teams |
| **[Python API Reference](api-reference.md)** | Comprehensive module-by-module Python API documentation and Pydantic data contracts. | Software Developers & SDK Users |
| **[Hackathon Presentation & Demo Guide](../DEMO_GUIDE.md)** | 6-act live demonstration script, terminal matrix, and judge Q&A defense playbook. | Presenters & Hackathon Teams |

---

## ⚡ Quick Navigation

### 1. Running VAYU Locally
```bash
source venv/bin/activate
source .env.local
python -m crs.vayu samples/vulnerable/command_injection
```

### 2. Running with DigitalOcean Hardware Hypervisor Sandbox
```bash
python -m crs.vayu scan samples/vulnerable/command_injection --sandbox digitalocean
```

### 3. Launching the Model Context Protocol (MCP) Server
```bash
python -m vayu_mcp.server
```

### 4. Installing Reusable AI Skills
```bash
vayu skills add security-analysis
vayu skills list
```

### 5. Launching the Web Review Console
```bash
cd vayu-nextjs
npm run dev
# Open http://localhost:3000 in your browser
```
