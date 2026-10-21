# 🌐 Next.js 16 Real-Time Web Dashboard & Review Console

VAYU features a modern, real-time web telemetry console built on **Next.js 16**, **React 19**, **TailwindCSS**, and **Three.js**.

---

## 1. Web Architecture Overview

```
┌────────────────────────────────────────────────────────┐
│ Next.js 16 Frontend (App Router, Turbopack, React 19)  │
│ - Live Telemetry Dashboard (/dashboard)                │
│ - Interactive 3D WebGL Code Terrain (Terrain.tsx)      │
│ - Dynamic SVG Architecture Flow (System.tsx)           │
│ - Patch Review & GitHub PR Console (/review)           │
└───────────────────────────┬────────────────────────────┘
                            │ HTTP Streaming Fetch / SSE
                            ▼
┌────────────────────────────────────────────────────────┐
│ Next.js API Streaming Bridge (app/api/run/route.ts)    │
│ - Spawns subprocess: python -m crs.stream <target>     │
│ - Pipes stdout chunks to browser ReadableStream        │
└───────────────────────────┬────────────────────────────┘
                            │ Newline-Delimited JSON (NDJSON)
                            ▼
┌────────────────────────────────────────────────────────┐
│ VAYU NDJSON Stream Engine (crs/stream.py)              │
│ - Dispatches Find-Reason-Patch-Verify pipeline         │
│ - Emits flushed JSON events line-by-line               │
└────────────────────────────────────────────────────────┘
```

---

## 2. Real-Time Visualizations

### 2.1 3D Codebase Terrain Visualizer (`Terrain.tsx`)
Rendered using Three.js and WebGL canvas:
- **Topology**: Code files and directories form a three-dimensional coordinate landscape.
- **Elevation (Y-Axis)**: Calculated from the character length and indentation depth of each source code line.
- **Thermal Heat Mapping**: Vulnerable AST lines pulse in vibrant crimson (`#ef4444`). Once the 4 verification gates approve the patch, the shader transitions the line into cool emerald green (`#10b981`), visually signaling risk eradication.

### 2.2 Dynamic SVG System Flow (`System.tsx`)
Interactive architectural diagram depicting the telemetry request path from ingress through authentication, daemon dispatch, and database execution:
- **Active Risk Path**: When a vulnerability is active, red energy pulses travel along the affected network route.
- **Remediated State**: Upon verification, the route locks into place and displays a cryptographic verification badge.

---

## 3. Web Review Console & Direct GitHub Push

The **Web Review Console** (`app/review/page.tsx`) provides an intuitive environment for human-in-the-loop review:

1. **Side-by-Side Unified Diff**: Interactive diff viewer showing exact additions and deletions.
2. **Deterministic Gate Proof**: Complete compiler, pytest, and Semgrep logs for every verification gate.
3. **Cryptographic Attestation**: Visual inspector for the in-toto SLSA statement, hash digests, and ECDSA signature.
4. **Direct GitHub Push (`app/api/push-github/route.ts`)**:
   - Operator clicks **"Push Verified Patch to GitHub"**.
   - The route connects to the GitHub REST API using the configured `GITHUB_TOKEN`.
   - Creates a dedicated remediation branch (e.g., `vayu/remediation-cwe78-9f4a1c`).
   - Commits the canonical unified diff.
   - Automatically opens a Pull Request with the SLSA v1.0 attestation and test proofs embedded in the PR body.

---

## 4. Setup & Running Locally

### Prerequisites
- Node.js 18.0+
- Python virtual environment with VAYU installed

### Installation & Launch

```bash
# 1. Navigate to the web application directory
cd vayu-nextjs

# 2. Install Node dependencies
npm install

# 3. Create .env.local configuration
cat << EOF > .env.local
AIKAVACH_LLM_PROVIDER=ollama
AIKAVACH_OLLAMA_URL=http://localhost:11434
AIKAVACH_OLLAMA_MODEL=llama3
GITHUB_TOKEN=ghp_your_personal_access_token
GITHUB_REPO=ayushkumar2601/vayu_hacktoberfest
EOF

# 4. Start the Turbopack development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser to access the live dashboard.
