# 💻 VAYU CLI & Operational Command Reference

VAYU provides a unified command-line interface with rich visual rendering, structured error diagnostics, and deep toolchain integrations.

---

## 1. Main CRS CLI (`vayu` / `python -m crs.vayu`)

The primary command runs the autonomous Find-Reason-Patch-Verify pipeline.

### Command Syntax

```bash
python -m crs.vayu [OPTIONS] [COMMAND] [TARGET_PATH]
# Or, if installed via pip:
vayu [OPTIONS] [COMMAND] [TARGET_PATH]
```

### Automatic Subcommand Resolution
VAYU implements `VayuDefaultGroup`: if you pass a target directory path directly without specifying a subcommand, VAYU automatically routes execution to the `scan` command for seamless developer ergonomics:

```bash
# These two commands are strictly identical:
python -m crs.vayu samples/vulnerable/command_injection
python -m crs.vayu scan samples/vulnerable/command_injection
```

---

## 2. `vayu scan` Command

Runs the autonomous cyber reasoning loop against a target repository.

### Syntax
```bash
python -m crs.vayu scan <TARGET_PATH> [OPTIONS]
```

### Arguments
- `TARGET_PATH` (Required, string): Relative or absolute path to the codebase to analyze. Must exist on the filesystem.

### Options
| Option | Type | Default | Description |
|---|---|---|---|
| `--sandbox` | `Choice(['local', 'digitalocean'])` | `local` | Execution sandbox provider used during Stage 4 Verification. `local` allocates an ephemeral `/tmp` directory. `digitalocean` provisions a disposable hardware KVM Droplet. |
| `--help` | Flag | N/A | Show help message and exit. |

### Examples

```bash
# 1. Scan and remediate using local ephemeral workspace isolation
python -m crs.vayu samples/vulnerable/command_injection

# 2. Explicitly select local sandbox
python -m crs.vayu scan samples/vulnerable/command_injection --sandbox local

# 3. Execute 4-gate verification inside an ephemeral DigitalOcean Cloud Droplet
python -m crs.vayu scan samples/vulnerable/command_injection --sandbox digitalocean
```

### Terminal Output Stages
When executed, VAYU renders five distinct terminal UI phases:
1. **ASCII Art Banner & Environment Check**: Displays active model (`gemma 4`, `qwen`, or `llama3`) and chosen sandbox provider.
2. **Repository Inventory Table**: Tabular listing of all detected vulnerabilities, severity levels, file locations, and line numbers.
3. **Remediation Cycles**:
   - `1. Vulnerability Detected`: Code context snippet with syntax highlighting and vulnerable line pointer.
   - `2. AI Reasoning`: Panel detailing Root Cause, Security Impact, and Remediation Strategy.
   - `3. Patch Generation`: Target file indicator, structural validation status, and syntax-highlighted unified diff.
   - `4. Formal Verification`: 4-gate status checklist (Build Integration, Functional Tests, Security Regression, Static Rescan) and final `VERIFIED` or `REJECTED` decision.
4. **Final Summary Panel**: Consolidated table reporting the final status for each vulnerability in the repository.

### Exit Status Codes
| Exit Code | Meaning | Condition |
|---|---|---|
| `0` | Success | All vulnerabilities remediated and verified, OR no vulnerabilities detected in the repository. |
| `1` | Failure | Unhandled configuration error, missing `.env.local`, Ollama endpoint unreachable, or invalid repository path. |

---

## 3. `vayu skills` Command Group

The Skills CLI manages reusable AI agent skills compatible with the open Agent Skills format.

### Command Overview
```bash
vayu skills [COMMAND] [OPTIONS]
```

| Subcommand | Description |
|---|---|
| `list` | List all bundled catalog skills and installed project/global skills. |
| `search <query>` | Search skills in the catalog by keyword, tag, or description. |
| `add <skill>` | Install a skill into the local project (`.agents/skills/`) or globally. |
| `remove <skill>` | Remove an installed skill. |
| `info <skill>` | Display detailed metadata, version, tags, and instructions preview. |
| `doctor` | Run diagnostic checks on skills directories and environment health. |

### Detailed Subcommand Reference

#### `vayu skills list`
Lists all available skills in the bundled catalog, their version, description, and installation status.

```bash
vayu skills list
```

#### `vayu skills search <query>`
Searches the skills catalog for matching terms in the name, description, or tags.

```bash
vayu skills search security
vayu skills search injection
```

#### `vayu skills add <skill>`
Installs a skill. By default, installs into the project-level directory (`.agents/skills/<skill-name>/`).

```bash
# Install bundled skill to current project (.agents/skills/security-analysis)
vayu skills add security-analysis

# Install bundled skill globally for user-level AI assistants (~/.gemini/skills/)
vayu skills add security-analysis --global

# Install skill directly from an external remote Git repository
vayu skills add frontend-design --from https://github.com/anthropics/skills
```

#### `vayu skills remove <skill>`
Removes an installed skill.

```bash
# Remove from project
vayu skills remove security-analysis

# Remove from global directory
vayu skills remove security-analysis --global
```

#### `vayu skills info <skill>`
Inspects the YAML frontmatter, authors, license, version, tags, and displays the first 25 lines of the instruction file (`SKILL.md`).

```bash
vayu skills info security-analysis
```

#### `vayu skills doctor`
Performs health diagnostics:
- Verifies existence and write permissions of project `.agents/skills/` directory.
- Verifies existence and write permissions of global skills directory.
- Audits installed skills for valid `SKILL.md` files and well-formed YAML frontmatter.

```bash
vayu skills doctor
```

---

## 4. `vayu-mcp` CLI (Model Context Protocol Server)

Launches the VAYU FastMCP server over standard I/O for integration with Claude Desktop, Cursor, and Windsurf.

### Syntax
```bash
python -m vayu_mcp.server [OPTIONS]
# Or, if installed via pip:
vayu-mcp [OPTIONS]
```

### Options
| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | Path | None | Path to custom `mcp_config.json` configuration file. |
| `--help` | Flag | N/A | Show help message and exit. |

### Operational Details
- **Transport**: Standard I/O (`stdio`) using JSON-RPC 2.0.
- **Stdout Preservation**: All non-protocol text is strictly banned from `sys.stdout`.
- **Diagnostic Logging**: Server logs, startup banners, and errors are written exclusively to `sys.stderr`.

---

## 5. `crs.stream` CLI (NDJSON Telemetry Bridge)

The streaming CLI runs the CRS pipeline and emits progress as newline-delimited JSON (NDJSON) objects.

### Syntax
```bash
python -m crs.stream <TARGET_PATH> [OPTIONS]
```

### Options
| Option | Type | Default | Description |
|---|---|---|---|
| `--mode` | `Choice(['auto', 'ollama', 'offline'])` | `auto` | Reasoning client mode. `auto` checks if Ollama is reachable; falls back to offline rules if offline. |
| `--model` | String | Config default | Override Ollama model name (e.g., `qwen2.5-coder:7b-instruct`). |

### Example
```bash
python -m crs.stream samples/vulnerable/command_injection --mode auto
```

Each line emitted is a flushed JSON object:
```json
{"type": "stage", "t": 0.012, "data": {"stage": "FIND", "status": "running"}}
{"type": "findings", "t": 0.450, "data": {"findings": [...]}}
{"type": "done", "t": 3.200, "data": {"decision": "VERIFIED", "approved": true}}
```
This command serves as the backend bridge for the Next.js 16 Web Dashboard (`/api/run`).
