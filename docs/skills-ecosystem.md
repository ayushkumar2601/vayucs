# 🧠 VAYU Agent Skills Ecosystem

VAYU includes a native **AI Agent Skills framework** and dedicated CLI (`vayu skills`) engineered to bridge autonomous cyber reasoning with interactive AI coding assistants.

---

## 1. Architecture & Specification

An **Agent Skill** is a modular, composable capability packaged as a directory containing structured instructions, workflows, and rules formatted in GitHub Markdown with YAML frontmatter.

### Standard Skill Directory Structure

```
.agents/skills/<skill-name>/
├── SKILL.md                 # Primary instruction file (Mandatory)
├── scripts/                 # Executable helper scripts and automation (Optional)
├── examples/                # Concrete reference examples and patterns (Optional)
└── references/              # Architectural documentation and standards (Optional)
```

### Frontmatter Schema (`SKILL.md`)

```yaml
---
name: security-analysis
description: Analyze application security vulnerabilities using evidence-driven reasoning and VAYU's security principles.
version: 1.0.0
author: VAYU Development Team
license: Apache-2.0
tags: [security, sast, reasoning, semgrep]
---

# Instructions
...
```

---

## 2. Bundled Catalog Inventory

VAYU bundles eight enterprise-grade AI agent skills in `crs/skills_catalog/`:

| Skill | Category | Primary Workflow |
|---|---|---|
| **`security-analysis`** | Detection & Triage | Performs structured root-cause analysis, calculates CVSS impact, traces data flows from source to sink, and formulates remediation strategies. |
| **`secure-code-review`** | Code Review | Systematic pre-merge audit: checks for input sanitization, unsafe deserialization, hardcoded secrets, and missing access controls. |
| **`vulnerability-remediation`** | Patching | Generates atomic, single-site code fixes. Enforces the Indentation Lock and prohibits destructive full-file rewrites. |
| **`patch-verification`** | Verification | Orchestrates 4-gate fail-closed testing: syntax checks, functional regression tests, AST invariant assertions, and Semgrep rescans. |
| **`prompt-injection-defense`** | Guardrails | Quarantines untrusted code, strips adversarial system prompts, and separates instructions from passive repository data. |
| **`sast-workflow`** | Static Analysis | Writes and tests Semgrep AST rules, tunes false-positive thresholds, and manages rule catalogs. |
| **`mcp-development`** | Protocol | Guides development of FastMCP servers, tool schemas, session managers, and stdio transport safety. |
| **`vayu-development`** | System Architecture | Enforces VAYU core invariants, Pydantic data schemas, test requirements (188 pytest tests), and code standards. |

---

## 3. Skills Installation & Resolution Hierarchy

VAYU resolves skills across two distinct scopes:

```
┌────────────────────────────────────────────────────────┐
│                   SKILL RESOLUTION                     │
├────────────────────────────────────────────────────────┤
│ 1. Project-Level Scope:                                │
│    <workspace_root>/.agents/skills/<skill_name>/       │
│    (Overrides global skills for repository-specific)   │
├────────────────────────────────────────────────────────┤
│ 2. Global-Level Scope:                                 │
│    ~/.gemini/config/skills/<skill_name>/               │
│    (Available across all repositories for user)        │
└────────────────────────────────────────────────────────┘
```

### CLI Workflows

```bash
# 1. Inspect all skills in the bundled catalog
vayu skills list

# 2. Search for skills related to remediation
vayu skills search remediation

# 3. Install into your repository (.agents/skills/)
vayu skills add vulnerability-remediation

# 4. Install globally for user-level AI assistants
vayu skills add vulnerability-remediation --global

# 5. Install from an external GitHub repository
vayu skills add frontend-design --from https://github.com/anthropics/skills

# 6. View skill details and instruction preview
vayu skills info vulnerability-remediation

# 7. Check directory health
vayu skills doctor

# 8. Remove a skill
vayu skills remove vulnerability-remediation
```

---

## 4. Prompt Injection Defense in Skills

When skills are loaded into Large Language Models, malicious repositories may attempt to exploit the skill instructions. VAYU's `prompt-injection-defense` skill establishes three defensive invariants:
1. **Quarantine Tagging**: Repository evidence must always be wrapped in `<untrusted_content>` tags.
2. **Passive Data Principle**: AI models must treat all repository text strictly as passive data, never interpreting text in code comments or docstrings as instructions.
3. **Canonical Diff Enforcement**: Models must never be permitted to approve their own patches.

---

## 5. Creating a Custom Skill

To contribute or deploy a custom skill:
1. Create a directory: `.agents/skills/<your-skill-name>/`.
2. Add a `SKILL.md` file with valid YAML frontmatter containing `name` and `description`.
3. Provide step-by-step instructions with clear input contracts and output expectations.
4. Run `vayu skills doctor` to validate that the skill passes all frontmatter and schema checks.
