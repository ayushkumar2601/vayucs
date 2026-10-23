---
name: secure-code-review
description: Review code for security defects, injection vectors, and unsafe programming patterns.
category: Code Review & Quality
version: 1.0.0
author: VAYU Development Team
---

# Secure Code Review

## Objective
Systematically inspect source code for security vulnerabilities, dangerous APIs, and insecure coding idioms before pull requests are approved.

## Review Checklist
1. **Command Execution (CWE-78)**:
   - Check for `subprocess.run`, `Popen`, `os.system` with `shell=True`.
   - Verify argument arrays are passed instead of concatenated shell command strings.
2. **SQL Injection (CWE-89)**:
   - Check for SQL queries constructed using f-strings, format specifiers, or string concatenation.
   - Enforce parameterized queries (`cursor.execute("SELECT ... WHERE id = ?", (val,))`).
3. **Insecure Deserialization (CWE-502)**:
   - Identify uses of `pickle.loads`, `yaml.load(Loader=Loader)`, or unsafe marshalers on untrusted data.
   - Enforce structured, safe formats like JSON or Protocol Buffers.
4. **Cryptographic Weaknesses (CWE-328 & CWE-798)**:
   - Identify broken hash functions (`hashlib.md5`, `SHA1`) used for security purposes.
   - Identify hardcoded API tokens, private keys, or JWT secrets in code literals.
5. **Path Traversal (CWE-22)**:
   - Check filesystem reads/writes using user-provided paths without `resolve()` and root boundary containment checks.

## Output Format
- Provide file path, line number, severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- State the CWE identifier and explain the risk.
- Propose the exact secure code replacement.
