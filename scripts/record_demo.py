#!/usr/bin/env python3
"""
VAYU Automated CLI Live Demonstration Runner
Designed for high-impact screen recording (3-4 minutes).
Simulates realistic terminal interaction with smooth pauses.
"""

import sys
import os
import time
import subprocess
import shlex

# Colors and formatting
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
WHITE = "\033[97m"

PROMPT = f"{GREEN}{BOLD}ayush@macbook{RESET}:{CYAN}{BOLD}~/vayu{RESET}$ "

def type_command(cmd: str, delay: float = 0.04):
    """Simulates realistic human typing of a command."""
    sys.stdout.write(PROMPT)
    sys.stdout.flush()
    time.sleep(0.3)
    for ch in cmd:
        sys.stdout.write(f"{WHITE}{BOLD}{ch}{RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    time.sleep(0.4)
    sys.stdout.write("\n")
    sys.stdout.flush()

def run_step(title: str, cmd: str, pause_after: float = 4.0):
    """Executes a demonstration step with simulated typing and output streaming."""
    type_command(cmd)
    
    # Run command streaming stdout and stderr
    env = os.environ.copy()
    # Ensure env vars from .env.local are loaded if present
    env_local_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env.local")
    if os.path.exists(env_local_path):
        with open(env_local_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("export "):
                    line = line[7:]
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")

    proc = subprocess.run(cmd, shell=True, env=env)
    
    time.sleep(pause_after)
    sys.stdout.write("\n")
    sys.stdout.flush()

def main():
    os.system("clear")
    time.sleep(1.0)
    
    # Step 1: Vayu Help overview
    run_step(
        "Act 1: VAYU Core System Overview",
        "vayu --help",
        pause_after=4.0
    )
    
    # Step 2: Vayu Skills Catalog
    run_step(
        "Act 2: Exploring Agent Skills Catalog",
        "vayu skills list",
        pause_after=6.0
    )
    
    # Step 3: Vayu Skills Diagnostics (Doctor)
    run_step(
        "Act 3: System Health Diagnostics",
        "vayu skills doctor",
        pause_after=5.0
    )
    
    # Step 4: Installing a Security Skill
    run_step(
        "Act 4: Installing Security Analysis Skill",
        "vayu skills add security-analysis --force",
        pause_after=5.0
    )
    
    # Step 5: Full Autonomous CRS Pipeline Scan & 4-Gate Verification
    run_step(
        "Act 5: Autonomous Vulnerability Remediation & Verification",
        "vayu scan samples/vulnerable/command_injection --sandbox local",
        pause_after=6.0
    )
    
    # Step 6: Full Automated Test Suite Validation
    run_step(
        "Act 6: Verifying System Invariants (188 Tests)",
        "pytest -q",
        pause_after=4.0
    )
    
    print(f"\n{GREEN}{BOLD}════════════════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{GREEN}{BOLD}  ⚡ VAYU Autonomous Cyber Reasoning System — Live Demo Completed Successfully  {RESET}")
    print(f"{GREEN}{BOLD}════════════════════════════════════════════════════════════════════════════════{RESET}\n")

if __name__ == "__main__":
    main()
