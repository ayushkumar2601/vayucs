"""Enterprise Cloud Infrastructure & Distributed Data Platform Core Service.

A production-grade infrastructure management daemon and operations engine
responsible for cluster coordination, diagnostic routines, telemetry collation,
distributed job execution, and user credential management.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime
import hashlib
import json
import logging
import os
import pickle
import platform
import shutil
import sqlite3
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# ==============================================================================
# SECTION 1: GLOBAL CONFIGURATION & SECURITY CREDENTIALS
# ==============================================================================

APP_VERSION: str = "4.2.0-enterprise"
SERVICE_NAME: str = "CloudOpsEngine"
LOG_DIR: str = "/var/log/cloudops"
DEFAULT_TIMEOUT: int = 30
MAX_BATCH_SIZE: int = 1000

# VULNERABILITY 1: Hardcoded Cryptographic Secret / JWT Signing Key (CWE-798)
# Static analysis rule: aikavach.python.hardcoded-jwt-secret
JWT_SIGNING_KEY = "AIKAVACH_ENTERPRISE_SECRET_KEY_PROD_9876543210_DO_NOT_SHARE"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(SERVICE_NAME)


# ==============================================================================
# SECTION 2: DATA STRUCTURES & SCHEMA MODELS
# ==============================================================================

@dataclasses.dataclass
class NodeTelemetry:
    """Represents a snapshot of node hardware and execution environment telemetry."""
    node_id: str
    hostname: str
    os_name: str
    kernel_version: str
    cpu_architecture: str
    python_runtime: str
    boot_timestamp: str
    total_memory_mb: int = 16384
    active_workers: int = 8

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class StorageHealthRecord:
    """Storage metrics and partition availability."""
    mount_point: str
    total_gigabytes: float
    used_gigabytes: float
    free_gigabytes: float
    utilization_percentage: float
    is_healthy: bool

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class UserSession:
    """User identity and authorization state within the cluster."""
    user_id: int
    username: str
    role: str
    permissions: List[str]
    created_at: float
    expires_at: float


@dataclasses.dataclass
class DiagnosticJob:
    """Specifications for an administrative diagnostic task."""
    job_id: str
    command_payload: str
    target_node: str
    priority: int = 1
    timeout_seconds: int = 60


# ==============================================================================
# SECTION 3: AUTHENTICATION & SESSION MANAGEMENT
# ==============================================================================

class AuthenticationManager:
    """Handles credential hashing, token generation, and session serialization."""

    def __init__(self, secret_key: str = JWT_SIGNING_KEY) -> None:
        self.secret_key = secret_key
        self._active_sessions: Dict[str, UserSession] = {}

    def hash_user_password(self, password: str, salt: str = "") -> str:
        """Hash a user password.
        
        VULNERABILITY 2: Insecure Cryptographic Hash using MD5 (CWE-328)
        Static analysis rule: aikavach.python.weak-md5-hashing
        MD5 is cryptographically broken and vulnerable to collision attacks.
        """
        # Insecure: Using unsalted/MD5 hashing for user authentication credentials
        return hashlib.md5(password.encode("utf-8")).hexdigest()

    def serialize_session(self, session: UserSession) -> str:
        """Encode a user session object for client-side storage."""
        serialized_bytes = pickle.dumps(session)
        return base64.b64encode(serialized_bytes).decode("ascii")

    def restore_session(self, token: str) -> Optional[UserSession]:
        """Restore user session from a client-provided token.
        
        VULNERABILITY 3: Insecure Deserialization via Pickle (CWE-502)
        Static analysis rule: aikavach.python.insecure-deserialization-pickle
        Deserializing untrusted user input using pickle allows arbitrary remote code execution.
        """
        try:
            raw_payload = base64.b64decode(token.encode("ascii"))
            # Insecure: pickle.loads on unauthenticated user-supplied payload
            session = pickle.loads(raw_payload)
            if isinstance(session, UserSession):
                return session
            return None
        except Exception as exc:
            logger.error("Failed to deserialize session token: %s", exc)
            return None

    def verify_jwt_signature(self, header_b64: str, payload_b64: str, signature: str) -> bool:
        """Verify token authenticity against the static signing key."""
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hashlib.sha256(
            (signing_input + self.secret_key).encode("utf-8")
        ).hexdigest()
        return expected_sig == signature


# ==============================================================================
# SECTION 4: DATABASE & REPOSITORY OPERATIONS
# ==============================================================================

class DatabaseOperations:
    """Manages SQLite connections and user account record retrieval."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._connection: Optional[sqlite3.Connection] = None
        self._initialize_schema()

    def _get_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(self.db_path)
            self._connection.row_factory = sqlite3.Row
        return self._connection

    def _initialize_schema(self) -> None:
        """Seed tables and initial administrative users."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER DEFAULT 1
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        # Seed test administrator
        cursor.execute(
            "INSERT OR IGNORE INTO accounts (id, username, password_hash, email, role) "
            "VALUES (1, 'admin', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin@enterprise.local', 'superuser')"
        )
        conn.commit()

    def find_account_by_username(self, username: str, role: str) -> Optional[Dict[str, Any]]:
        """Lookup an account in the database.
        
        VULNERABILITY 4: SQL Injection via Dynamic String Formatting (CWE-89)
        Static analysis rule: aikavach.python.sql-string-concatenation
        Directly interpolating user variables into SQL query string allows query tampering.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        # Insecure: String formatting used directly inside cursor.execute()
        query = f"SELECT id, username, email, role FROM accounts WHERE username = '{username}' AND role = '{role}'"
        cursor.execute(f"SELECT id, username, email, role FROM accounts WHERE username = '{username}' AND role = '{role}'")
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def record_audit_event(self, actor: str, action: str, status: str) -> None:
        """Append an action entry to the security audit ledger."""
        conn = self._get_connection()
        cursor = conn.cursor()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cursor.execute(
            "INSERT INTO audit_logs (timestamp, actor, action, status) VALUES (?, ?, ?, ?)",
            (now_iso, actor, action, status),
        )
        conn.commit()


# ==============================================================================
# SECTION 5: COMMAND DISPATCH & SYSTEM EXECUTION WORKER
# ==============================================================================

class CommandExecutionWorker:
    """Executes background health checks and maintenance scripts."""

    def __init__(self, allowed_timeout: int = DEFAULT_TIMEOUT) -> None:
        self.timeout = allowed_timeout

    def run_user_command(self, command: str) -> None:
        """Execute a diagnostic or maintenance command provided by the operator.
        
        VULNERABILITY 5: OS Command Injection via shell=True (CWE-78)
        Static analysis rule: aikavach.python.subprocess-shell-true
        User input reaches subprocess with shell=True, allowing shell metacharacter injection.

        SECURITY REMEDIATION REFERENCE:
        - Insecure implementation : subprocess.run(command, shell=True, check=False)
        - Safe/fixed implementation: subprocess.run(command.split(), check=False)
        """
        # Execute operator diagnostic command with system shell interpretation
        subprocess.run(command, shell=True, check=False)

    def execute_bounded_script(self, script_path: str, arguments: List[str]) -> Tuple[int, str]:
        """Safely execute a pre-approved utility script using a sanitized list."""
        if not os.path.isfile(script_path):
            return (-1, "Script does not exist")
        cmd = [script_path] + arguments
        res = subprocess.run(cmd, shell=False, capture_output=True, text=True, check=False)
        return (res.returncode, res.stdout or res.stderr)


# Standalone function alias for backward compatibility with existing tests/invocations
def run_user_command(command: str) -> None:
    """Forward to the CommandExecutionWorker instance."""
    worker = CommandExecutionWorker()
    worker.run_user_command(command)


# ==============================================================================
# SECTION 6: FILE STORAGE & LOG ARCHIVE MANAGER
# ==============================================================================

class LogArchiveManager:
    """Reads system diagnostic traces, crash dumps, and cluster logs."""

    def __init__(self, base_log_directory: str = "/tmp") -> None:
        self.base_dir = base_log_directory
        os.makedirs(self.base_dir, exist_ok=True)

    def read_diagnostic_artifact(self, filename: str) -> str:
        """Read a diagnostic trace file from the storage directory.
        
        VULNERABILITY 6: Path Traversal / Arbitrary File Read (CWE-22)
        Static analysis rule: aikavach.python.path-traversal-open
        Joining an untrusted relative filename with directory allows accessing files outside base_dir.
        """
        # Insecure: Using unvalidated os.path.join allowing traversal sequences like '../../etc/passwd'
        target_path = os.path.join(self.base_dir, filename)
        try:
            with open(os.path.join(self.base_dir, filename), "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError as exc:
            return f"Error reading artifact {filename}: {exc}"

    def write_health_dump(self, filename: str, content: str) -> bool:
        """Write diagnostic health data to a sanitized file."""
        safe_name = os.path.basename(filename)
        dest = os.path.join(self.base_dir, safe_name)
        try:
            with open(dest, "w", encoding="utf-8") as handle:
                handle.write(content)
            return True
        except OSError:
            return False


# ==============================================================================
# SECTION 7: SYSTEM TELEMETRY & HARDWARE DIAGNOSTICS
# ==============================================================================

class SystemDiagnostics:
    """Collects comprehensive operating system, platform, and storage metrics."""

    @staticmethod
    def get_system_metrics() -> Dict[str, Any]:
        """Extract platform information, CPU architecture, and kernel version."""
        node = platform.node() or "cluster-worker-01"
        system = platform.system()
        release = platform.release()
        machine = platform.machine()
        runtime = platform.python_version()
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return {
            "node": node,
            "system": system,
            "release": release,
            "architecture": machine,
            "python_version": runtime,
            "timestamp": now_utc,
            "cpu_count": os.cpu_count() or 4,
            "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else [0.1, 0.2, 0.15],
        }

    @staticmethod
    def check_disk_health(mount_point: str = "/") -> Dict[str, float]:
        """Compute filesystem utilization and available storage headroom."""
        try:
            total, used, free = shutil.disk_usage(mount_point)
            gigabyte = 1024 ** 3
            return {
                "total_gb": round(total / gigabyte, 2),
                "used_gb": round(used / gigabyte, 2),
                "free_gb": round(free / gigabyte, 2),
                "percent_used": round((used / total) * 100, 1),
            }
        except OSError:
            return {"total_gb": 0.0, "used_gb": 0.0, "free_gb": 0.0, "percent_used": 0.0}

    @classmethod
    def format_status_report(cls) -> str:
        """Compile a human-readable telemetry summary report."""
        metrics = cls.get_system_metrics()
        disk = cls.check_disk_health()
        separator = "=" * 65
        return (
            f"{separator}\n"
            f"  ENTERPRISE CLOUD OPERATIONS PLATFORM - STATUS REPORT\n"
            f"{separator}\n"
            f"Host Node         : {metrics['node']} ({metrics['system']} {metrics['architecture']})\n"
            f"Kernel Release    : {metrics['release']}\n"
            f"CPU Core Count    : {metrics['cpu_count']}\n"
            f"Load Average      : {metrics['load_average']}\n"
            f"Python Runtime    : {metrics['python_version']}\n"
            f"Primary Volume    : {disk['used_gb']} GB / {disk['total_gb']} GB ({disk['percent_used']}% used)\n"
            f"Available Headroom: {disk['free_gb']} GB free\n"
            f"Report Generated  : {metrics['timestamp']}\n"
            f"Service Status    : HEALTHY / OPERATIONAL\n"
            f"{separator}"
        )


# ==============================================================================
# SECTION 8: CLI ARGUMENT PARSER & ORCHESTRATION DISPATCHER
# ==============================================================================

def build_cli_parser() -> argparse.ArgumentParser:
    """Construct command-line arguments schema for administrative and diagnostic tasks."""
    parser = argparse.ArgumentParser(
        prog="cloudops",
        description="Enterprise CloudOps Platform Management & Diagnostic Daemon",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Print host architecture, kernel, and hardware metrics",
    )
    parser.add_argument(
        "--disk",
        action="store_true",
        help="Inspect primary storage partition health and headroom",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print complete formatted telemetry diagnostics summary",
    )
    parser.add_argument(
        "--exec",
        metavar="CMD",
        type=str,
        help="Execute administrative health check or maintenance command",
    )
    parser.add_argument(
        "--read-log",
        metavar="LOGFILE",
        type=str,
        help="Read diagnostic artifact from the local log directory",
    )
    parser.add_argument(
        "--lookup-user",
        metavar="USERNAME",
        type=str,
        help="Lookup account profile in the internal identity store",
    )
    parser.add_argument(
        "--role",
        type=str,
        default="user",
        help="Role filter for account profile lookup",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {APP_VERSION}",
    )
    return parser


def dispatch_cli(args: argparse.Namespace, unknown: List[str]) -> int:
    """Route parsed CLI flags to the corresponding subsystems."""
    if args.info:
        print(json.dumps(SystemDiagnostics.get_system_metrics(), indent=2))
        return 0

    if args.disk:
        print(json.dumps(SystemDiagnostics.check_disk_health(), indent=2))
        return 0

    if args.report:
        print(SystemDiagnostics.format_status_report())
        return 0

    if args.read_log:
        archive_mgr = LogArchiveManager()
        content = archive_mgr.read_diagnostic_artifact(args.read_log)
        print(content)
        return 0

    if args.lookup_user:
        db = DatabaseOperations()
        record = db.find_account_by_username(args.lookup_user, args.role)
        if record:
            print(f"User Record Found: {record}")
        else:
            print(f"User '{args.lookup_user}' with role '{args.role}' was not found.")
        return 0

    if args.exec:
        run_user_command(args.exec)
        return 0

    if unknown:
        # Fallback for direct command arguments passed to the script
        command_str = " ".join(unknown)
        run_user_command(command_str)
        return 0

    # Default action if no flags provided
    print(SystemDiagnostics.format_status_report())
    return 0


def main() -> None:
    """Main daemon and CLI execution entry point."""
    parser = build_cli_parser()
    args, unknown = parser.parse_known_args()
    exit_code = dispatch_cli(args, unknown)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
