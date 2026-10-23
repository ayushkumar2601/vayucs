from __future__ import annotations
"""In-memory Ephemeral SSH Keypair Generation & Remote Execution."""

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def generate_ephemeral_ssh_keypair() -> Tuple[str, str]:
    """Generate a high-security in-memory Ed25519 keypair for ephemeral sandbox SSH."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_ssh = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8")

    return private_pem, f"{public_ssh.strip()} vayu-ephemeral-sandbox"


@dataclass
class RemoteExecutionResult:
    """Outcome of a command executed remotely on the sandbox droplet."""
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class SSHTunnel:
    """Manages secure communication with the ephemeral sandbox Droplet."""

    def __init__(self, host_ip: str, private_key_pem: str, user: str = "root", port: int = 22) -> None:
        self.host_ip = host_ip
        self.private_key_pem = private_key_pem
        self.user = user
        self.port = port
        self._key_file: tempfile.NamedTemporaryFile | None = None

    def __enter__(self) -> "SSHTunnel":
        self._key_file = tempfile.NamedTemporaryFile(mode="w", delete=False, prefix="vayu-ssh-")
        self._key_file.write(self.private_key_pem)
        self._key_file.flush()
        os.chmod(self._key_file.name, 0o600)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._key_file:
            try:
                os.remove(self._key_file.name)
            except OSError:
                pass
            self._key_file = None

    def _base_ssh_args(self) -> list[str]:
        if not self._key_file:
            raise RuntimeError("SSHTunnel must be used within a context manager block")
        return [
            "-i",
            self._key_file.name,
            "-p",
            str(self.port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "BatchMode=yes",
        ]

    def run_command(self, command: str, timeout: float = 60.0) -> RemoteExecutionResult:
        """Run a shell command on the remote droplet."""
        ssh_cmd = ["ssh", *self._base_ssh_args(), f"{self.user}@{self.host_ip}", command]
        try:
            res = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
            return RemoteExecutionResult(
                returncode=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            return RemoteExecutionResult(
                returncode=-1,
                stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
                stderr=exc.stderr or "Command timed out" if isinstance(exc.stderr, str) else "Command timed out",
                timed_out=True,
            )

    def upload_directory(self, local_path: Path | str, remote_path: str, timeout: float = 60.0) -> bool:
        """Upload a local directory to the remote droplet using rsync or tar over ssh."""
        local = Path(local_path).resolve()
        tar_cmd = f"tar -czf - -C {local} ."
        untar_cmd = f"ssh {' '.join(self._base_ssh_args())} {self.user}@{self.host_ip} 'mkdir -p {remote_path} && tar -xzf - -C {remote_path}'"
        
        full_pipeline = f"{tar_cmd} | {untar_cmd}"
        try:
            res = subprocess.run(
                full_pipeline,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False
