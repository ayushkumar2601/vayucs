from __future__ import annotations
"""DigitalOcean Ephemeral Sandbox Workspace Context Manager."""

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import tempfile
from types import TracebackType
from typing import Callable
import uuid

from crs.verification.cloud.do_client import DigitalOceanClient, DigitalOceanError
from crs.verification.cloud.do_config import DigitalOceanConfig
from crs.verification.cloud.ssh_tunnel import SSHTunnel, generate_ephemeral_ssh_keypair


@dataclass
class DropletMetadata:
    """Metadata regarding the ephemeral cloud sandbox instance."""
    droplet_id: int | str
    name: str
    ip_address: str
    region: str
    size: str
    image: str


class DigitalOceanSandboxWorkspace:
    """Provisions a disposable DigitalOcean Droplet sandbox for safe patch verification."""

    IGNORED_DIRECTORIES = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "node_modules",
        "dist",
        "build",
    }

    def __init__(
        self,
        repository_root: str,
        config: DigitalOceanConfig | None = None,
        client: DigitalOceanClient | None = None,
        on_status: Callable[[str], None] | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).expanduser().resolve()
        self.config = config or DigitalOceanConfig.from_env()
        self.client = client or DigitalOceanClient(self.config)
        self.on_status = on_status

        self.droplet_id: int | str | None = None
        self.ssh_key_id: int | str | None = None
        self.droplet_ip: str | None = None
        self.droplet_metadata: DropletMetadata | None = None

        self._local_staging: tempfile.TemporaryDirectory[str] | None = None
        self.path: Path | None = None
        self._private_ssh_key: str | None = None
        self._public_ssh_key: str | None = None
        self.tunnel: SSHTunnel | None = None

    def _emit(self, msg: str) -> None:
        if self.on_status:
            self.on_status(msg)

    def _generate_cloud_init(self) -> str:
        ttl = self.config.safety_ttl_minutes
        return f"""#cloud-config
package_update: true
packages:
  - python3
  - python3-pip
  - git
runcmd:
  - mkdir -p /opt/vayu/sandbox
  - echo "shutdown -h +{ttl} 'VAYU CRS Safety TTL Expired'" | at now || true
"""

    def __enter__(self) -> "DigitalOceanSandboxWorkspace":
        if not self.repository_root.is_dir():
            raise NotADirectoryError(f"Repository root is not a directory: {self.repository_root}")

        self.config.validate()
        run_suffix = uuid.uuid4().hex[:8]
        droplet_name = f"vayu-sandbox-{run_suffix}"
        key_name = f"vayu-key-{run_suffix}"

        # 1. Local Staging Copy (for patch application & upload)
        self._local_staging = tempfile.TemporaryDirectory(prefix="vayu-do-staging-")
        destination = Path(self._local_staging.name) / self.repository_root.name
        shutil.copytree(
            self.repository_root,
            destination,
            ignore=self._ignore_entries,
            symlinks=True,
        )
        self.path = destination

        # 2. Ephemeral SSH Keypair
        self._emit(f"Generating ephemeral SSH keypair for {droplet_name}...")
        self._private_ssh_key, self._public_ssh_key = generate_ephemeral_ssh_keypair()
        key_resp = self.client.add_ssh_key(key_name, self._public_ssh_key)
        self.ssh_key_id = key_resp.get("id")

        # 3. Provision Droplet
        self._emit(f"Provisioning DigitalOcean Droplet ({self.config.region}, {self.config.size})...")
        user_data = self._generate_cloud_init()
        droplet_resp = self.client.create_droplet(
            name=droplet_name,
            size=self.config.size,
            region=self.config.region,
            image=self.config.image,
            ssh_keys=[self.ssh_key_id] if self.ssh_key_id else None,
            user_data=user_data,
            tags=["vayu", "vayu-sandbox", "ephemeral"],
        )
        self.droplet_id = droplet_resp.get("id")

        if not self.droplet_id:
            raise DigitalOceanError("Failed to obtain Droplet ID from DigitalOcean API")

        # 4. Wait for Active Status & Public IP
        self._emit("Waiting for Droplet to become active...")
        active_droplet = self.client.wait_for_active(
            self.droplet_id,
            max_wait=120.0,
            on_poll=lambda s: self._emit(f"Droplet status: {s}..."),
        )
        self.droplet_ip = self.client.extract_public_ipv4(active_droplet)

        if not self.droplet_ip:
            raise DigitalOceanError(f"Droplet {self.droplet_id} reached active status but has no public IPv4")

        self.droplet_metadata = DropletMetadata(
            droplet_id=self.droplet_id,
            name=droplet_name,
            ip_address=self.droplet_ip,
            region=self.config.region,
            size=self.config.size,
            image=self.config.image,
        )
        self._emit(f"Droplet active at {self.droplet_ip}")

        # 5. Initialize SSH Tunnel
        self.tunnel = SSHTunnel(
            host_ip=self.droplet_ip,
            private_key_pem=self._private_ssh_key,
        )
        self.tunnel.__enter__()

        return self

    def sync_to_remote(self) -> bool:
        """Sync the locally patched workspace tree to the remote droplet."""
        if not self.tunnel or not self.path or not self.droplet_ip:
            return False
        self._emit(f"Syncing workspace to remote droplet at {self.droplet_ip}:/opt/vayu/sandbox...")
        return self.tunnel.upload_directory(self.path, "/opt/vayu/sandbox")

    def run_remote_command(self, cmd: str, timeout: float = 60.0):
        """Execute a command inside the remote droplet."""
        if not self.tunnel:
            raise RuntimeError("SSH tunnel is not open to remote sandbox")
        return self.tunnel.run_command(cmd, timeout=timeout)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Guaranteed teardown of cloud resources in reverse order."""
        # 1. Close SSH Tunnel
        if self.tunnel:
            try:
                self.tunnel.__exit__(exc_type, exc_value, traceback)
            except Exception:
                pass
            self.tunnel = None

        # 2. Destroy Droplet
        if self.droplet_id:
            try:
                self._emit(f"Destroying ephemeral Droplet {self.droplet_id}...")
                self.client.destroy_droplet(self.droplet_id)
            except Exception as exc:
                self._emit(f"Warning: Failed to destroy Droplet {self.droplet_id}: {exc}")
            self.droplet_id = None

        # 3. Delete Ephemeral SSH Key
        if self.ssh_key_id:
            try:
                self.client.delete_ssh_key(self.ssh_key_id)
            except Exception:
                pass
            self.ssh_key_id = None

        # 4. Clean local staging
        if self._local_staging is not None:
            self._local_staging.cleanup()
            self._local_staging = None
        self.path = None

    def _ignore_entries(self, directory: str, names: list[str]) -> set[str]:
        current = Path(directory)
        return {
            name
            for name in names
            if name in self.IGNORED_DIRECTORIES or os.path.islink(current / name)
        }
