from __future__ import annotations
"""Lightweight DigitalOcean API v2 REST client for Ephemeral Sandboxing."""

import json
from time import monotonic, sleep
from typing import Any, Callable
import urllib.error
import urllib.request

from crs.verification.cloud.do_config import DigitalOceanConfig


class DigitalOceanError(Exception):
    """Raised when an operation against the DigitalOcean API fails."""

    def __init__(self, message: str, status_code: int | None = None, response_body: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class DigitalOceanClient:
    """REST Client for DigitalOcean Droplet & SSH Key management."""

    def __init__(self, config: DigitalOceanConfig | None = None) -> None:
        self.config = config or DigitalOceanConfig.from_env()

    def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        self.config.validate()
        url = f"{self.config.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {self.config.token}",
            "Content-Type": "application/json",
            "User-Agent": "VAYU-CRS-CloudSandbox/1.0",
        }

        body_bytes = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = response.status
                raw = response.read().decode("utf-8")
                if not raw.strip():
                    return {}
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            # If 404 on delete, treat as already deleted
            if method == "DELETE" and exc.code == 404:
                return {}
            raise DigitalOceanError(
                f"DigitalOcean API error ({exc.code} {exc.reason}): {err_body}",
                status_code=exc.code,
                response_body=err_body,
            ) from exc
        except urllib.error.URLError as exc:
            raise DigitalOceanError(f"Network error connecting to DigitalOcean: {exc.reason}") from exc
        except Exception as exc:
            raise DigitalOceanError(f"Unexpected error communicating with DigitalOcean: {exc}") from exc

    def create_droplet(
        self,
        name: str,
        size: str | None = None,
        region: str | None = None,
        image: str | None = None,
        ssh_keys: list[int | str] | None = None,
        user_data: str | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new ephemeral sandbox Droplet."""
        payload: dict[str, Any] = {
            "name": name,
            "region": region or self.config.region,
            "size": size or self.config.size,
            "image": image or self.config.image,
            "tags": tags or ["vayu", "vayu-sandbox", "ephemeral"],
        }
        if ssh_keys:
            payload["ssh_keys"] = ssh_keys
        if user_data:
            payload["user_data"] = user_data

        resp = self._request("POST", "/droplets", data=payload)
        return resp.get("droplet", {})

    def get_droplet(self, droplet_id: int | str) -> dict[str, Any]:
        """Fetch status and network information for a Droplet."""
        resp = self._request("GET", f"/droplets/{droplet_id}")
        return resp.get("droplet", {})

    def wait_for_active(
        self,
        droplet_id: int | str,
        poll_interval: float = 3.0,
        max_wait: float = 120.0,
        on_poll: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Poll until the Droplet is active and has an allocated public IPv4 address."""
        start = monotonic()
        while monotonic() - start < max_wait:
            droplet = self.get_droplet(droplet_id)
            status = droplet.get("status")

            if on_poll:
                on_poll(status or "unknown")

            if status == "active":
                ip = self.extract_public_ipv4(droplet)
                if ip:
                    return droplet

            sleep(poll_interval)

        raise DigitalOceanError(
            f"Timed out waiting for sandbox Droplet {droplet_id} to become active ({max_wait}s limit exceeded)"
        )

    def extract_public_ipv4(self, droplet: dict[str, Any]) -> str | None:
        """Extract public IPv4 address from Droplet network payload."""
        networks = droplet.get("networks", {}).get("v4", [])
        for net in networks:
            if net.get("type") == "public":
                return net.get("ip_address")
        return None

    def destroy_droplet(self, droplet_id: int | str) -> bool:
        """Permanently delete a sandbox Droplet."""
        try:
            self._request("DELETE", f"/droplets/{droplet_id}")
            return True
        except DigitalOceanError as err:
            if err.status_code == 404:
                return True
            raise

    def add_ssh_key(self, name: str, public_key: str) -> dict[str, Any]:
        """Register an ephemeral public SSH key on DigitalOcean."""
        resp = self._request("POST", "/account/keys", data={"name": name, "public_key": public_key})
        return resp.get("ssh_key", {})

    def delete_ssh_key(self, key_id: int | str) -> bool:
        """Delete an ephemeral SSH key."""
        try:
            self._request("DELETE", f"/account/keys/{key_id}")
            return True
        except DigitalOceanError as err:
            if err.status_code == 404:
                return True
            raise

    def list_sandboxes(self, tag: str = "vayu-sandbox") -> list[dict[str, Any]]:
        """List active sandboxes with the given tag."""
        resp = self._request("GET", f"/droplets?tag_name={tag}")
        return resp.get("droplets", [])
