from __future__ import annotations
"""Configuration for DigitalOcean Ephemeral Cloud Sandboxing."""

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class DigitalOceanConfig:
    """Settings required to manage ephemeral sandbox Droplets on DigitalOcean."""

    token: str = ""
    region: str = "nyc3"
    size: str = "s-1vcpu-1gb"
    image: str = "ubuntu-24-04-x64"
    timeout: float = 300.0
    safety_ttl_minutes: int = 10
    base_url: str = "https://api.digitalocean.com/v2"

    @classmethod
    def from_env(cls) -> "DigitalOceanConfig":
        """Load configuration from environment variables."""
        token = (
            os.environ.get("DO_API_TOKEN")
            or os.environ.get("DIGITALOCEAN_TOKEN")
            or ""
        ).strip()
        region = os.environ.get("DO_REGION", "nyc3").strip() or "nyc3"
        size = os.environ.get("DO_SIZE", "s-1vcpu-1gb").strip() or "s-1vcpu-1gb"
        image = os.environ.get("DO_IMAGE", "ubuntu-24-04-x64").strip() or "ubuntu-24-04-x64"

        try:
            timeout = float(os.environ.get("DO_SANDBOX_TIMEOUT", "300.0"))
        except ValueError:
            timeout = 300.0

        try:
            safety_ttl = int(os.environ.get("DO_SAFETY_TTL_MINUTES", "10"))
        except ValueError:
            safety_ttl = 10

        return cls(
            token=token,
            region=region,
            size=size,
            image=image,
            timeout=timeout,
            safety_ttl_minutes=safety_ttl,
        )

    def is_configured(self) -> bool:
        """Return True if an API token is provided."""
        return bool(self.token)

    def validate(self) -> None:
        """Ensure token is present; raise actionable error if missing."""
        if not self.is_configured():
            raise ValueError(
                "DigitalOcean API token is not configured. "
                "Set DIGITALOCEAN_TOKEN or DO_API_TOKEN in your environment or .env.local:\n"
                "  export DIGITALOCEAN_TOKEN=\"dop_v1_...\""
            )
