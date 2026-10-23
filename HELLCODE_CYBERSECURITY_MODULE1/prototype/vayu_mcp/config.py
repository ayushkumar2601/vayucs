from __future__ import annotations
"""Configuration and security boundary validation for the VAYU MCP Server."""

from dataclasses import dataclass, field
import os
from pathlib import Path
import sys
from typing import Any

# Use standard library tomllib in Python 3.11+; fallback to tomli if needed
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore


DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "gemma4:31b-cloud"
DEFAULT_TIMEOUT_SECONDS = 60.0
MAX_TIMEOUT_SECONDS = 300.0


class SecurityBoundaryError(ValueError):
    """Raised when an MCP client requests access outside authorized boundaries."""


@dataclass
class MCPConfig:
    """Runtime configuration and security policy for the VAYU MCP Server."""

    allowed_roots: list[Path] = field(default_factory=list)
    ollama_url: str = DEFAULT_OLLAMA_URL
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    mode: str = "auto"  # 'auto', 'ollama', 'offline'
    default_timeout: float = DEFAULT_TIMEOUT_SECONDS
    artifacts_dir: Path = field(default_factory=lambda: Path.cwd() / "artifacts")
    log_level: str = "INFO"

    def is_path_allowed(self, path: Path) -> bool:
        """Check if a canonical path falls within any configured allowed root."""
        if not self.allowed_roots:
            # If no explicit roots are configured, allow the current working directory and subdirectories
            return True
        resolved = path.resolve()
        for root in self.allowed_roots:
            root_res = root.resolve()
            if resolved == root_res or root_res in resolved.parents:
                return True
        return False

    def validate_target_path(self, target_path_str: str) -> Path:
        """Resolve and enforce security boundary validation on a target repository path."""
        if not target_path_str or not target_path_str.strip():
            raise SecurityBoundaryError("Target path must not be empty")

        if "\x00" in target_path_str:
            raise SecurityBoundaryError("Target path contains illegal null bytes")

        try:
            target = Path(target_path_str).expanduser().resolve()
        except Exception as exc:
            raise SecurityBoundaryError(f"Malformed filesystem path: {exc}") from exc

        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        if not target.is_dir():
            raise NotADirectoryError(f"Target path is not a directory: {target}")

        # Check symlink destination if target is a symlink
        if Path(target_path_str).is_symlink():
            real_target = target.resolve()
            if not self.is_path_allowed(real_target):
                raise SecurityBoundaryError(
                    f"Symlink target {real_target} escapes authorized workspace boundaries"
                )

        if not self.is_path_allowed(target):
            allowed_str = ", ".join(str(r) for r in self.allowed_roots)
            raise SecurityBoundaryError(
                f"Access denied: path '{target}' is outside authorized workspace roots: [{allowed_str}]"
            )

        return target

    def validate_output_path(self, output_path_str: str) -> Path:
        """Resolve and validate an output destination for exported artifacts (e.g., SARIF)."""
        if not output_path_str or not output_path_str.strip():
            raise SecurityBoundaryError("Output path must not be empty")

        if "\x00" in output_path_str:
            raise SecurityBoundaryError("Output path contains illegal null bytes")

        try:
            output = Path(output_path_str).expanduser().resolve()
        except Exception as exc:
            raise SecurityBoundaryError(f"Malformed output path: {exc}") from exc

        # Ensure parent directory exists or can be created
        parent = output.parent
        if not parent.exists():
            raise FileNotFoundError(f"Output destination parent directory does not exist: {parent}")

        # Destination must be inside an allowed root or the artifacts directory
        is_in_allowed = self.is_path_allowed(output) or (
            self.artifacts_dir.resolve() in output.parents or output.resolve() == self.artifacts_dir.resolve()
        )
        if not is_in_allowed:
            raise SecurityBoundaryError(
                f"Access denied: output destination '{output}' is outside authorized workspace boundaries"
            )

        # Prevent overwriting critical system files
        if output.name in (".git", "pyproject.toml", "package.json", "requirements.txt", ".env", ".env.local"):
            raise SecurityBoundaryError(
                f"Cannot overwrite protected project configuration file: {output.name}"
            )

        return output


def load_mcp_config(config_path: str | Path | None = None) -> MCPConfig:
    """Load settings from optional TOML configuration file and environment variables."""
    config = MCPConfig()

    # 1. Attempt to load from TOML file if present
    toml_path = None
    if config_path:
        toml_path = Path(config_path).expanduser().resolve()
    elif os.getenv("VAYU_CONFIG"):
        toml_path = Path(os.getenv("VAYU_CONFIG", "")).expanduser().resolve()
    else:
        # Check standard local paths
        candidates = [
            Path.cwd() / "vayu-config.toml",
            Path.cwd() / "examples" / "vayu-config.example.toml",
        ]
        for c in candidates:
            if c.is_file():
                toml_path = c
                break

    if toml_path and toml_path.is_file() and tomllib is not None:
        try:
            with open(toml_path, "rb") as f:
                data = tomllib.load(f)
            _apply_toml_data(config, data)
        except Exception as exc:
            print(f"[vayu-mcp] Warning: Failed to parse config file {toml_path}: {exc}", file=sys.stderr)

    # 2. Environment variables take precedence over file settings
    env_roots = os.getenv("VAYU_ALLOWED_ROOTS")
    if env_roots:
        roots = []
        for r in env_roots.split(","):
            r_str = r.strip()
            if r_str:
                roots.append(Path(r_str).expanduser().resolve())
        if roots:
            config.allowed_roots = roots

    if not config.allowed_roots:
        # Default to current working directory and repo root
        cwd = Path.cwd().resolve()
        config.allowed_roots = [cwd]
        # If running from inside a subfolder, add repo root if discernible
        repo_root = os.getenv("VAYU_REPO_ROOT")
        if repo_root:
            config.allowed_roots.append(Path(repo_root).expanduser().resolve())

    env_ollama_url = os.getenv("AIKAVACH_OLLAMA_URL")
    if env_ollama_url:
        config.ollama_url = env_ollama_url.rstrip("/")

    env_ollama_model = os.getenv("AIKAVACH_OLLAMA_MODEL")
    if env_ollama_model:
        config.ollama_model = env_ollama_model.strip()

    env_provider = os.getenv("AIKAVACH_LLM_PROVIDER")
    if env_provider:
        if env_provider.lower() in ("offline", "offline-rules"):
            config.mode = "offline"
        elif env_provider.lower() == "ollama":
            config.mode = "ollama"

    env_mode = os.getenv("VAYU_MCP_MODE")
    if env_mode and env_mode.lower() in ("auto", "ollama", "offline"):
        config.mode = env_mode.lower()

    env_timeout = os.getenv("VAYU_TIMEOUT")
    if env_timeout:
        try:
            val = float(env_timeout)
            if 0 < val <= MAX_TIMEOUT_SECONDS:
                config.default_timeout = val
        except ValueError:
            pass

    env_artifacts = os.getenv("VAYU_ARTIFACTS_DIR")
    if env_artifacts:
        config.artifacts_dir = Path(env_artifacts).expanduser().resolve()

    return config


def _apply_toml_data(config: MCPConfig, data: dict[str, Any]) -> None:
    """Populate MCPConfig from dictionary loaded from TOML."""
    server_sec = data.get("server", {})
    if "allowed_roots" in server_sec and isinstance(server_sec["allowed_roots"], list):
        config.allowed_roots = [
            Path(r).expanduser().resolve() for r in server_sec["allowed_roots"] if isinstance(r, str) and r.strip()
        ]
    if "default_timeout" in server_sec and isinstance(server_sec["default_timeout"], (int, float)):
        config.default_timeout = min(MAX_TIMEOUT_SECONDS, max(5.0, float(server_sec["default_timeout"])))
    if "artifacts_dir" in server_sec and isinstance(server_sec["artifacts_dir"], str):
        config.artifacts_dir = Path(server_sec["artifacts_dir"]).expanduser().resolve()

    ai_sec = data.get("reasoning", {})
    if "ollama_url" in ai_sec and isinstance(ai_sec["ollama_url"], str):
        config.ollama_url = ai_sec["ollama_url"].rstrip("/")
    if "model" in ai_sec and isinstance(ai_sec["model"], str):
        config.ollama_model = ai_sec["model"].strip()
    if "mode" in ai_sec and isinstance(ai_sec["mode"], str):
        config.mode = ai_sec["mode"].strip().lower()
