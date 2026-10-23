from __future__ import annotations
import os
from pathlib import Path
import pytest

from vayu_mcp.config import (
    MCPConfig,
    SecurityBoundaryError,
    load_mcp_config,
)


def test_default_config():
    config = MCPConfig()
    assert config.default_timeout == 60.0
    assert config.ollama_url == "http://127.0.0.1:11434"
    assert config.mode == "auto"


def test_load_mcp_config_with_env(monkeypatch, tmp_path):
    monkeypatch.setenv("VAYU_ALLOWED_ROOTS", f"{tmp_path}")
    monkeypatch.setenv("AIKAVACH_OLLAMA_URL", "http://localhost:11434/")
    monkeypatch.setenv("AIKAVACH_OLLAMA_MODEL", "qwen2.5-coder:7b-instruct")
    monkeypatch.setenv("VAYU_MCP_MODE", "offline")
    monkeypatch.setenv("VAYU_TIMEOUT", "45")

    config = load_mcp_config()
    assert config.ollama_url == "http://localhost:11434"
    assert config.ollama_model == "qwen2.5-coder:7b-instruct"
    assert config.mode == "offline"
    assert config.default_timeout == 45.0
    assert any(tmp_path.resolve() == r.resolve() for r in config.allowed_roots)


def test_validate_target_path_success(tmp_path):
    repo = tmp_path / "my_repo"
    repo.mkdir()
    config = MCPConfig(allowed_roots=[tmp_path])

    resolved = config.validate_target_path(str(repo))
    assert resolved == repo.resolve()


def test_validate_target_path_traversal_rejection(tmp_path):
    repo = tmp_path / "allowed_repo"
    repo.mkdir()
    outside = tmp_path.parent / "outside_secret"
    config = MCPConfig(allowed_roots=[repo])

    with pytest.raises(SecurityBoundaryError, match="outside authorized workspace roots"):
        config.validate_target_path(str(tmp_path.parent))


def test_validate_target_path_nonexistent(tmp_path):
    config = MCPConfig(allowed_roots=[tmp_path])
    with pytest.raises(FileNotFoundError):
        config.validate_target_path(str(tmp_path / "does_not_exist"))


def test_validate_target_path_not_directory(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("hello")
    config = MCPConfig(allowed_roots=[tmp_path])
    with pytest.raises(NotADirectoryError):
        config.validate_target_path(str(f))


def test_validate_target_path_null_byte():
    config = MCPConfig()
    with pytest.raises(SecurityBoundaryError, match="null bytes"):
        config.validate_target_path("repo\x00escape")


def test_validate_output_path_success(tmp_path):
    config = MCPConfig(allowed_roots=[tmp_path], artifacts_dir=tmp_path / "artifacts")
    config.artifacts_dir.mkdir(parents=True, exist_ok=True)

    dest = config.artifacts_dir / "report.sarif"
    validated = config.validate_output_path(str(dest))
    assert validated == dest.resolve()


def test_validate_output_path_protected_file(tmp_path):
    config = MCPConfig(allowed_roots=[tmp_path])
    with pytest.raises(SecurityBoundaryError, match="protected project configuration file"):
        config.validate_output_path(str(tmp_path / "pyproject.toml"))
