from __future__ import annotations
"""Unit & Integration tests for DigitalOcean Cloud Sandboxing in VAYU CRS."""

import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from crs.core.schemas import PatchProposal, Severity, VulnerabilityFinding
from crs.verification.cloud.do_config import DigitalOceanConfig
from crs.verification.cloud.do_client import DigitalOceanClient, DigitalOceanError
from crs.verification.cloud.ssh_tunnel import generate_ephemeral_ssh_keypair
from crs.verification.cloud.do_workspace import DigitalOceanSandboxWorkspace
from crs.verification.verification_engine import VerificationEngine
from crs.verification.remote_runner import run_remote_verification


def test_do_config_defaults(monkeypatch):
    monkeypatch.delenv("DO_API_TOKEN", raising=False)
    monkeypatch.delenv("DIGITALOCEAN_TOKEN", raising=False)
    monkeypatch.delenv("DO_REGION", raising=False)
    monkeypatch.delenv("DO_SIZE", raising=False)

    cfg = DigitalOceanConfig.from_env()
    assert cfg.token == ""
    assert cfg.region == "nyc3"
    assert cfg.size == "s-1vcpu-1gb"
    assert cfg.image == "ubuntu-24-04-x64"
    assert cfg.safety_ttl_minutes == 10
    assert not cfg.is_configured()


def test_do_config_from_env(monkeypatch):
    monkeypatch.setenv("DIGITALOCEAN_TOKEN", "dop_v1_mock_test_token")
    monkeypatch.setenv("DO_REGION", "sfo3")
    monkeypatch.setenv("DO_SIZE", "s-2vcpu-2gb")
    monkeypatch.setenv("DO_SAFETY_TTL_MINUTES", "15")

    cfg = DigitalOceanConfig.from_env()
    assert cfg.token == "dop_v1_mock_test_token"
    assert cfg.region == "sfo3"
    assert cfg.size == "s-2vcpu-2gb"
    assert cfg.safety_ttl_minutes == 15
    assert cfg.is_configured()
    cfg.validate()  # Should not raise


def test_do_config_validate_raises_on_missing_token(monkeypatch):
    monkeypatch.delenv("DO_API_TOKEN", raising=False)
    monkeypatch.delenv("DIGITALOCEAN_TOKEN", raising=False)

    cfg = DigitalOceanConfig.from_env()
    with pytest.raises(ValueError, match="DigitalOcean API token is not configured"):
        cfg.validate()


def test_ephemeral_ssh_keypair_generation():
    private_pem, public_ssh = generate_ephemeral_ssh_keypair()
    assert "BEGIN OPENSSH PRIVATE KEY" in private_pem
    assert public_ssh.startswith("ssh-ed25519")
    assert "vayu-ephemeral-sandbox" in public_ssh


def test_do_client_create_droplet_request():
    cfg = DigitalOceanConfig(token="test-token")
    client = DigitalOceanClient(cfg)

    mock_resp = io.BytesIO(json.dumps({
        "droplet": {
            "id": 998877,
            "name": "vayu-sandbox-test",
            "status": "new",
        }
    }).encode("utf-8"))
    mock_resp.status = 202

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        result = client.create_droplet(
            name="vayu-sandbox-test",
            size="s-1vcpu-1gb",
            region="nyc3",
            image="ubuntu-24-04-x64",
            ssh_keys=[12345],
        )

        assert result["id"] == 998877
        assert mock_urlopen.called
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer test-token"
        assert req.get_method() == "POST"


def test_do_client_wait_for_active():
    cfg = DigitalOceanConfig(token="test-token")
    client = DigitalOceanClient(cfg)

    resp_pending = io.BytesIO(json.dumps({
        "droplet": {"id": 111, "status": "active", "networks": {"v4": []}}
    }).encode("utf-8"))
    resp_pending.status = 200

    resp_active = io.BytesIO(json.dumps({
        "droplet": {
            "id": 111,
            "status": "active",
            "networks": {"v4": [{"type": "public", "ip_address": "159.203.88.99"}]},
        }
    }).encode("utf-8"))
    resp_active.status = 200

    with patch("urllib.request.urlopen", side_effect=[resp_pending, resp_active]):
        with patch("time.sleep", return_value=None):
            active = client.wait_for_active(111, poll_interval=0.01, max_wait=5.0)
            assert active["id"] == 111
            assert client.extract_public_ipv4(active) == "159.203.88.99"


def test_do_client_destroy_droplet_success_and_404():
    cfg = DigitalOceanConfig(token="test-token")
    client = DigitalOceanClient(cfg)

    # 1. 204 No Content
    mock_204 = io.BytesIO(b"")
    mock_204.status = 204
    with patch("urllib.request.urlopen", return_value=mock_204):
        assert client.destroy_droplet(111) is True

    # 2. 404 Not Found (already destroyed) -> should return True idempotently
    err_404 = urllib.error.HTTPError("url", 404, "Not Found", {}, io.BytesIO(b"Not Found"))
    with patch("urllib.request.urlopen", side_effect=err_404):
        assert client.destroy_droplet(111) is True


def test_do_workspace_guaranteed_cleanup(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')", encoding="utf-8")

    cfg = DigitalOceanConfig(token="test-token")
    mock_client = MagicMock()
    mock_client.add_ssh_key.return_value = {"id": 555}
    mock_client.create_droplet.return_value = {"id": 777}
    mock_client.wait_for_active.return_value = {
        "id": 777,
        "status": "active",
        "networks": {"v4": [{"type": "public", "ip_address": "10.0.0.1"}]},
    }
    mock_client.extract_public_ipv4.return_value = "10.0.0.1"
    mock_client.destroy_droplet.return_value = True
    mock_client.delete_ssh_key.return_value = True

    status_events = []

    # Verify context manager lifecycle and guaranteed exit
    with patch("crs.verification.cloud.do_workspace.SSHTunnel") as mock_tunnel_cls:
        mock_tunnel = MagicMock()
        mock_tunnel_cls.return_value = mock_tunnel

        workspace = DigitalOceanSandboxWorkspace(
            str(repo),
            config=cfg,
            client=mock_client,
            on_status=lambda s: status_events.append(s),
        )

        with workspace:
            assert workspace.droplet_id == 777
            assert workspace.ssh_key_id == 555
            assert workspace.droplet_ip == "10.0.0.1"
            assert workspace.path is not None
            assert (workspace.path / "app.py").exists()

        # After __exit__, droplet and ssh key MUST be destroyed
        mock_client.destroy_droplet.assert_called_once_with(777)
        mock_client.delete_ssh_key.assert_called_once_with(555)
        assert workspace.path is None


def test_verification_engine_with_sandbox_provider(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import subprocess\nsubprocess.run(['echo', 'safe'])", encoding="utf-8")

    finding = VulnerabilityFinding(
        finding_id="FIND-01",
        title="OS Command Injection",
        vulnerability_type="Command Injection",
        severity=Severity.HIGH,
        confidence=0.9,
        file="app.py",
        line_start=1,
        evidence=[],
    )
    patch = PatchProposal(
        finding_id="FIND-01",
        target_file="app.py",
        rationale="Fix command injection",
        unified_diff="--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n-import subprocess\n+import subprocess\n subprocess.run(['echo', 'safe'])\n",
        expected_security_effect="Safe",
        confidence=1.0,
    )

    verifier = VerificationEngine(sandbox_provider="local")
    result = verifier.verify(str(repo), finding, patch)

    assert result.approved is True
    assert result.sandbox_provider == "local"
    assert "in isolated workspace" in result.reason
