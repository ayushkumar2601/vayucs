from __future__ import annotations
"""Comprehensive test suite for VAYU Skills CLI and animated installer."""

import os
from pathlib import Path
import shutil
import tempfile
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
import pytest

from crs.skills_cli.catalog import (
    fetch_skill_from_git,
    get_bundled_skills,
    search_skills,
    validate_git_url,
)
from crs.skills_cli.installer import (
    get_global_skills_dir,
    get_installed_skills,
    get_project_root,
    get_project_skills_dir,
    install_skill,
    remove_skill,
    validate_skill_name,
)
from crs.skills_cli.models import SkillEntry, SkillMetadata, parse_skill_frontmatter
from crs.skills_cli.ui import should_animate
from crs.vayu import cli, main


@pytest.fixture
def cli_runner():
    """Click CLI testing runner."""
    return CliRunner()


@pytest.fixture
def temp_project(tmp_path):
    """Temporary project fixture mimicking a git-controlled workspace."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname='test-project'\n", encoding="utf-8")
    return tmp_path


def test_frontmatter_parser_valid():
    content = """---
name: sample-skill
description: A sample test skill for verification.
category: Testing
version: 1.2.0
author: Tester
tags:
  - test
  - agent
---
# Sample Skill Instructions
Instructions here.
"""
    meta, body = parse_skill_frontmatter(content)
    assert meta is not None
    assert meta.name == "sample-skill"
    assert meta.description == "A sample test skill for verification."
    assert meta.category == "Testing"
    assert meta.version == "1.2.0"
    assert "test" in meta.tags
    assert "# Sample Skill Instructions" in body


def test_frontmatter_parser_malformed():
    content = "Just plain text without any YAML frontmatter."
    meta, body = parse_skill_frontmatter(content)
    assert meta is None
    assert body == content


def test_bundled_catalog_completeness():
    bundled = get_bundled_skills()
    expected_skills = [
        "security-analysis",
        "secure-code-review",
        "vulnerability-remediation",
        "patch-verification",
        "prompt-injection-defense",
        "sast-workflow",
        "mcp-development",
        "vayu-development",
    ]
    for skill_name in expected_skills:
        assert skill_name in bundled, f"Missing bundled skill: {skill_name}"
        assert bundled[skill_name].is_valid
        assert bundled[skill_name].metadata.description


def test_validate_skill_name():
    assert validate_skill_name("security-analysis")
    assert validate_skill_name("secure_review_1")
    assert not validate_skill_name("../traversal")
    assert not validate_skill_name("skill/nested")
    assert not validate_skill_name("")
    assert not validate_skill_name("a" * 65)


def test_validate_git_url():
    assert validate_git_url("https://github.com/anthropics/skills")
    assert validate_git_url("http://git.internal/repo.git")
    assert validate_git_url("git@github.com:owner/repo.git")
    assert validate_git_url("file:///tmp/repo")
    assert not validate_git_url("https://bad.com; rm -rf /")
    assert not validate_git_url("`curl evil.com`")
    assert not validate_git_url("")


def test_should_animate():
    assert not should_animate(no_animation_flag=True)
    with patch.dict(os.environ, {"NO_COLOR": "1"}):
        assert not should_animate(no_animation_flag=False)
    with patch.dict(os.environ, {"VAYU_NO_ANIMATION": "1"}, clear=False):
        assert not should_animate(no_animation_flag=False)


def test_cli_skills_root_help(cli_runner):
    result = cli_runner.invoke(cli, ["skills"])
    assert result.exit_code == 0
    assert "VAYU SKILLS" in result.output
    assert "Available Commands:" in result.output
    assert "list" in result.output
    assert "add" in result.output


def test_cli_skills_list(cli_runner):
    result = cli_runner.invoke(cli, ["skills", "list"])
    assert result.exit_code == 0
    assert "VAYU Agent Skills Catalog" in result.output
    assert "security-analysis" in result.output
    assert "prompt-injection-defense" in result.output


def test_cli_skills_search(cli_runner):
    result = cli_runner.invoke(cli, ["skills", "search", "prompt"])
    assert result.exit_code == 0
    assert "prompt-injection-defense" in result.output

    # Nonexistent search
    result_none = cli_runner.invoke(cli, ["skills", "search", "xyznonexistentquery"])
    assert result_none.exit_code == 0
    assert "No skills matching query" in result_none.output


def test_cli_skills_info(cli_runner):
    result = cli_runner.invoke(cli, ["skills", "info", "security-analysis"])
    assert result.exit_code == 0
    assert "security-analysis" in result.output
    assert "Category:" in result.output
    assert "SKILL.md Preview" in result.output

    # Nonexistent skill info
    result_none = cli_runner.invoke(cli, ["skills", "info", "nonexistent-skill"])
    assert result_none.exit_code == 1
    assert "Skill 'nonexistent-skill' was not found" in result_none.output


def test_install_and_remove_bundled_skill_project(cli_runner, temp_project):
    skills_dir = temp_project / ".agents" / "skills"
    with patch("crs.skills_cli.commands.get_project_skills_dir", return_value=skills_dir):
        # 1. Add skill
        res = cli_runner.invoke(cli, ["skills", "add", "security-analysis", "--no-animation"])
        assert res.exit_code == 0
        assert "Skill Installed Successfully" in res.output
        installed_skill_md = skills_dir / "security-analysis" / "SKILL.md"
        assert installed_skill_md.is_file()

        # 2. Conflict without --force
        res_conflict = cli_runner.invoke(cli, ["skills", "add", "security-analysis", "--no-animation"])
        assert res_conflict.exit_code == 1
        assert "already installed" in res_conflict.output

        # 3. Overwrite with --force
        res_force = cli_runner.invoke(cli, ["skills", "add", "security-analysis", "--force", "--no-animation"])
        assert res_force.exit_code == 0
        assert "Skill Installed Successfully" in res_force.output

        # 4. Remove skill
        with patch("crs.skills_cli.commands.get_project_skills_dir", return_value=skills_dir):
            res_remove = cli_runner.invoke(cli, ["skills", "remove", "security-analysis"])
            assert res_remove.exit_code == 0
            assert "Removed skill" in res_remove.output
            assert not (skills_dir / "security-analysis").exists()


def test_install_and_remove_bundled_skill_global(cli_runner, tmp_path):
    global_dir = tmp_path / "global_skills"
    with patch("crs.skills_cli.commands.get_global_skills_dir", return_value=global_dir):
        # 1. Add skill globally
        res = cli_runner.invoke(cli, ["skills", "add", "sast-workflow", "--global", "--no-animation"])
        assert res.exit_code == 0
        assert "Skill Installed Successfully" in res.output
        assert (global_dir / "sast-workflow" / "SKILL.md").is_file()

        # 2. Remove skill globally
        res_remove = cli_runner.invoke(cli, ["skills", "remove", "sast-workflow", "--global"])
        assert res_remove.exit_code == 0
        assert not (global_dir / "sast-workflow").exists()


def test_remove_nonexistent_skill(cli_runner, tmp_path):
    skills_dir = tmp_path / ".agents" / "skills"
    skills_dir.mkdir(parents=True)
    with patch("crs.skills_cli.commands.get_project_skills_dir", return_value=skills_dir):
        res = cli_runner.invoke(cli, ["skills", "remove", "unknown-skill"])
        assert res.exit_code == 1
        assert "Skill Not Found" in res.output


def test_install_path_traversal_prevention(tmp_path):
    target_parent = tmp_path / "skills"
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("---\nname: test\ndescription: d\n---\nbody")

    with pytest.raises(ValueError, match="Invalid skill name"):
        install_skill(source, target_parent, skill_name="../../evil")


def test_install_invalid_missing_skill_md_rollback(tmp_path):
    target_parent = tmp_path / "skills"
    source = tmp_path / "invalid_source"
    source.mkdir()
    (source / "README.txt").write_text("Missing SKILL.md")

    with pytest.raises(ValueError, match="Installed skill directory must contain a valid 'SKILL.md'"):
        install_skill(source, target_parent, skill_name="corrupt-skill")

    # Destination should have been rolled back and not exist
    assert not (target_parent / "corrupt-skill").exists()


def test_cli_doctor(cli_runner, temp_project):
    skills_dir = temp_project / ".agents" / "skills"
    skills_dir.mkdir(parents=True)
    with patch("crs.skills_cli.commands.get_project_root", return_value=temp_project):
        with patch("crs.skills_cli.commands.get_project_skills_dir", return_value=skills_dir):
            res = cli_runner.invoke(cli, ["skills", "doctor"])
            assert res.exit_code == 0
            assert "VAYU Skills Diagnostics (Doctor)" in res.output
            assert "PASS" in res.output


def test_fetch_skill_from_git_mock(tmp_path):
    # Create a mock local git repo directory
    mock_repo = tmp_path / "remote_repo"
    skill_dir = mock_repo / "skills" / "mock-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: mock-skill\ndescription: A mock git skill\n---\n# Mock Content",
        encoding="utf-8",
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # Instead of real network clone, copy the mock_repo into the target clone path
        def side_effect(cmd, **kwargs):
            dest = Path(cmd[cmd.index("--depth") + 3])
            shutil.copytree(mock_repo, dest)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect

        found_dir, meta, temp_holder = fetch_skill_from_git(
            "https://github.com/mock/repo", "mock-skill"
        )
        assert meta.name == "mock-skill"
        assert (found_dir / "SKILL.md").is_file()
        if temp_holder:
            temp_holder.cleanup()


def test_cli_default_group_routing(cli_runner):
    # Calling with --help shows general VAYU CLI help with subcommands
    res = cli_runner.invoke(cli, ["--help"])
    assert res.exit_code == 0
    assert "VAYU — Autonomous Cyber Reasoning System" in res.output
    assert "scan" in res.output
    assert "skills" in res.output
