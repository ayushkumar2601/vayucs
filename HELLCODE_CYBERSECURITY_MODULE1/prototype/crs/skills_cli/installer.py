from __future__ import annotations
"""Installation, removal, and health diagnostics for VAYU Agent Skills."""

import os
from pathlib import Path
import shutil

from crs.skills_cli.models import SkillEntry, SkillMetadata, parse_skill_frontmatter


def get_project_root(start_path: Path | None = None) -> Path:
    """Detect project root by traversing upward for marker files/directories."""
    current = (start_path or Path.cwd()).resolve()
    for parent in [current, *current.parents]:
        if (
            (parent / ".git").exists()
            or (parent / "pyproject.toml").is_file()
            or (parent / ".agents").is_dir()
            or (parent / "package.json").is_file()
        ):
            return parent
    return current


def get_project_skills_dir(start_path: Path | None = None) -> Path:
    """Return standard project-level Agent Skills directory (.agents/skills)."""
    return get_project_root(start_path) / ".agents" / "skills"


def get_global_skills_dir() -> Path:
    """Return user-level global Agent Skills directory."""
    env_dir = os.environ.get("VAYU_GLOBAL_SKILLS_DIR")
    if env_dir:
        return Path(env_dir).expanduser().resolve()

    home = Path.home().resolve()
    # Check Antigravity / Gemini IDE directory first
    gemini_skills = home / ".gemini" / "antigravity-ide" / "skills"
    if (home / ".gemini").is_dir():
        return gemini_skills

    # Fall back to standard XDG / agents location
    return home / ".config" / "agents" / "skills"


def get_installed_skills(
    project_dir: Path | None = None,
    global_dir: Path | None = None,
) -> list[SkillEntry]:
    """Scan and list all installed skills across project and global locations."""
    p_dir = project_dir or get_project_skills_dir()
    g_dir = global_dir or get_global_skills_dir()
    entries: list[SkillEntry] = []

    for base, src in [(p_dir, "project"), (g_dir, "global")]:
        if not base.is_dir():
            continue
        for item in sorted(base.iterdir()):
            if not item.is_dir():
                continue
            skill_md = item / "SKILL.md"
            if not skill_md.is_file():
                entries.append(
                    SkillEntry(
                        name=item.name,
                        path=item,
                        source=src,
                        metadata=SkillMetadata(name=item.name, description="Missing SKILL.md"),
                        installed=True,
                        is_valid=False,
                        error_message="Missing SKILL.md instruction file",
                    )
                )
                continue

            try:
                content = skill_md.read_text(encoding="utf-8")
                meta, _ = parse_skill_frontmatter(content)
                if meta:
                    entries.append(
                        SkillEntry(
                            name=meta.name,
                            path=item,
                            source=src,
                            metadata=meta,
                            installed=True,
                            is_valid=True,
                        )
                    )
                else:
                    entries.append(
                        SkillEntry(
                            name=item.name,
                            path=item,
                            source=src,
                            metadata=SkillMetadata(name=item.name, description="Malformed YAML frontmatter"),
                            installed=True,
                            is_valid=False,
                            error_message="YAML frontmatter missing or invalid",
                        )
                    )
            except Exception as exc:
                entries.append(
                    SkillEntry(
                        name=item.name,
                        path=item,
                        source=src,
                        metadata=SkillMetadata(name=item.name, description=f"Read error: {exc}"),
                        installed=True,
                        is_valid=False,
                        error_message=str(exc),
                    )
                )

    return entries


import re


def validate_skill_name(name: str) -> bool:
    """Validate that a skill name consists of safe alphanumeric characters, dashes, and underscores."""
    if not name or len(name) > 64:
        return False
    return bool(re.match(r"^[a-zA-Z0-9_-]+$", name))


def install_skill(
    source_dir: Path,
    target_parent_dir: Path,
    skill_name: str | None = None,
    force: bool = False,
) -> tuple[Path, int]:
    """Install a skill directory to the target location, preserving existing files unless force=True."""
    name = skill_name or source_dir.name
    if not validate_skill_name(name):
        raise ValueError(
            f"Invalid skill name '{name}'. Skill names may only contain alphanumeric characters, hyphens, and underscores."
        )

    target_parent_dir = target_parent_dir.resolve()
    dest_dir = (target_parent_dir / name).resolve()

    # Prevent path traversal
    if dest_dir.parent != target_parent_dir:
        raise ValueError(f"Target path traversal detected for skill '{name}'.")

    if dest_dir.exists() and not force:
        raise FileExistsError(
            f"Skill '{name}' is already installed at {dest_dir}. Use --force to overwrite."
        )

    target_parent_dir.mkdir(parents=True, exist_ok=True)

    if dest_dir.exists() and force:
        shutil.rmtree(dest_dir)

    shutil.copytree(source_dir, dest_dir)

    skill_file = dest_dir / "SKILL.md"
    if not skill_file.is_file():
        # Rollback copy if invalid
        shutil.rmtree(dest_dir)
        raise ValueError(f"Installed skill directory must contain a valid 'SKILL.md' file.")

    # Count installed files
    file_count = sum(1 for p in dest_dir.rglob("*") if p.is_file())
    return dest_dir, file_count


def remove_skill(skill_name: str, target_parent_dir: Path) -> tuple[Path, int]:
    """Safely remove an installed skill from the specified directory."""
    if not validate_skill_name(skill_name):
        raise ValueError(
            f"Invalid skill name '{skill_name}'. Skill names may only contain alphanumeric characters, hyphens, and underscores."
        )

    target_parent_dir = target_parent_dir.resolve()
    dest_dir = (target_parent_dir / skill_name).resolve()

    # Prevent path traversal
    if dest_dir.parent != target_parent_dir:
        raise ValueError(f"Target path traversal detected for skill '{skill_name}'.")

    if not dest_dir.exists():
        raise FileNotFoundError(
            f"Skill '{skill_name}' is not installed at {dest_dir}."
        )

    file_count = sum(1 for p in dest_dir.rglob("*") if p.is_file())
    shutil.rmtree(dest_dir)
    return dest_dir, file_count
