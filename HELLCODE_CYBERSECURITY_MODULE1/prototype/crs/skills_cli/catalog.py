from __future__ import annotations
"""Catalog discovery and Git repository fetching for VAYU skills."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from crs.skills_cli.models import SkillEntry, SkillMetadata, parse_skill_frontmatter

BUNDLED_CATALOG_DIR = Path(__file__).resolve().parents[1] / "skills_catalog"


def get_bundled_skills(catalog_dir: Path | None = None) -> dict[str, SkillEntry]:
    """Discover all bundled skills included with VAYU."""
    base = catalog_dir or BUNDLED_CATALOG_DIR
    skills: dict[str, SkillEntry] = {}
    if not base.is_dir():
        return skills

    for item in sorted(base.iterdir()):
        if not item.is_dir():
            continue
        skill_file = item / "SKILL.md"
        if not skill_file.is_file():
            continue

        try:
            content = skill_file.read_text(encoding="utf-8")
            meta, _ = parse_skill_frontmatter(content)
            if meta:
                entry = SkillEntry(
                    name=meta.name,
                    path=item,
                    source="bundled",
                    metadata=meta,
                    installed=False,
                    is_valid=True,
                )
                skills[meta.name] = entry
        except Exception as exc:
            skills[item.name] = SkillEntry(
                name=item.name,
                path=item,
                source="bundled",
                metadata=SkillMetadata(name=item.name, description=f"Corrupt skill file: {exc}"),
                is_valid=False,
                error_message=str(exc),
            )

    return skills


def search_skills(query: str, entries: list[SkillEntry]) -> list[SkillEntry]:
    """Search skills by name, description, category, or tags with token and prefix matching."""
    q = query.strip().lower()
    if not q:
        return entries

    query_tokens = [t for t in re.split(r"[\s\-_]+", q) if t]
    matches = []
    for entry in entries:
        meta = entry.metadata
        haystack = f"{entry.name} {meta.description} {meta.category} {' '.join(meta.tags)}".lower()
        if q in haystack:
            matches.append(entry)
            continue

        haystack_tokens = [t for t in re.split(r"[\s\-_/]+", haystack) if t]
        matched = False
        for qt in query_tokens:
            stem = qt[:-1] if qt.endswith(('e', 's', 'y', 'd')) and len(qt) > 4 else qt
            for ht in haystack_tokens:
                if ht.startswith(stem) or (len(ht) >= 4 and stem.startswith(ht[:4])):
                    matched = True
                    break
            if matched:
                break
        if matched:
            matches.append(entry)

    return matches


def validate_git_url(url: str) -> bool:
    """Check that a Git URL matches safe protocols and contains no shell metacharacters."""
    clean = url.strip()
    if not clean or any(c in clean for c in ";|&$`\n\r\t\"'"):
        return False
    if (
        clean.startswith("https://")
        or clean.startswith("http://")
        or clean.startswith("git@")
        or clean.startswith("file://")
    ):
        return True
    if Path(clean).is_dir():
        return True
    return False


def fetch_skill_from_git(repo_url: str, skill_name: str, target_temp_dir: Path | None = None) -> tuple[Path, SkillMetadata, tempfile.TemporaryDirectory | None]:
    """Clone an external Git repository shallowly and locate the requested skill directory."""
    if not validate_git_url(repo_url):
        raise ValueError(f"Invalid or unsafe Git repository URL: '{repo_url}'")

    temp_holder = None
    if target_temp_dir:
        clone_root = target_temp_dir
    else:
        temp_holder = tempfile.TemporaryDirectory(prefix="vayu-skill-git-")
        clone_root = Path(temp_holder.name)

    repo_dir = clone_root / "repo"

    try:
        res = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(repo_dir)],
            capture_output=True,
            text=True,
            timeout=45.0,
            shell=False,
            check=False,
        )
        if res.returncode != 0:
            raise RuntimeError(f"Git clone failed: {res.stderr.strip() or res.stdout.strip()}")

        # Locate skill directory by candidate locations
        candidates = [
            repo_dir / "skills" / skill_name,
            repo_dir / skill_name,
            repo_dir / ".agents" / "skills" / skill_name,
        ]
        
        # Also search recursively for any directory matching skill_name that contains SKILL.md
        found_dir = None
        for cand in candidates:
            if cand.is_dir() and (cand / "SKILL.md").is_file():
                found_dir = cand
                break

        if not found_dir:
            for p in repo_dir.rglob(f"**/{skill_name}"):
                if p.is_dir() and (p / "SKILL.md").is_file():
                    found_dir = p
                    break

        if not found_dir:
            raise FileNotFoundError(
                f"Skill '{skill_name}' containing a valid SKILL.md was not found in repository {repo_url}"
            )

        skill_md = found_dir / "SKILL.md"
        content = skill_md.read_text(encoding="utf-8")
        meta, _ = parse_skill_frontmatter(content)
        if not meta:
            raise ValueError(f"Skill '{skill_name}' contains an invalid SKILL.md without YAML frontmatter.")

        return found_dir, meta, temp_holder

    except Exception:
        if temp_holder:
            temp_holder.cleanup()
        raise
