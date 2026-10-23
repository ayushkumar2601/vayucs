from __future__ import annotations
"""Data models and frontmatter parser for VAYU Agent Skills."""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any


@dataclass
class SkillMetadata:
    """Parsed YAML frontmatter and attributes of a SKILL.md file."""

    name: str
    description: str
    version: str = "1.0.0"
    author: str = "VAYU Development Team"
    category: str = "General"
    tags: list[str] = field(default_factory=list)
    raw_frontmatter: dict[str, Any] = field(default_factory=dict)


@dataclass
class SkillEntry:
    """Representation of an available or installed skill."""

    name: str
    path: Path
    source: str  # 'bundled', 'project', 'global', 'git'
    metadata: SkillMetadata
    installed: bool = False
    is_valid: bool = True
    error_message: str | None = None


def parse_skill_frontmatter(content: str) -> tuple[SkillMetadata | None, str]:
    """Parse YAML frontmatter from a SKILL.md string.
    
    Returns (SkillMetadata, body_markdown) or (None, content) on failure.
    """
    pattern = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)
    match = pattern.match(content.strip())
    if not match:
        return None, content

    raw_yaml, body = match.group(1), match.group(2)
    meta_dict: dict[str, Any] = {}

    try:
        try:
            import yaml
            parsed = yaml.safe_load(raw_yaml)
            if isinstance(parsed, dict):
                meta_dict = parsed
        except ImportError:
            from ruamel.yaml import YAML
            import io
            y = YAML(typ="safe")
            parsed = y.load(io.StringIO(raw_yaml))
            if isinstance(parsed, dict):
                meta_dict = dict(parsed)
    except Exception:
        pass

    if not meta_dict:
        current_list_key = None
        for line in raw_yaml.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("- ") and current_list_key:
                meta_dict.setdefault(current_list_key, []).append(stripped[2:].strip().strip("'\""))
                continue
            current_list_key = None
            if ":" in stripped:
                key, val = stripped.split(":", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if not val:
                    current_list_key = key
                    meta_dict[key] = []
                elif val.startswith("[") and val.endswith("]"):
                    items = [i.strip().strip("'\"") for i in val[1:-1].split(",") if i.strip()]
                    meta_dict[key] = items
                else:
                    meta_dict[key] = val

    name = meta_dict.get("name", "")
    description = meta_dict.get("description", "")
    if not name or not description:
        return None, body

    raw_tags = meta_dict.get("tags", [])
    if isinstance(raw_tags, str):
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
    elif isinstance(raw_tags, list):
        tags = [str(t) for t in raw_tags]
    else:
        tags = []

    meta = SkillMetadata(
        name=str(name),
        description=str(description),
        version=str(meta_dict.get("version", "1.0.0")),
        author=str(meta_dict.get("author", "VAYU Development Team")),
        category=str(meta_dict.get("category", "General")),
        tags=tags,
        raw_frontmatter=meta_dict,
    )
    return meta, body
