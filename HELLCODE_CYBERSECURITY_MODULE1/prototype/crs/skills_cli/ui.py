from __future__ import annotations
"""Terminal UI, ASCII banners, and animated progress rendering for VAYU Skills CLI."""

import os
import sys
import time
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from crs.skills_cli.models import SkillEntry, SkillMetadata

console = Console()

VAYU_SKILLS_BANNER = """[bold orange3]
██╗   ██╗ █████╗ ██╗   ██╗██╗   ██╗
██║   ██║██╔══██╗╚██╗ ██╔╝██║   ██║
██║   ██║███████║ ╚████╔╝ ██║   ██║
╚██╗ ██╔╝██╔══██║  ╚██╔╝  ██║   ██║
 ╚████╔╝ ██║  ██║   ██║   ╚██████╔╝
  ╚═══╝  ╚═╝  ╚═╝   ╚═╝    ╚═════╝ 

   ███████╗██╗  ██╗██╗██╗     ██╗     ███████╗
   ██╔════╝██║ ██╔╝██║██║     ██║     ██╔════╝
   ███████╗█████╔╝ ██║██║     ██║     ███████╗
   ╚════██║██╔═██╗ ██║██║     ██║     ╚════██║
   ███████║██║  ██╗██║███████╗███████╗███████║
   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝
[/bold orange3]
[bold white]VAYU SKILLS[/bold white] [dim orange3]— Autonomous Cyber Reasoning System Agent Skills Engine[/dim orange3]
"""


def should_animate(no_animation_flag: bool = False) -> bool:
    """Determine if animations should run based on TTY status and environment."""
    if no_animation_flag:
        return False
    if os.environ.get("NO_COLOR") or os.environ.get("VAYU_NO_ANIMATION"):
        return False
    return sys.stdout.isatty()


def print_banner() -> None:
    """Print the official VAYU SKILLS full branding banner."""
    console.print(VAYU_SKILLS_BANNER)


def render_animated_install(
    skill_name: str,
    install_fn: Any,
    no_animation: bool = False,
) -> tuple[Any, int]:
    """Execute skill installation with an animated step-by-step progress sequence."""
    animate = should_animate(no_animation)
    steps = [
        f"Resolving skill: [bold cyan]{skill_name}[/]",
        "Checking skill metadata and frontmatter",
        "Preparing target installation directory",
        "Installing SKILL.md and reference assets",
        "Validating installed skill structure",
    ]

    dest_path = None
    file_count = 0

    if animate:
        with Progress(
            SpinnerColumn(style="orange3"),
            TextColumn("[orange3]{task.description}[/]"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(steps[0], total=None)
            time.sleep(0.12)

            for step in steps[1:]:
                progress.update(task, description=step)
                time.sleep(0.12)

            # Perform actual installation
            dest_path, file_count = install_fn()
    else:
        for step in steps:
            console.print(f"[dim orange3]◆[/] {step}")
        dest_path, file_count = install_fn()

    return dest_path, file_count


def render_install_success_panel(
    skill_name: str,
    dest_path: str,
    file_count: int,
    scope: str = "project",
) -> None:
    """Display the polished completion panel for an installed skill."""
    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_column("Key", style="bold white", width=14)
    table.add_column("Value")

    table.add_row("Name:", f"[bold cyan]{skill_name}[/]")
    table.add_row("Location:", f"[dim]{dest_path}[/]")
    table.add_row("Files:", f"[bold green]{file_count}[/]")
    table.add_row("Scope:", f"[{'green' if scope == 'project' else 'yellow'}]{scope.capitalize()}[/]")
    table.add_row("Status:", "[bold green]✓ READY[/]")

    panel = Panel(
        Group(
            table,
            Text(""),
            Text("Next Step:", style="bold white"),
            Text(
                "Open your AI coding client (Antigravity IDE, Claude, Cursor) to use the installed skill.",
                style="dim",
            ),
        ),
        title="[bold green]✓ Skill Installed Successfully[/]",
        border_style="green",
    )
    console.print(panel)


def render_skills_table(skills: list[SkillEntry], title: str = "Available Skills") -> None:
    """Render a formatted table of skills."""
    table = Table(
        title=f"[bold orange3]{title} ({len(skills)} Total)[/]",
        box=box.ROUNDED,
        border_style="orange3",
        header_style="bold white",
    )
    table.add_column("Skill Name", style="bold cyan", no_wrap=True)
    table.add_column("Category", style="yellow")
    table.add_column("Description", style="dim white")
    table.add_column("Scope / Source", justify="center")
    table.add_column("Status", justify="right")

    for s in skills:
        meta = s.metadata
        scope_str = s.source.capitalize()
        status_str = "[bold green]Installed[/]" if s.installed else "[dim]Available[/]"
        if not s.is_valid:
            status_str = f"[bold red]Error[/]"

        table.add_row(
            s.name,
            meta.category,
            meta.description[:60] + ("..." if len(meta.description) > 60 else ""),
            scope_str,
            status_str,
        )

    console.print(table)


def render_skill_info(entry: SkillEntry) -> None:
    """Display detailed information about a single skill."""
    meta = entry.metadata
    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_column("Key", style="bold white", width=16)
    table.add_column("Value")

    table.add_row("Name:", f"[bold cyan]{entry.name}[/]")
    table.add_row("Category:", f"[yellow]{meta.category}[/]")
    table.add_row("Version:", f"[dim]{meta.version}[/]")
    table.add_row("Author:", f"[dim]{meta.author}[/]")
    table.add_row("Source:", f"[green]{entry.source.capitalize()}[/]")
    table.add_row("Path:", f"[dim]{entry.path}[/]")
    table.add_row(
        "Status:",
        "[bold green]Installed[/]" if entry.installed else "[dim orange3]Available in Catalog[/]",
    )

    content_preview = ""
    skill_file = entry.path / "SKILL.md"
    if skill_file.is_file():
        try:
            raw = skill_file.read_text(encoding="utf-8")
            # Strip frontmatter
            if raw.startswith("---"):
                parts = raw.split("---", 2)
                if len(parts) >= 3:
                    content_preview = parts[2].strip()[:350] + "..."
            else:
                content_preview = raw[:350] + "..."
        except Exception:
            content_preview = "(Could not read preview)"

    elements = [table]
    if meta.description:
        elements.extend([Text(""), Text(f"Description:\n{meta.description}", style="white")])
    if content_preview:
        preview_panel = Panel(
            Text(content_preview, style="dim white"),
            title="[dim]SKILL.md Preview[/]",
            border_style="dim",
        )
        elements.extend([Text(""), preview_panel])

    panel = Panel(
        Group(*elements),
        title=f"[bold orange3]VAYU Skill: {entry.name}[/]",
        border_style="orange3",
    )
    console.print(panel)


def render_doctor_table(checks: list[dict[str, Any]]) -> None:
    """Display VAYU Skills Doctor health diagnostics table."""
    table = Table(
        title="[bold orange3]VAYU Skills Diagnostics (Doctor)[/]",
        box=box.ROUNDED,
        border_style="orange3",
        header_style="bold white",
    )
    table.add_column("Check", style="bold white", width=28)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Details", style="dim white")

    for c in checks:
        status = "[bold green]✓ PASS[/]" if c["passed"] else "[bold red]✗ FAIL[/]"
        table.add_row(c["name"], status, c["details"])

    console.print(table)
