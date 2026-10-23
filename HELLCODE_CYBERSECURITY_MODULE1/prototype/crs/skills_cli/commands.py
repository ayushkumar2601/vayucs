from __future__ import annotations
"""Click command group implementation for `vayu skills`."""

from pathlib import Path
import sys

import click
from rich.panel import Panel

from crs.skills_cli.catalog import (
    fetch_skill_from_git,
    get_bundled_skills,
    search_skills,
)
from crs.skills_cli.installer import (
    get_global_skills_dir,
    get_installed_skills,
    get_project_root,
    get_project_skills_dir,
    install_skill,
    remove_skill,
)
from crs.skills_cli.models import SkillEntry, parse_skill_frontmatter
from crs.skills_cli.ui import (
    console,
    print_banner,
    render_animated_install,
    render_doctor_table,
    render_install_success_panel,
    render_skill_info,
    render_skills_table,
)


@click.group(
    "skills",
    invoke_without_command=True,
    help="Explore, search, install, and manage VAYU AI Agent Skills.",
)
@click.pass_context
def skills_cli(ctx: click.Context) -> None:
    """VAYU Skills CLI root command."""
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(
            "[bold white]Usage:[/] [orange3]vayu skills[/] [cyan]<command>[/] [dim][options][/]\n"
        )
        console.print("[bold white]Available Commands:[/]")
        console.print("  [cyan]list[/]               List bundled and installed skills")
        console.print("  [cyan]search <query>[/]     Search the skills catalog")
        console.print("  [cyan]add <skill>[/]        Install a skill into your project or globally")
        console.print("  [cyan]remove <skill>[/]     Remove an installed skill")
        console.print("  [cyan]info <skill>[/]       Display metadata and preview for a skill")
        console.print("  [cyan]doctor[/]             Verify skills directory health and diagnostics\n")
        console.print("[bold white]Examples:[/]")
        console.print("  vayu skills add security-analysis")
        console.print("  vayu skills add security-analysis --global")
        console.print("  vayu skills add frontend-design --from https://github.com/anthropics/skills\n")


@skills_cli.command("list", help="List bundled catalog skills and installed project/global skills.")
def list_skills() -> None:
    """List available and installed skills."""
    print_banner()
    bundled = get_bundled_skills()
    installed = get_installed_skills()

    installed_names = {s.name: s for s in installed}
    all_skills = []

    # Add bundled skills (with status if installed)
    for name, b_skill in bundled.items():
        if name in installed_names:
            inst = installed_names[name]
            all_skills.append(
                SkillEntry(
                    name=name,
                    path=inst.path,
                    source=inst.source,
                    metadata=b_skill.metadata,
                    installed=True,
                )
            )
        else:
            all_skills.append(b_skill)

    # Add any external/custom installed skills not in bundled catalog
    for name, inst in installed_names.items():
        if name not in bundled:
            all_skills.append(inst)

    render_skills_table(all_skills, title="VAYU Agent Skills Catalog")


@skills_cli.command("search", help="Search available and installed skills by keyword.")
@click.argument("query")
def search_skills_cmd(query: str) -> None:
    """Search skills by keyword."""
    print_banner()
    bundled = get_bundled_skills()
    installed = get_installed_skills()

    combined = list(bundled.values())
    for inst in installed:
        if inst.name not in bundled:
            combined.append(inst)

    results = search_skills(query, combined)
    if not results:
        console.print(f"[yellow]No skills matching query '[/][bold white]{query}[/][yellow]'.[/]")
        sys.exit(0)

    render_skills_table(results, title=f"Search Results for '{query}'")


@skills_cli.command("add", help="Install a skill into your project or global environment.")
@click.argument("skill_name")
@click.option("--project", "scope_project", is_flag=True, default=True, help="Install into current project (.agents/skills) [default]")
@click.option("--global", "scope_global", is_flag=True, default=False, help="Install into global user directory")
@click.option("--from", "from_repo", type=str, default=None, help="Install skill from remote Git repository URL")
@click.option("--force", "-f", is_flag=True, default=False, help="Overwrite skill if already installed")
@click.option("--no-animation", is_flag=True, default=False, help="Disable step progress animation")
def add_skill(
    skill_name: str,
    scope_project: bool,
    scope_global: bool,
    from_repo: str | None,
    force: bool,
    no_animation: bool,
) -> None:
    """Install a skill into project or global skills directory."""
    print_banner()

    # Determine destination directory
    is_global = scope_global
    target_parent = get_global_skills_dir() if is_global else get_project_skills_dir()
    scope_str = "global" if is_global else "project"

    git_cleanup_holder = None
    source_dir = None

    try:
        if from_repo:
            console.print(f"[dim orange3]◆[/] Cloning external repository: [cyan]{from_repo}[/]...")
            source_dir, meta, git_cleanup_holder = fetch_skill_from_git(from_repo, skill_name)
        else:
            bundled = get_bundled_skills()
            if skill_name not in bundled:
                console.print(
                    Panel(
                        f"[bold red]Error:[/] Skill '[cyan]{skill_name}[/]' is not available in the bundled catalog.\n"
                        f"Run [bold orange3]vayu skills list[/] or [bold orange3]vayu skills search[/] to see available skills.\n"
                        f"Or install from Git via: [dim]vayu skills add {skill_name} --from <git-url>[/]",
                        title="[bold red]Skill Not Found[/]",
                        border_style="red",
                    )
                )
                sys.exit(1)
            source_dir = bundled[skill_name].path

        # Perform animated installation
        def do_install() -> tuple[Path, int]:
            return install_skill(source_dir, target_parent, skill_name=skill_name, force=force)

        dest_path, file_count = render_animated_install(skill_name, do_install, no_animation=no_animation)
        render_install_success_panel(skill_name, str(dest_path), file_count, scope=scope_str)

    except FileExistsError as exc:
        console.print(
            Panel(
                f"[bold yellow]Conflict:[/] {str(exc)}\n\n"
                f"To overwrite the existing installation, run:\n"
                f"  [bold orange3]vayu skills add {skill_name} {'--global' if is_global else ''} --force[/]",
                title="[bold yellow]Skill Already Installed[/]",
                border_style="yellow",
            )
        )
        sys.exit(1)
    except Exception as exc:
        console.print(
            Panel(
                f"[bold red]Installation Error:[/] {str(exc)}",
                title="[bold red]Failed to Install Skill[/]",
                border_style="red",
            )
        )
        sys.exit(1)
    finally:
        if git_cleanup_holder:
            git_cleanup_holder.cleanup()


@skills_cli.command("remove", help="Remove an installed skill from your project or global environment.")
@click.argument("skill_name")
@click.option("--project", "scope_project", is_flag=True, default=True, help="Remove from current project (.agents/skills) [default]")
@click.option("--global", "scope_global", is_flag=True, default=False, help="Remove from global user directory")
def remove_skill_cmd(skill_name: str, scope_project: bool, scope_global: bool) -> None:
    """Remove an installed skill."""
    print_banner()
    is_global = scope_global
    target_parent = get_global_skills_dir() if is_global else get_project_skills_dir()
    scope_str = "global" if is_global else "project"

    try:
        dest_path, file_count = remove_skill(skill_name, target_parent)
        console.print(
            Panel(
                f"[bold green]✓[/] Removed skill '[bold cyan]{skill_name}[/]' from {scope_str} location.\n"
                f"[dim]Unlinked: {dest_path} ({file_count} files removed)[/]",
                title="[bold green]Skill Removed[/]",
                border_style="green",
            )
        )
    except FileNotFoundError as exc:
        console.print(
            Panel(
                f"[bold yellow]Warning:[/] {str(exc)}",
                title="[bold yellow]Skill Not Found[/]",
                border_style="yellow",
            )
        )
        sys.exit(1)
    except Exception as exc:
        console.print(
            Panel(f"[bold red]Error:[/] {str(exc)}", title="[bold red]Removal Failed[/]", border_style="red")
        )
        sys.exit(1)


@skills_cli.command("info", help="Display metadata and instructions preview for a skill.")
@click.argument("skill_name")
def info_skill_cmd(skill_name: str) -> None:
    """Display information about a skill."""
    print_banner()
    bundled = get_bundled_skills()
    installed = {s.name: s for s in get_installed_skills()}

    entry = installed.get(skill_name) or bundled.get(skill_name)
    if not entry:
        console.print(
            Panel(
                f"[bold red]Error:[/] Skill '[cyan]{skill_name}[/]' was not found in installed skills or bundled catalog.",
                title="[bold red]Skill Not Found[/]",
                border_style="red",
            )
        )
        sys.exit(1)

    render_skill_info(entry)


@skills_cli.command("doctor", help="Diagnose skills directory health, permissions, and metadata.")
def doctor_cmd() -> None:
    """Run diagnostics on skills directories and installed skills."""
    print_banner()
    checks = []

    # 1. Project Root Check
    p_root = get_project_root()
    checks.append({
        "name": "Project Root Detection",
        "passed": p_root.is_dir(),
        "details": f"Detected project root at {p_root}",
    })

    # 2. Project Skills Directory Check
    p_skills = get_project_skills_dir()
    p_exists = p_skills.is_dir()
    checks.append({
        "name": "Project Skills Directory",
        "passed": True,  # Non-fatal if not created yet
        "details": f"{p_skills} ({'Exists' if p_exists else 'Not created yet; will be created on first add'})",
    })

    # 3. Global Skills Directory Check
    g_skills = get_global_skills_dir()
    g_exists = g_skills.is_dir()
    checks.append({
        "name": "Global Skills Directory",
        "passed": True,
        "details": f"{g_skills} ({'Exists' if g_exists else 'Will be created when using --global'})",
    })

    # 4. Bundled Catalog Integrity Check
    bundled = get_bundled_skills()
    checks.append({
        "name": "Bundled Catalog Health",
        "passed": len(bundled) >= 8,
        "details": f"Found {len(bundled)} valid bundled skills in catalog",
    })

    # 5. Installed Skills Validation
    installed = get_installed_skills()
    corrupt_skills = [s for s in installed if not s.is_valid]
    if corrupt_skills:
        for cs in corrupt_skills:
            checks.append({
                "name": f"Installed Skill: {cs.name}",
                "passed": False,
                "details": f"Corrupt: {cs.error_message}",
            })
    else:
        checks.append({
            "name": "Installed Skills Validation",
            "passed": True,
            "details": f"Validated {len(installed)} installed skill(s); zero corruption detected",
        })

    render_doctor_table(checks)
