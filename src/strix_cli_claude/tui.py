"""TUI for managing Strix scans - Professional Edition."""

import os
import platform
import shutil
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule
from rich.style import Style
from rich import box

from . import scan_manager

# Version
__version__ = "0.1.0"

# Initialize console with force_terminal for better compatibility
console = Console(force_terminal=True)

# ═══════════════════════════════════════════════════════════════════════════════
# THEME & STYLES
# ═══════════════════════════════════════════════════════════════════════════════

class Theme:
    """Clean, professional color theme inspired by k3s."""
    # Primary colors
    PRIMARY = "cyan"
    SECONDARY = "blue"
    ACCENT = "yellow"

    # Status colors
    SUCCESS = "green"
    WARNING = "yellow"
    ERROR = "red"
    MUTED = "dim white"

    # UI colors
    BORDER = "bright_black"
    HEADER_BG = "on rgb(25,25,35)"
    FOOTER_BG = "on rgb(20,40,60)"

    # Styles
    TITLE = Style(color="cyan", bold=True)
    SUBTITLE = Style(color="white", dim=True)
    KEY = Style(color="cyan", bold=True)
    VALUE = Style(color="white")
    RUNNING = Style(color="green", bold=True)
    STOPPED = Style(color="white", dim=True)


# ═══════════════════════════════════════════════════════════════════════════════
# ASCII ART BANNER
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = """[cyan]
   _____ _______ _____  _______   __
  / ____|__   __|  __ \|_   _\ \ / /
 | (___    | |  | |__) | | |  \ V /
  \___ \   | |  |  _  /  | |   > <
  ____) |  | |  | | \ \ _| |_ / . \
 |_____/   |_|  |_|  \_\_____/_/ \_\\
[/cyan]"""

BANNER_MINI = "[cyan bold]▸ STRIX[/cyan bold]"

TAGLINE = "[dim]AI-Powered Penetration Testing[/dim]"


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def get_terminal_width() -> int:
    """Get terminal width, with fallback."""
    try:
        return console.width
    except Exception:
        return 80


def format_time_ago(iso_time: str) -> str:
    """Format time as human-readable 'X ago'."""
    try:
        dt = datetime.fromisoformat(iso_time)
        delta = datetime.now() - dt
        seconds = delta.total_seconds()

        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds / 60)}m"
        elif seconds < 86400:
            return f"{int(seconds / 3600)}h"
        else:
            days = int(seconds / 86400)
            return f"{days}d"
    except Exception:
        return "-"


def get_status_indicator(is_running: bool) -> str:
    """Get a visual status indicator."""
    if is_running:
        return "[green]●[/green]"
    return "[dim]○[/dim]"


def get_system_info() -> dict:
    """Get system information for display."""
    return {
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.system(),
        "screen": "✓" if shutil.which("screen") else "✗",
        "docker": "✓" if shutil.which("docker") else "✗",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# UI COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════

def render_header(show_banner: bool = True) -> Panel:
    """Render the application header."""
    width = get_terminal_width()

    if show_banner and width >= 60:
        content = Group(
            Text.from_markup(BANNER),
            Text.from_markup(f"\n{TAGLINE}  [dim]v{__version__}[/dim]"),
        )
    else:
        content = Group(
            Text.from_markup(f"{BANNER_MINI} {TAGLINE}  [dim]v{__version__}[/dim]"),
        )

    return Panel(
        Align.center(content),
        box=box.HEAVY,
        border_style="cyan",
        padding=(0, 2),
    )


def render_status_bar(scans: list[dict]) -> Panel:
    """Render the status bar with scan statistics."""
    running = len([s for s in scans if s.get("is_running")])
    total = len(scans)

    # Create status items
    items = []

    # Running indicator
    if running > 0:
        items.append(f"[green bold]● {running} RUNNING[/green bold]")
    else:
        items.append(f"[dim]○ 0 running[/dim]")

    items.append("[dim]│[/dim]")
    items.append(f"[white]{total} total scans[/white]")
    items.append("[dim]│[/dim]")

    # System status
    sys_info = get_system_info()
    items.append(f"[dim]screen {sys_info['screen']}[/dim]")
    items.append(f"[dim]docker {sys_info['docker']}[/dim]")

    status_text = Text.from_markup("  ".join(items))

    return Panel(
        Align.center(status_text),
        box=box.ROUNDED,
        border_style="bright_black",
        padding=(0, 1),
    )


def render_scans_table(scans: list[dict]) -> Table:
    """Render a clean, professional scans table."""
    table = Table(
        box=box.SIMPLE_HEAD,
        expand=True,
        show_edge=False,
        header_style="bold cyan",
        row_styles=["", "dim"],
    )

    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("", width=2)  # Status indicator
    table.add_column("SCAN ID", style="cyan", width=12)
    table.add_column("MODE", width=10, justify="center")
    table.add_column("TARGETS", style="white", ratio=1)
    table.add_column("STARTED", width=10, justify="right")
    table.add_column("REPORT", style="dim", width=25)

    for idx, scan in enumerate(scans, 1):
        is_running = scan.get("is_running", False)
        status = get_status_indicator(is_running)

        # Format mode with color
        mode = scan.get("scan_mode", "")
        if mode == "deep":
            mode_display = "[red bold]DEEP[/red bold]"
        elif mode == "standard":
            mode_display = "[yellow]STANDARD[/yellow]"
        else:
            mode_display = "[dim]QUICK[/dim]"

        # Truncate targets
        targets = ", ".join(scan.get("targets", []))
        if len(targets) > 35:
            targets = targets[:32] + "..."

        # Format time
        started = format_time_ago(scan.get("started_at", ""))

        # Report filename
        report = Path(scan.get("output_file", "")).name
        if len(report) > 23:
            report = report[:20] + "..."

        table.add_row(
            str(idx),
            status,
            scan.get("scan_id", "")[:10],
            mode_display,
            targets,
            started,
            report,
        )

    return table


def render_empty_state() -> Panel:
    """Render empty state when no scans exist."""
    content = Group(
        Text(""),
        Text("No scans yet", style="dim", justify="center"),
        Text(""),
        Text.from_markup("[cyan]n[/cyan] to start a new scan", justify="center"),
        Text(""),
    )

    return Panel(
        Align.center(content),
        box=box.ROUNDED,
        border_style="bright_black",
        padding=(1, 2),
    )


def render_footer() -> Panel:
    """Render the command footer."""
    # Build command hints
    commands = [
        ("[cyan]n[/cyan]", "new"),
        ("[cyan]a[/cyan] #", "attach"),
        ("[cyan]v[/cyan] #", "view"),
        ("[cyan]l[/cyan] #", "log"),
        ("[cyan]s[/cyan] #", "stop"),
        ("[cyan]d[/cyan] #", "delete"),
        ("[cyan]r[/cyan]", "refresh"),
        ("[cyan]q[/cyan]", "quit"),
    ]

    parts = []
    for key, desc in commands:
        parts.append(f"{key} {desc}")

    footer_text = Text.from_markup("  ".join(parts))

    # Add screen hint
    screen_hint = Text.from_markup("  [dim]│[/dim]  [yellow]Ctrl+A,D[/yellow] [dim]detach from screen[/dim]")

    full_footer = Text()
    full_footer.append_text(footer_text)
    full_footer.append_text(screen_hint)

    return Panel(
        Align.center(full_footer),
        box=box.HEAVY,
        style="on rgb(20,40,60)",
        border_style="blue",
        padding=(0, 1),
    )


def render_detail_footer(scan: dict) -> Panel:
    """Render footer for scan details view."""
    parts = ["[cyan]Enter[/cyan] back"]

    if scan.get("is_running"):
        parts.append("[dim]│[/dim]")
        parts.append(f"[green]screen -r strix-{scan.get('scan_id')}[/green]")
        parts.append("[dim]│[/dim]")
        parts.append("[yellow]Ctrl+A,D[/yellow] detach")

    footer_text = Text.from_markup("  ".join(parts))

    return Panel(
        Align.center(footer_text),
        box=box.HEAVY,
        style="on rgb(20,40,60)",
        border_style="blue",
        padding=(0, 1),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# VIEWS
# ═══════════════════════════════════════════════════════════════════════════════

def show_scan_details(scan: dict):
    """Show detailed information about a scan."""
    console.clear()

    # Mini header
    console.print(Panel(
        Text.from_markup(f"{BANNER_MINI}  [dim]Scan Details[/dim]"),
        box=box.HEAVY,
        border_style="cyan",
    ))
    console.print()

    # Status
    is_running = scan.get("is_running", False)
    status_text = "[green bold]● RUNNING[/green bold]" if is_running else "[dim]○ STOPPED[/dim]"

    # Build info table
    info_table = Table(box=None, show_header=False, padding=(0, 2))
    info_table.add_column("Key", style="dim")
    info_table.add_column("Value", style="white")

    info_table.add_row("Scan ID", f"[cyan]{scan.get('scan_id')}[/cyan]")
    info_table.add_row("Status", status_text)
    info_table.add_row("Mode", f"[yellow]{scan.get('scan_mode', '').upper()}[/yellow]")
    info_table.add_row("Started", scan.get("started_at", "-"))
    info_table.add_row("Report", scan.get("output_file", "-"))

    # Targets
    targets = scan.get("targets", [])
    for i, target in enumerate(targets):
        label = "Targets" if i == 0 else ""
        info_table.add_row(label, f"[green]{target}[/green]")

    console.print(Panel(
        info_table,
        title="[bold]Configuration[/bold]",
        title_align="left",
        box=box.ROUNDED,
        border_style="bright_black",
    ))
    console.print()

    # Recent log
    log = scan_manager.get_scan_log(scan.get("scan_id", ""), tail=20)
    console.print(Panel(
        log or "[dim]No log output yet[/dim]",
        title="[bold]Recent Output[/bold]",
        title_align="left",
        subtitle="[dim]last 20 lines[/dim]",
        subtitle_align="right",
        box=box.ROUNDED,
        border_style="bright_black",
    ))
    console.print()

    # Footer
    console.print(render_detail_footer(scan))


def main_menu():
    """Display main TUI dashboard."""
    while True:
        console.clear()

        # Header
        console.print(render_header())
        console.print()

        # Get scans
        scans = scan_manager.list_all_scans()

        # Status bar
        console.print(render_status_bar(scans))
        console.print()

        # Scans table or empty state
        if scans:
            console.print(render_scans_table(scans))
        else:
            console.print(render_empty_state())

        console.print()

        # Footer
        console.print(render_footer())
        console.print()

        # Input prompt
        cmd = Prompt.ask("[cyan bold]❯[/cyan bold]", default="r").strip().lower()

        if cmd == "q":
            break

        elif cmd == "r":
            continue

        elif cmd == "n":
            new_scan_wizard()

        elif cmd.startswith("a "):
            handle_attach(cmd, scans)

        elif cmd.startswith("v "):
            handle_view(cmd, scans)

        elif cmd.startswith("l "):
            handle_log(cmd, scans)

        elif cmd.startswith("s "):
            handle_stop(cmd, scans)

        elif cmd.startswith("d "):
            handle_delete(cmd, scans)


# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

def handle_attach(cmd: str, scans: list[dict]):
    """Handle attach command."""
    try:
        idx = int(cmd.split()[1]) - 1
        if 0 <= idx < len(scans):
            scan = scans[idx]
            if scan.get("is_running"):
                console.print()
                console.print(Panel(
                    Group(
                        Text.from_markup(f"Attaching to [cyan bold]{scan['scan_id']}[/cyan bold]"),
                        Text(""),
                        Text.from_markup("[yellow]Ctrl+A[/yellow] then [yellow]D[/yellow] to detach"),
                    ),
                    box=box.ROUNDED,
                    border_style="green",
                ))
                import time
                time.sleep(1)
                scan_manager.attach_scan(scan["scan_id"])
            else:
                show_error("Scan is not running")
        else:
            show_error("Invalid scan number")
    except (ValueError, IndexError):
        show_error("Invalid scan number")


def handle_view(cmd: str, scans: list[dict]):
    """Handle view command."""
    try:
        idx = int(cmd.split()[1]) - 1
        if 0 <= idx < len(scans):
            show_scan_details(scans[idx])
            Prompt.ask("\n[dim]Press Enter to continue[/dim]")
        else:
            show_error("Invalid scan number")
    except (ValueError, IndexError):
        show_error("Invalid scan number")


def handle_log(cmd: str, scans: list[dict]):
    """Handle log command."""
    try:
        idx = int(cmd.split()[1]) - 1
        if 0 <= idx < len(scans):
            scan = scans[idx]
            console.clear()

            console.print(Panel(
                Text.from_markup(f"{BANNER_MINI}  [dim]Live Log[/dim]  [cyan]{scan['scan_id']}[/cyan]"),
                box=box.HEAVY,
                border_style="cyan",
            ))
            console.print()
            console.print(Panel(
                Text.from_markup("[yellow]Ctrl+C[/yellow] to stop watching"),
                box=box.ROUNDED,
                border_style="yellow",
            ))
            console.print()

            import subprocess
            log_file = scan.get("log_file", "")
            if Path(log_file).exists():
                try:
                    subprocess.run(["tail", "-f", log_file])
                except KeyboardInterrupt:
                    pass
            else:
                show_error("Log file not found")
        else:
            show_error("Invalid scan number")
    except (ValueError, IndexError):
        show_error("Invalid scan number")


def handle_stop(cmd: str, scans: list[dict]):
    """Handle stop command."""
    try:
        idx = int(cmd.split()[1]) - 1
        if 0 <= idx < len(scans):
            scan = scans[idx]
            console.print()
            if Confirm.ask(f"Stop scan [cyan]{scan['scan_id']}[/cyan]?"):
                scan_manager.stop_scan(scan["scan_id"])
                show_success("Scan stopped")
        else:
            show_error("Invalid scan number")
    except (ValueError, IndexError):
        show_error("Invalid scan number")


def handle_delete(cmd: str, scans: list[dict]):
    """Handle delete command."""
    try:
        idx = int(cmd.split()[1]) - 1
        if 0 <= idx < len(scans):
            scan = scans[idx]
            console.print()
            if Confirm.ask(f"[red]Delete[/red] scan [cyan]{scan['scan_id']}[/cyan] and all data?"):
                scan_manager.delete_scan(scan["scan_id"])
                show_success("Scan deleted")
        else:
            show_error("Invalid scan number")
    except (ValueError, IndexError):
        show_error("Invalid scan number")


# ═══════════════════════════════════════════════════════════════════════════════
# FEEDBACK COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════

def show_error(message: str):
    """Show an error message."""
    console.print()
    console.print(Panel(
        Text.from_markup(f"[red]✗[/red] {message}"),
        box=box.ROUNDED,
        border_style="red",
    ))
    Prompt.ask("[dim]Press Enter[/dim]")


def show_success(message: str):
    """Show a success message."""
    console.print()
    console.print(Panel(
        Text.from_markup(f"[green]✓[/green] {message}"),
        box=box.ROUNDED,
        border_style="green",
    ))
    Prompt.ask("[dim]Press Enter[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# NEW SCAN WIZARD
# ═══════════════════════════════════════════════════════════════════════════════

def new_scan_wizard():
    """Professional wizard to create a new scan."""
    console.clear()

    # Header
    console.print(Panel(
        Text.from_markup(f"{BANNER_MINI}  [dim]New Scan[/dim]"),
        box=box.HEAVY,
        border_style="cyan",
    ))
    console.print()

    # Step 1: Targets
    console.print(Rule("[bold]Step 1: Targets[/bold]", style="cyan"))
    console.print()
    console.print("[dim]Enter your targets one per line. Empty line when done.[/dim]")
    console.print()

    # Format hints as a clean table
    hints = Table(box=None, show_header=False, padding=(0, 2))
    hints.add_column("Format", style="cyan")
    hints.add_column("Example", style="dim")
    hints.add_row("URL", "https://example.com")
    hints.add_row("Local Path", "./code or /path/to/project")
    hints.add_row("GitHub SSH", "git@github.com:user/repo.git")
    hints.add_row("GitHub HTTPS", "https://github.com/user/repo")
    hints.add_row("Domain/IP", "example.com or 192.168.1.1")
    console.print(Panel(hints, box=box.ROUNDED, border_style="bright_black"))
    console.print()

    targets = []
    while True:
        target = Prompt.ask(f"[cyan]{len(targets) + 1}.[/cyan] Target", default="").strip()
        if not target:
            break
        targets.append(target)
        console.print(f"   [green]✓[/green] Added: [white]{target}[/white]")

    if not targets:
        show_error("No targets specified")
        return

    console.print()

    # Step 2: Configuration
    console.print(Rule("[bold]Step 2: Configuration[/bold]", style="cyan"))
    console.print()

    # Scan mode selection with descriptions
    console.print("[dim]Select scan intensity:[/dim]")
    console.print()
    mode_table = Table(box=None, show_header=False, padding=(0, 2))
    mode_table.add_column("Mode", style="cyan")
    mode_table.add_column("Description", style="dim")
    mode_table.add_row("[bold]deep[/bold]", "Full coverage, all techniques (recommended)")
    mode_table.add_row("standard", "Balanced coverage and speed")
    mode_table.add_row("quick", "Fast scan for CI/CD integration")
    console.print(mode_table)
    console.print()

    scan_mode = Prompt.ask(
        "Mode",
        choices=["quick", "standard", "deep"],
        default="deep"
    )
    console.print()

    # Custom instruction
    instruction = Prompt.ask(
        "Custom instruction [dim](optional)[/dim]",
        default=""
    ).strip() or None
    console.print()

    # Output file
    output_default = str(Path.home() / f"strix_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
    output_file = Prompt.ask("Report file", default=output_default)

    console.print()

    # Step 3: Confirmation
    console.print(Rule("[bold]Step 3: Confirm[/bold]", style="cyan"))
    console.print()

    # Summary panel
    summary = Table(box=None, show_header=False, padding=(0, 2))
    summary.add_column("Setting", style="dim")
    summary.add_column("Value", style="white")

    # Add targets
    for i, t in enumerate(targets):
        label = "Targets" if i == 0 else ""
        summary.add_row(label, f"[green]{t}[/green]")

    mode_color = "red bold" if scan_mode == "deep" else "yellow" if scan_mode == "standard" else "dim"
    summary.add_row("Mode", f"[{mode_color}]{scan_mode.upper()}[/{mode_color}]")
    summary.add_row("Instructions", instruction or "[dim]None[/dim]")
    summary.add_row("Report", f"[cyan]{output_file}[/cyan]")

    console.print(Panel(
        summary,
        title="[bold]Scan Configuration[/bold]",
        title_align="left",
        box=box.ROUNDED,
        border_style="cyan",
    ))
    console.print()

    if not Confirm.ask("[bold]Start scan?[/bold]"):
        return

    # Start scan with spinner
    console.print()
    with console.status("[cyan]Initializing scan...[/cyan]", spinner="dots"):
        import time
        time.sleep(0.5)  # Brief pause for UX
        metadata = scan_manager.start_scan(
            targets=targets,
            scan_mode=scan_mode,
            instruction=instruction,
            output_file=output_file,
        )

    # Success message
    console.print()
    console.print(Panel(
        Group(
            Text.from_markup("[green bold]✓ Scan Started Successfully[/green bold]"),
            Text(""),
            Text.from_markup(f"   Scan ID:  [cyan]{metadata['scan_id']}[/cyan]"),
            Text.from_markup(f"   Screen:   [dim]{metadata['screen_name']}[/dim]"),
        ),
        box=box.ROUNDED,
        border_style="green",
    ))
    console.print()

    if Confirm.ask("Attach to scan now?"):
        console.print()
        console.print(Panel(
            Text.from_markup("[yellow]Ctrl+A[/yellow] then [yellow]D[/yellow] to detach"),
            box=box.ROUNDED,
            border_style="yellow",
        ))
        import time
        time.sleep(1)
        scan_manager.attach_scan(metadata["scan_id"])
    else:
        Prompt.ask("[dim]Press Enter[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Entry point for TUI."""
    # Dependency checks
    missing = []
    if not shutil.which("screen"):
        missing.append("screen")
    if not shutil.which("docker"):
        missing.append("docker")

    if missing:
        console.print()
        console.print(Panel(
            Group(
                Text.from_markup("[red bold]Missing Dependencies[/red bold]"),
                Text(""),
                Text.from_markup(f"Required: [yellow]{', '.join(missing)}[/yellow]"),
                Text(""),
                Text.from_markup("[dim]Install with:[/dim]"),
                Text.from_markup(f"  [cyan]sudo apt install {' '.join(missing)}[/cyan]"),
            ),
            box=box.ROUNDED,
            border_style="red",
        ))
        console.print()
        sys.exit(1)

    try:
        main_menu()
    except KeyboardInterrupt:
        pass

    # Goodbye message
    console.print()
    console.print(Panel(
        Text.from_markup("[dim]Thanks for using Strix. Happy hacking![/dim]"),
        box=box.ROUNDED,
        border_style="bright_black",
    ))
    console.print()


if __name__ == "__main__":
    main()
