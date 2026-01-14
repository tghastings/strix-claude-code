"""Scan manager for running persistent scans with screen sessions."""

import json
import os
import shlex
import subprocess
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Scan data directory
SCANS_DIR = Path.home() / ".strix-cli" / "scans"
SCREENRC_FILE = SCANS_DIR / "strix.screenrc"


def ensure_screenrc():
    """Create an optimized screenrc for strix sessions."""
    ensure_dirs()

    screenrc_content = """\
# Strix Claude Code - Screen Configuration
# Minimal config for clean Claude CLI terminal experience

# Terminal - pass through terminal type from environment
term $TERM

# Large scrollback buffer (50k lines)
defscrollback 50000

# Disable alternate screen - allows terminal native scrollback
altscreen off

# UTF-8 support
defutf8 on

# Disable startup message
startup_message off

# Disable visual bell
vbell off

# No status line - keep terminal clean
hardstatus off

# Don't block when a window's output stops
nonblock on

# Auto-detach on hangup
autodetach on

# Faster command sequences
maptimeout 5

# Allow terminal scrollback to work
termcapinfo xterm* ti@:te@
"""

    if not SCREENRC_FILE.exists() or SCREENRC_FILE.read_text() != screenrc_content:
        SCREENRC_FILE.write_text(screenrc_content)


def ensure_dirs():
    """Ensure scan directories exist."""
    SCANS_DIR.mkdir(parents=True, exist_ok=True)


def get_scan_file(scan_id: str) -> Path:
    """Get path to scan metadata file."""
    return SCANS_DIR / f"{scan_id}.json"


def save_scan_metadata(scan_id: str, metadata: dict[str, Any]):
    """Save scan metadata to file."""
    ensure_dirs()
    with open(get_scan_file(scan_id), "w") as f:
        json.dump(metadata, f, indent=2, default=str)


def load_scan_metadata(scan_id: str) -> dict[str, Any] | None:
    """Load scan metadata from file."""
    scan_file = get_scan_file(scan_id)
    if scan_file.exists():
        with open(scan_file) as f:
            return json.load(f)
    return None


def list_all_scans() -> list[dict[str, Any]]:
    """List all scans (active and completed)."""
    ensure_dirs()
    scans = []
    for scan_file in SCANS_DIR.glob("*.json"):
        try:
            with open(scan_file) as f:
                metadata = json.load(f)
                # Check if screen session is still running
                scan_id = scan_file.stem
                metadata["is_running"] = is_screen_running(scan_id)
                scans.append(metadata)
        except Exception:
            pass
    # Sort by start time, newest first
    scans.sort(key=lambda x: x.get("started_at", ""), reverse=True)
    return scans


def is_screen_running(scan_id: str) -> bool:
    """Check if a screen session is running for this scan."""
    result = subprocess.run(
        ["screen", "-list"],
        capture_output=True,
        text=True,
    )
    return f"strix-{scan_id}" in result.stdout


def get_running_scans() -> list[dict[str, Any]]:
    """Get only running scans."""
    return [s for s in list_all_scans() if s.get("is_running")]


def start_scan(
    targets: list[str],
    scan_mode: str = "deep",
    instruction: str | None = None,
    output_file: str | None = None,
    mount_docker: bool = False,
) -> dict[str, Any]:
    """Start a new scan in a detached screen session.

    Args:
        targets: List of targets to scan
        scan_mode: Scan intensity (quick, standard, deep)
        instruction: Custom instructions for the scan
        output_file: Path to save the report
        mount_docker: Mount Docker socket for container scanning
    """
    import secrets

    ensure_dirs()
    ensure_screenrc()

    # Generate scan ID
    scan_id = secrets.token_hex(4)

    # Default output file
    if not output_file:
        output_file = str(Path.home() / f"strix_report_{scan_id}.md")

    # Build the command using the same Python interpreter with module invocation
    cmd_parts = [
        sys.executable, "-m", "strix_cli_claude.main",
        "-m", scan_mode,
        "-o", output_file,
        "--scan-id", scan_id,
    ]

    for target in targets:
        cmd_parts.extend(["-t", target])

    if instruction:
        cmd_parts.extend(["--instruction", instruction])

    if mount_docker:
        cmd_parts.append("--mount-docker")

    # Create a wrapper script for the screen session
    # No longer using 'script' command - it corrupts terminal display
    # Screen's native logging (-L) provides clean log capture
    scan_script = SCANS_DIR / f"{scan_id}_run.sh"
    log_file = SCANS_DIR / f"{scan_id}.log"

    # SECURITY: Use shlex.quote() to prevent command injection from user inputs
    quoted_parts = " ".join(shlex.quote(part) for part in cmd_parts)

    # Simple wrapper script - no script command, just run directly
    # Don't override TERM - let the terminal pass through naturally
    scan_script.write_text(f'''#!/bin/bash
# Strix scan wrapper
export LANG=en_US.UTF-8

# Show keyboard shortcuts
echo ""
echo "┌───────────────────────────────────────────────────────────┐"
echo "│  STRIX SCAN                                               │"
echo "├───────────────────────────────────────────────────────────┤"
echo "│  Scroll with your terminal (mouse wheel / trackpad)       │"
echo "│  Ctrl+A, D  =  Detach (scan continues in background)      │"
echo "└───────────────────────────────────────────────────────────┘"
echo ""

# Run the scan
{quoted_parts}
exit_code=$?

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  SCAN COMPLETED (exit code: $exit_code)"
echo "  Report: {shlex.quote(output_file)}"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Press Enter to close, or Ctrl+A,D to detach..."
read
''')
    scan_script.chmod(0o755)

    # Save metadata
    metadata = {
        "scan_id": scan_id,
        "targets": targets,
        "scan_mode": scan_mode,
        "instruction": instruction,
        "output_file": output_file,
        "log_file": str(log_file),
        "mount_docker": mount_docker,
        "started_at": datetime.now().isoformat(),
        "screen_name": f"strix-{scan_id}",
    }
    save_scan_metadata(scan_id, metadata)

    # Start screen session with:
    # -c: use our optimized screenrc
    # -dmS: detached mode with session name
    # -L: enable logging
    # -Logfile: specify log file location
    subprocess.run([
        "screen",
        "-c", str(SCREENRC_FILE),
        "-dmS", f"strix-{scan_id}",
        "-L", "-Logfile", str(log_file),
        "bash", str(scan_script),
    ])

    metadata["is_running"] = True
    return metadata


def attach_scan(scan_id: str, interactive: bool = True) -> bool:
    """Attach to a running scan's screen session.

    Args:
        scan_id: The scan ID to attach to
        interactive: If True, attach to screen session directly.
                    If False, tail the log file (better scrolling).
    """
    if not is_screen_running(scan_id):
        return False

    if interactive:
        # Direct screen attach - allows interaction but scroll is Ctrl+A,[
        subprocess.run(["screen", "-x", f"strix-{scan_id}"])
    else:
        # Tail the log - normal terminal scrolling works, Ctrl+C to stop watching
        metadata = load_scan_metadata(scan_id)
        if metadata and metadata.get("log_file"):
            log_file = metadata["log_file"]
            print(f"\n  Watching log: {log_file}")
            print("  (Ctrl+C to stop watching - scan continues in background)\n")
            subprocess.run(["tail", "-f", log_file])
    return True


def stop_docker_container(scan_id: str) -> bool:
    """Stop and remove Docker container for a scan."""
    container_name = f"strix-cli-{scan_id}"

    # Check if container exists
    result = subprocess.run(
        ["docker", "ps", "-aq", "--filter", f"name={container_name}"],
        capture_output=True,
        text=True,
    )

    if result.stdout.strip():
        # Container exists - stop and remove it
        subprocess.run(["docker", "stop", container_name], capture_output=True)
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        return True

    return False


def stop_scan(scan_id: str) -> bool:
    """Stop a running scan (screen session and Docker container)."""
    stopped_something = False

    # Stop screen session if running
    if is_screen_running(scan_id):
        subprocess.run(["screen", "-S", f"strix-{scan_id}", "-X", "quit"])
        stopped_something = True

    # Stop Docker container
    if stop_docker_container(scan_id):
        stopped_something = True

    return stopped_something


def get_scan_log(scan_id: str, tail: int = 50) -> str:
    """Get recent log output from a scan."""
    metadata = load_scan_metadata(scan_id)
    if not metadata:
        return "Scan not found"

    log_file = Path(metadata.get("log_file", ""))
    if not log_file.exists():
        return "Log file not found"

    try:
        result = subprocess.run(
            ["tail", "-n", str(tail), str(log_file)],
            capture_output=True,
            text=True,
        )
        return result.stdout
    except Exception as e:
        return f"Error reading log: {e}"


def delete_scan(scan_id: str) -> bool:
    """Delete a scan's metadata and logs (keeps report files)."""
    # Always try to stop screen session and Docker container
    stop_scan(scan_id)

    # Delete files in SCANS_DIR
    scan_file = get_scan_file(scan_id)
    if scan_file.exists():
        scan_file.unlink()

    # Delete log file
    log_file = SCANS_DIR / f"{scan_id}.log"
    if log_file.exists():
        log_file.unlink()

    # Delete run scripts
    run_script = SCANS_DIR / f"{scan_id}_run.sh"
    if run_script.exists():
        run_script.unlink()

    cmd_script = SCANS_DIR / f"{scan_id}_cmd.sh"
    if cmd_script.exists():
        cmd_script.unlink()

    # Clean up temp directories in /tmp (but keep report files)
    tmp_dir = Path("/tmp")
    for pattern in [f"strix-cli-{scan_id}", f"strix-repos-{scan_id}"]:
        for temp_path in tmp_dir.glob(pattern):
            if temp_path.is_dir():
                shutil.rmtree(temp_path, ignore_errors=True)

    return True
