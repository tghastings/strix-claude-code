"""Scan manager for running persistent scans with screen sessions."""

import json
import os
import shlex
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

# Scan data directory
SCANS_DIR = Path.home() / ".strix-cli" / "scans"


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
) -> dict[str, Any]:
    """Start a new scan in a detached screen session."""
    import secrets

    ensure_dirs()

    # Generate scan ID
    scan_id = secrets.token_hex(4)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Default output file
    if not output_file:
        output_file = str(Path.home() / f"strix_report_{scan_id}.md")

    # Build the command
    strix_cli_dir = Path(__file__).parent.parent.parent
    run_script = strix_cli_dir / "run.py"

    cmd_parts = [
        "python3", str(run_script),
        "-m", scan_mode,
        "-o", output_file,
        "--scan-id", scan_id,
    ]

    for target in targets:
        cmd_parts.extend(["-t", target])

    if instruction:
        cmd_parts.extend(["--instruction", instruction])

    # Create a wrapper script for the screen session
    scan_script = SCANS_DIR / f"{scan_id}_run.sh"
    inner_script = SCANS_DIR / f"{scan_id}_cmd.sh"
    log_file = SCANS_DIR / f"{scan_id}.log"

    # Use 'script' command to capture output while preserving TTY interactivity
    # This is critical for Claude CLI which requires a proper terminal
    # SECURITY: Use shlex.quote() to prevent command injection from user inputs
    # Write command to inner script to avoid complex quoting issues with script -c
    quoted_parts = " ".join(shlex.quote(part) for part in cmd_parts)
    quoted_dir = shlex.quote(str(strix_cli_dir))
    quoted_log = shlex.quote(str(log_file))
    quoted_inner = shlex.quote(str(inner_script))

    # Inner script runs the actual command
    inner_script.write_text(f'''#!/bin/bash
cd {quoted_dir}
exec {quoted_parts}
''')
    inner_script.chmod(0o755)

    # Outer script uses 'script' to capture TTY output
    scan_script.write_text(f'''#!/bin/bash
script -q {quoted_log} -c {quoted_inner}
echo ""
echo "=== SCAN COMPLETED ==="
echo "Press Enter to close this session..."
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
        "started_at": datetime.now().isoformat(),
        "screen_name": f"strix-{scan_id}",
    }
    save_scan_metadata(scan_id, metadata)

    # Start screen session
    subprocess.run([
        "screen", "-dmS", f"strix-{scan_id}",
        "bash", str(scan_script),
    ])

    metadata["is_running"] = True
    return metadata


def attach_scan(scan_id: str) -> bool:
    """Attach to a running scan's screen session."""
    if not is_screen_running(scan_id):
        return False

    subprocess.run(["screen", "-r", f"strix-{scan_id}"])
    return True


def stop_docker_container(scan_id: str) -> bool:
    """Stop and remove Docker container for a scan."""
    container_name = f"strix-cli-scan-{scan_id}"

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
