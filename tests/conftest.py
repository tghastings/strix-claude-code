"""Pytest fixtures for strix-claude-code tests."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def temp_scans_dir(tmp_path):
    """Create a temporary scans directory."""
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()
    with patch("strix_cli_claude.scan_manager.SCANS_DIR", scans_dir):
        yield scans_dir


@pytest.fixture
def mock_screen_running():
    """Mock screen -list to simulate running sessions."""
    def _mock(scan_ids: list[str]):
        output = "There are screens on:\n"
        for sid in scan_ids:
            output += f"\t12345.strix-{sid}\t(Detached)\n"
        output += f"{len(scan_ids)} Sockets in /run/screen/S-user.\n"

        def mock_run(cmd, *args, **kwargs):
            from unittest.mock import MagicMock
            result = MagicMock()
            result.stdout = output
            result.returncode = 0
            return result

        return patch("subprocess.run", side_effect=mock_run)

    return _mock


@pytest.fixture
def mock_screen_not_running():
    """Mock screen -list to simulate no running sessions."""
    def mock_run(cmd, *args, **kwargs):
        from unittest.mock import MagicMock
        result = MagicMock()
        result.stdout = "No Sockets found in /run/screen/S-user.\n"
        result.returncode = 1
        return result

    return patch("subprocess.run", side_effect=mock_run)
