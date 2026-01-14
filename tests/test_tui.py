"""Tests for TUI module."""

from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, call
from io import StringIO

import pytest
from rich.table import Table
from rich.panel import Panel

from strix_cli_claude import tui


class TestRenderFooter:
    """Tests for render_footer function."""

    def test_returns_panel(self):
        """Should return a Rich Panel."""
        result = tui.render_footer()
        assert isinstance(result, Panel)

    def test_contains_key_commands(self):
        """Should contain key command shortcuts."""
        result = tui.render_footer()
        # The renderable contains an Align with a Text object
        text_content = str(result.renderable)
        assert "n" in text_content
        assert "attach" in text_content.lower() or "a" in text_content
        assert "quit" in text_content.lower() or "q" in text_content

    def test_contains_detach_instructions(self):
        """Should contain screen detach instructions."""
        result = tui.render_footer()
        text_content = str(result.renderable)
        assert "Ctrl+A" in text_content or "detach" in text_content


class TestRenderDetailFooter:
    """Tests for render_detail_footer function."""

    def test_returns_panel(self):
        """Should return a Rich Panel."""
        scan = {"scan_id": "test123", "is_running": True}
        result = tui.render_detail_footer(scan)
        assert isinstance(result, Panel)

    def test_shows_attach_command_when_running(self):
        """Should show attach command for running scans."""
        scan = {"scan_id": "abc123", "is_running": True}
        result = tui.render_detail_footer(scan)
        text_content = str(result.renderable)
        assert "screen" in text_content or "Attach" in text_content

    def test_shows_detach_instructions_when_running(self):
        """Should show detach instructions for running scans."""
        scan = {"scan_id": "abc123", "is_running": True}
        result = tui.render_detail_footer(scan)
        text_content = str(result.renderable)
        assert "Ctrl+A" in text_content

    def test_minimal_footer_when_stopped(self):
        """Should show minimal footer for stopped scans."""
        scan = {"scan_id": "abc123", "is_running": False}
        result = tui.render_detail_footer(scan)
        text_content = str(result.renderable)
        assert "Enter" in text_content or "back" in text_content.lower()
        # Should not show attach/detach for stopped scans
        assert "screen -r" not in text_content


class TestFormatTimeAgo:
    """Tests for format_time_ago function."""

    def test_seconds_ago(self):
        """Should format seconds correctly."""
        now = datetime.now()
        time_30s_ago = (now - timedelta(seconds=30)).isoformat()

        result = tui.format_time_ago(time_30s_ago)

        assert result.endswith("s")
        # Allow some tolerance for test execution time
        seconds = int(result.replace("s", ""))
        assert 28 <= seconds <= 35

    def test_minutes_ago(self):
        """Should format minutes correctly."""
        now = datetime.now()
        time_5m_ago = (now - timedelta(minutes=5)).isoformat()

        result = tui.format_time_ago(time_5m_ago)

        assert result == "5m"

    def test_hours_ago(self):
        """Should format hours correctly."""
        now = datetime.now()
        time_3h_ago = (now - timedelta(hours=3)).isoformat()

        result = tui.format_time_ago(time_3h_ago)

        assert result == "3h"

    def test_days_ago(self):
        """Should format days correctly."""
        now = datetime.now()
        time_2d_ago = (now - timedelta(days=2)).isoformat()

        result = tui.format_time_ago(time_2d_ago)

        assert result == "2d"

    def test_invalid_time_returns_dash(self):
        """Should return '-' for invalid time strings."""
        result = tui.format_time_ago("not-a-valid-time")
        assert result == "-"

    def test_empty_string_returns_dash(self):
        """Should return '-' for empty string."""
        result = tui.format_time_ago("")
        assert result == "-"


class TestRenderScansTable:
    """Tests for render_scans_table function."""

    def test_returns_table_instance(self):
        """Should return a Rich Table instance."""
        result = tui.render_scans_table([])
        assert isinstance(result, Table)

    def test_empty_scans_creates_empty_table(self):
        """Should create table with no rows for empty scans list."""
        result = tui.render_scans_table([])
        assert result.row_count == 0

    def test_table_has_correct_columns(self):
        """Should create table with expected columns."""
        result = tui.render_scans_table([])
        column_names = [str(col.header).upper() for col in result.columns]

        assert any("#" in name for name in column_names)
        assert any("SCAN" in name or "ID" in name for name in column_names)
        assert any("MODE" in name for name in column_names)
        assert any("TARGET" in name for name in column_names)
        assert any("START" in name for name in column_names)
        assert any("REPORT" in name for name in column_names)

    def test_adds_scan_rows(self):
        """Should add row for each scan."""
        scans = [
            {
                "scan_id": "abc123",
                "is_running": True,
                "scan_mode": "deep",
                "targets": ["example.com"],
                "started_at": datetime.now().isoformat(),
                "output_file": "/path/to/report.md",
            },
            {
                "scan_id": "def456",
                "is_running": False,
                "scan_mode": "quick",
                "targets": ["test.com"],
                "started_at": datetime.now().isoformat(),
                "output_file": "/path/to/other.md",
            },
        ]

        result = tui.render_scans_table(scans)
        assert result.row_count == 2

    def test_truncates_long_targets(self):
        """Should truncate targets list if too long."""
        scans = [
            {
                "scan_id": "abc123",
                "is_running": False,
                "scan_mode": "deep",
                "targets": ["very-long-domain-name-1.example.com", "very-long-domain-name-2.example.com"],
                "started_at": datetime.now().isoformat(),
                "output_file": "/path/to/report.md",
            },
        ]

        # This should not raise an error
        result = tui.render_scans_table(scans)
        assert result.row_count == 1

    def test_handles_missing_fields_gracefully(self):
        """Should handle scans with missing fields."""
        scans = [
            {
                "scan_id": "minimal",
                # Missing most fields
            },
        ]

        # Should not raise
        result = tui.render_scans_table(scans)
        assert result.row_count == 1


class TestShowScanDetails:
    """Tests for show_scan_details function."""

    def test_displays_scan_info(self):
        """Should display scan information without error."""
        scan = {
            "scan_id": "test123",
            "is_running": True,
            "scan_mode": "deep",
            "started_at": datetime.now().isoformat(),
            "output_file": "/path/to/report.md",
            "targets": ["example.com", "test.com"],
        }

        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui, "scan_manager") as mock_manager:
                    mock_manager.get_scan_log.return_value = "Log output here"

                    # Should not raise
                    tui.show_scan_details(scan)

    def test_calls_get_scan_log(self):
        """Should call get_scan_log to display recent log."""
        scan = {
            "scan_id": "logtest",
            "is_running": False,
            "scan_mode": "quick",
            "started_at": datetime.now().isoformat(),
            "output_file": "/path/to/report.md",
            "targets": ["example.com"],
        }

        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui, "scan_manager") as mock_manager:
                    mock_manager.get_scan_log.return_value = "Log content"

                    tui.show_scan_details(scan)

                    # New TUI uses tail=20 instead of tail=30
                    mock_manager.get_scan_log.assert_called_once_with("logtest", tail=20)


class TestNewScanWizard:
    """Tests for new_scan_wizard function."""

    def test_returns_early_when_no_targets(self):
        """Should return early if no targets are provided."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui.console, "status"):
                    with patch.object(tui, "Prompt") as mock_prompt:
                        # Simulate user entering empty target immediately
                        mock_prompt.ask.side_effect = ["", ""]  # Empty target, then press enter

                        # Should not raise and should not start scan
                        with patch.object(tui, "scan_manager") as mock_manager:
                            with patch.object(tui, "show_error"):
                                tui.new_scan_wizard()
                                mock_manager.start_scan.assert_not_called()

    def test_starts_scan_with_provided_inputs(self):
        """Should start scan with user-provided inputs."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui.console, "status"):
                    with patch.object(tui, "Prompt") as mock_prompt:
                        with patch.object(tui, "Confirm") as mock_confirm:
                            with patch.object(tui, "scan_manager") as mock_manager:
                                # Simulate user inputs
                                mock_prompt.ask.side_effect = [
                                    "example.com",  # First target
                                    "",  # End targets
                                    "deep",  # Scan mode
                                    "",  # No custom instruction
                                    "/path/to/output.md",  # Output file
                                    "",  # Press enter after starting
                                ]
                                mock_confirm.ask.side_effect = [False, True, False]  # Docker: no, Start: yes, Attach: no
                                mock_manager.start_scan.return_value = {
                                    "scan_id": "new123",
                                    "screen_name": "strix-new123",
                                }

                                tui.new_scan_wizard()

                                mock_manager.start_scan.assert_called_once()
                                call_kwargs = mock_manager.start_scan.call_args[1]
                                assert call_kwargs["targets"] == ["example.com"]
                                assert call_kwargs["scan_mode"] == "deep"
                                assert call_kwargs["output_file"] == "/path/to/output.md"

    def test_does_not_start_when_user_declines(self):
        """Should not start scan if user declines confirmation."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui.console, "status"):
                    with patch.object(tui, "Prompt") as mock_prompt:
                        with patch.object(tui, "Confirm") as mock_confirm:
                            with patch.object(tui, "scan_manager") as mock_manager:
                                mock_prompt.ask.side_effect = [
                                    "example.com",
                                    "",
                                    "quick",
                                    "",
                                    "/path/to/output.md",
                                ]
                                mock_confirm.ask.return_value = False  # Decline to start

                                tui.new_scan_wizard()

                                mock_manager.start_scan.assert_not_called()


class TestMain:
    """Tests for main entry point function."""

    def test_exits_when_screen_not_installed(self):
        """Should exit with error if screen is not installed."""
        with patch("shutil.which", return_value=None):
            with patch.object(tui.console, "print"):
                with pytest.raises(SystemExit) as exc_info:
                    tui.main()

                assert exc_info.value.code == 1

    def test_runs_main_menu_when_dependencies_available(self):
        """Should run main menu when dependencies are available."""
        # Mock both screen and docker as available
        def mock_which(cmd):
            return f"/usr/bin/{cmd}"

        with patch("shutil.which", side_effect=mock_which):
            with patch.object(tui, "main_menu") as mock_menu:
                with patch.object(tui.console, "print"):
                    mock_menu.side_effect = KeyboardInterrupt()  # Exit immediately

                    tui.main()

                    mock_menu.assert_called_once()


class TestMainMenu:
    """Tests for main_menu function."""

    def test_quit_command_exits_loop(self):
        """Should exit loop when 'q' is entered."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui, "Prompt") as mock_prompt:
                    with patch.object(tui, "scan_manager") as mock_manager:
                        mock_manager.list_all_scans.return_value = []
                        mock_prompt.ask.return_value = "q"

                        # Should not raise and should exit
                        tui.main_menu()

    def test_refresh_command_continues_loop(self):
        """Should continue loop when 'r' is entered."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui, "Prompt") as mock_prompt:
                    with patch.object(tui, "scan_manager") as mock_manager:
                        mock_manager.list_all_scans.return_value = []
                        # First 'r' to refresh, then 'q' to quit
                        mock_prompt.ask.side_effect = ["r", "q"]

                        tui.main_menu()

                        # Should have called list_all_scans twice (once per loop iteration)
                        assert mock_manager.list_all_scans.call_count == 2

    def test_new_scan_command_calls_wizard(self):
        """Should call new_scan_wizard when 'n' is entered."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui, "Prompt") as mock_prompt:
                    with patch.object(tui, "scan_manager") as mock_manager:
                        with patch.object(tui, "new_scan_wizard") as mock_wizard:
                            mock_manager.list_all_scans.return_value = []
                            mock_prompt.ask.side_effect = ["n", "q"]

                            tui.main_menu()

                            mock_wizard.assert_called_once()

    def test_attach_command_attaches_to_scan(self):
        """Should attach to scan when 'a <#>' is entered."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui, "Prompt") as mock_prompt:
                    with patch.object(tui, "scan_manager") as mock_manager:
                        mock_manager.list_all_scans.return_value = [
                            {"scan_id": "test1", "is_running": True}
                        ]
                        mock_prompt.ask.side_effect = ["a 1", "q"]

                        tui.main_menu()

                        mock_manager.attach_scan.assert_called_once_with("test1")

    def test_stop_command_stops_scan(self):
        """Should stop scan when 's <#>' is entered and confirmed."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui, "Prompt") as mock_prompt:
                    with patch.object(tui, "Confirm") as mock_confirm:
                        with patch.object(tui, "scan_manager") as mock_manager:
                            mock_manager.list_all_scans.return_value = [
                                {"scan_id": "tostop", "is_running": True}
                            ]
                            mock_prompt.ask.side_effect = ["s 1", "", "q"]
                            mock_confirm.ask.return_value = True

                            tui.main_menu()

                            mock_manager.stop_scan.assert_called_once_with("tostop")

    def test_delete_command_deletes_scan(self):
        """Should delete scan when 'd <#>' is entered and confirmed."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui, "Prompt") as mock_prompt:
                    with patch.object(tui, "Confirm") as mock_confirm:
                        with patch.object(tui, "scan_manager") as mock_manager:
                            mock_manager.list_all_scans.return_value = [
                                {"scan_id": "todelete", "is_running": False}
                            ]
                            mock_prompt.ask.side_effect = ["d 1", "", "q"]
                            mock_confirm.ask.return_value = True

                            tui.main_menu()

                            mock_manager.delete_scan.assert_called_once_with("todelete")

    def test_view_command_shows_details(self):
        """Should show scan details when 'v <#>' is entered."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui, "Prompt") as mock_prompt:
                    with patch.object(tui, "scan_manager") as mock_manager:
                        with patch.object(tui, "show_scan_details") as mock_details:
                            scan = {"scan_id": "toview", "is_running": True}
                            mock_manager.list_all_scans.return_value = [scan]
                            mock_prompt.ask.side_effect = ["v 1", "", "q"]

                            tui.main_menu()

                            mock_details.assert_called_once_with(scan)

    def test_invalid_scan_number_shows_error(self):
        """Should handle invalid scan numbers gracefully."""
        with patch.object(tui.console, "clear"):
            with patch.object(tui.console, "print"):
                with patch.object(tui, "Prompt") as mock_prompt:
                    with patch.object(tui, "scan_manager") as mock_manager:
                        with patch.object(tui, "show_error") as mock_error:
                            mock_manager.list_all_scans.return_value = []
                            mock_prompt.ask.side_effect = ["a invalid", "q"]

                            # Should not raise
                            tui.main_menu()

                            # Should have called show_error
                            mock_error.assert_called()


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_get_status_indicator_running(self):
        """Should return green dot for running."""
        result = tui.get_status_indicator(True)
        assert "green" in result
        assert "●" in result

    def test_get_status_indicator_stopped(self):
        """Should return dim circle for stopped."""
        result = tui.get_status_indicator(False)
        assert "dim" in result
        assert "○" in result

    def test_get_system_info(self):
        """Should return system info dictionary."""
        result = tui.get_system_info()
        assert "version" in result
        assert "python" in result
        assert "platform" in result
        assert "screen" in result
        assert "docker" in result


class TestRenderComponents:
    """Tests for render helper functions."""

    def test_render_header_returns_panel(self):
        """Should return a Panel."""
        result = tui.render_header()
        assert isinstance(result, Panel)

    def test_render_status_bar_returns_panel(self):
        """Should return a Panel."""
        result = tui.render_status_bar([])
        assert isinstance(result, Panel)

    def test_render_empty_state_returns_panel(self):
        """Should return a Panel."""
        result = tui.render_empty_state()
        assert isinstance(result, Panel)

    def test_render_status_bar_shows_running_count(self):
        """Should show count of running scans."""
        scans = [
            {"scan_id": "1", "is_running": True},
            {"scan_id": "2", "is_running": True},
            {"scan_id": "3", "is_running": False},
        ]
        result = tui.render_status_bar(scans)
        text = str(result.renderable)
        # Should indicate 2 running scans
        assert "2" in text
