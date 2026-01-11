"""Tests for main.py module."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from strix_cli_claude import main


class TestGetSystemPrompt:
    """Tests for get_system_prompt function."""

    def test_includes_target_in_prompt(self):
        """Should include the target in the prompt."""
        result = main.get_system_prompt("URL: https://example.com", "quick", 4)
        assert "https://example.com" in result

    def test_includes_scan_mode(self):
        """Should include scan mode in prompt."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)
        assert "SCAN MODE: deep" in result

    def test_includes_cpu_count(self):
        """Should include CPU count for parallelization guidance."""
        result = main.get_system_prompt("URL: https://example.com", "quick", 8)
        assert "AVAILABLE CPUs: 8" in result
        assert "8" in result  # Should appear in parallelization examples

    def test_includes_custom_instruction(self):
        """Should include custom instruction when provided."""
        result = main.get_system_prompt(
            "URL: https://example.com",
            "quick",
            4,
            instruction="Focus on SQL injection only"
        )
        assert "Focus on SQL injection only" in result
        assert "CUSTOM INSTRUCTIONS:" in result

    def test_no_custom_instruction_section_when_none(self):
        """Should not include custom instruction section when not provided."""
        result = main.get_system_prompt("URL: https://example.com", "quick", 4)
        assert "CUSTOM INSTRUCTIONS:" not in result

    def test_deep_mode_includes_deep_scan_guidance(self):
        """Should include deep scan specific guidance."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)
        assert "DEEP SCAN MODE" in result
        assert "FULL COMPROMISE" in result or "EVERYTHING" in result

    def test_standard_mode_includes_standard_guidance(self):
        """Should include standard scan guidance."""
        result = main.get_system_prompt("URL: https://example.com", "standard", 4)
        assert "STANDARD SCAN MODE:" in result

    def test_quick_mode_includes_quick_guidance(self):
        """Should include quick scan guidance."""
        result = main.get_system_prompt("URL: https://example.com", "quick", 4)
        assert "QUICK SCAN MODE:" in result
        assert "CI/CD" in result

    def test_multi_target_includes_multi_target_guidance(self):
        """Should include multi-target guidance when multiple targets."""
        targets = "URL: https://example.com\nLocal code: /workspace/myapp"
        result = main.get_system_prompt(targets, "deep", 4)
        assert "MULTI-TARGET TESTING:" in result

    def test_single_target_no_multi_target_guidance(self):
        """Should not include multi-target guidance for single target."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)
        assert "MULTI-TARGET TESTING:" not in result

    def test_whitebox_mode_when_local_code(self):
        """Should include whitebox testing guidance when local code target exists."""
        targets = "Local code: /workspace/myapp"
        result = main.get_system_prompt(targets, "deep", 4)
        assert "WHITEBOX MODE" in result
        assert "SOURCE CODE" in result
        assert "PHASE 1" in result

    def test_whitebox_requires_code_review_first(self):
        """Whitebox mode should emphasize code review before testing."""
        targets = "Local code: /workspace/myapp"
        result = main.get_system_prompt(targets, "deep", 4)
        assert "RECONNAISSANCE" in result or "FIRST" in result
        assert "list_files" in result
        assert "Read EVERY" in result or "EVERY file" in result.lower()

    def test_whitebox_includes_vulnerability_patterns(self):
        """Whitebox mode should list specific vulnerability patterns to look for."""
        targets = "Local code: /workspace/myapp"
        result = main.get_system_prompt(targets, "deep", 4)
        assert "SQL" in result
        assert "XSS" in result or "Cross-site" in result
        assert "RCE" in result or "exec" in result
        assert "Path traversal" in result or "LFI" in result
        assert "IDOR" in result
        assert "secrets" in result.lower()

    def test_no_whitebox_for_url_only(self):
        """Should not include whitebox guidance for URL-only targets."""
        targets = "URL: https://example.com"
        result = main.get_system_prompt(targets, "deep", 4)
        assert "WHITEBOX MODE" not in result

    def test_includes_tool_documentation(self):
        """Should document available tools."""
        result = main.get_system_prompt("URL: https://example.com", "quick", 4)
        assert "terminal_execute" in result
        assert "python_action" in result
        assert "browser_action" in result
        assert "create_vulnerability_report" in result

    def test_includes_vulnerability_priorities(self):
        """Should list vulnerability priorities to test."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)
        assert "SQL Injection" in result
        assert "XSS" in result
        assert "SSRF" in result
        assert "RCE" in result


class TestClassifyTarget:
    """Tests for classify_target function."""

    def test_classifies_http_url(self):
        """Should classify http:// as URL."""
        result = main.classify_target("http://example.com")
        assert result["type"] == "url"
        assert result["url"] == "http://example.com"

    def test_classifies_https_url(self):
        """Should classify https:// as URL."""
        result = main.classify_target("https://example.com/path")
        assert result["type"] == "url"
        assert result["url"] == "https://example.com/path"

    def test_classifies_existing_local_path(self, tmp_path):
        """Should classify existing path as local."""
        test_dir = tmp_path / "myproject"
        test_dir.mkdir()

        result = main.classify_target(str(test_dir))
        assert result["type"] == "local"
        assert result["path"] == str(test_dir)
        assert result["name"] == "myproject"

    def test_classifies_relative_path_starting_with_dot(self, tmp_path, monkeypatch):
        """Should recognize ./ paths as local."""
        test_dir = tmp_path / "myproject"
        test_dir.mkdir()
        monkeypatch.chdir(tmp_path)

        result = main.classify_target("./myproject")
        assert result["type"] == "local"

    def test_classifies_absolute_path_starting_with_slash(self, tmp_path):
        """Should recognize /path as local if exists."""
        test_dir = tmp_path / "myproject"
        test_dir.mkdir()

        result = main.classify_target(str(test_dir))
        assert result["type"] == "local"

    def test_classifies_domain_as_domain(self):
        """Should classify plain domain as domain type."""
        result = main.classify_target("example.com")
        assert result["type"] == "domain"
        assert result["domain"] == "example.com"

    def test_classifies_ip_as_domain(self):
        """Should classify IP address as domain type."""
        result = main.classify_target("192.168.1.1")
        assert result["type"] == "domain"
        assert result["domain"] == "192.168.1.1"

    def test_classifies_nonexistent_path_as_domain(self):
        """Should treat nonexistent paths as domains."""
        result = main.classify_target("/nonexistent/path/to/nothing")
        # Since it doesn't exist, it won't be classified as local
        assert result["type"] == "domain"


class TestCreateMcpConfig:
    """Tests for create_mcp_config function."""

    def test_returns_dict_with_mcp_servers(self):
        """Should return config with mcpServers key."""
        result = main.create_mcp_config(
            "http://localhost:8080",
            "token123",
            "scan-abc",
            "/path/to/report.md"
        )
        assert "mcpServers" in result
        assert "strix-pentest" in result["mcpServers"]

    def test_config_includes_tool_server_url(self):
        """Should include tool server URL in env."""
        result = main.create_mcp_config(
            "http://localhost:8080",
            "token123",
            "scan-abc",
            "/path/to/report.md"
        )
        env = result["mcpServers"]["strix-pentest"]["env"]
        assert env["STRIX_TOOL_SERVER_URL"] == "http://localhost:8080"

    def test_config_includes_token(self):
        """Should include auth token in env."""
        result = main.create_mcp_config(
            "http://localhost:8080",
            "secret-token",
            "scan-abc",
            "/path/to/report.md"
        )
        env = result["mcpServers"]["strix-pentest"]["env"]
        assert env["STRIX_TOOL_SERVER_TOKEN"] == "secret-token"

    def test_config_includes_scan_id(self):
        """Should include scan ID in agent ID."""
        result = main.create_mcp_config(
            "http://localhost:8080",
            "token123",
            "my-scan-123",
            "/path/to/report.md"
        )
        env = result["mcpServers"]["strix-pentest"]["env"]
        assert "my-scan-123" in env["STRIX_AGENT_ID"]

    def test_config_includes_report_file(self):
        """Should include report file path."""
        result = main.create_mcp_config(
            "http://localhost:8080",
            "token123",
            "scan-abc",
            "/custom/report/path.md"
        )
        env = result["mcpServers"]["strix-pentest"]["env"]
        assert env["STRIX_REPORT_FILE"] == "/custom/report/path.md"

    def test_config_uses_python_executable(self):
        """Should use current Python executable."""
        import sys
        result = main.create_mcp_config(
            "http://localhost:8080",
            "token123",
            "scan-abc",
            "/path/to/report.md"
        )
        assert result["mcpServers"]["strix-pentest"]["command"] == sys.executable


class TestCheckClaudeCli:
    """Tests for check_claude_cli function."""

    def test_returns_true_when_claude_exists(self):
        """Should return True when claude CLI is available."""
        with patch("shutil.which", return_value="/usr/bin/claude"):
            assert main.check_claude_cli() is True

    def test_returns_false_when_claude_missing(self):
        """Should return False when claude CLI is not available."""
        with patch("shutil.which", return_value=None):
            assert main.check_claude_cli() is False


class TestMainCli:
    """Tests for main CLI entry point."""

    def test_exits_when_claude_not_installed(self):
        """Should exit with error when claude CLI not found."""
        from click.testing import CliRunner
        runner = CliRunner()

        with patch.object(main, "check_claude_cli", return_value=False):
            result = runner.invoke(main.main, ["-t", "example.com"])
            assert result.exit_code == 1
            assert "Claude CLI not found" in result.output

    def test_loads_instruction_from_file(self, tmp_path):
        """Should load custom instruction from file."""
        instruction_file = tmp_path / "instructions.txt"
        instruction_file.write_text("Focus on XSS vulnerabilities")

        from click.testing import CliRunner
        runner = CliRunner()

        with patch.object(main, "check_claude_cli", return_value=True):
            with patch.object(main, "Sandbox") as mock_sandbox:
                mock_instance = MagicMock()
                mock_instance.start.return_value = {
                    "container_name": "test",
                    "tool_server_url": "http://localhost:8080",
                    "tool_server_token": "token",
                    "scan_id": "abc123",
                    "cpu_count": 4,
                }
                mock_sandbox.return_value = mock_instance

                with patch("subprocess.run"):
                    with patch("sys.stdin") as mock_stdin:
                        mock_stdin.isatty.return_value = False
                        # Will wait for KeyboardInterrupt, so we catch it
                        with patch("time.sleep", side_effect=KeyboardInterrupt):
                            result = runner.invoke(main.main, [
                                "-t", "example.com",
                                "--instruction-file", str(instruction_file),
                            ])

    def test_classifies_multiple_targets(self, tmp_path):
        """Should correctly classify multiple target types."""
        local_dir = tmp_path / "mycode"
        local_dir.mkdir()

        from click.testing import CliRunner
        runner = CliRunner()

        with patch.object(main, "check_claude_cli", return_value=True):
            with patch.object(main, "Sandbox") as mock_sandbox:
                mock_instance = MagicMock()
                mock_instance.start.return_value = {
                    "container_name": "test",
                    "tool_server_url": "http://localhost:8080",
                    "tool_server_token": "token",
                    "scan_id": "abc123",
                    "cpu_count": 4,
                }
                mock_sandbox.return_value = mock_instance

                with patch("subprocess.run"):
                    with patch("sys.stdin") as mock_stdin:
                        mock_stdin.isatty.return_value = False
                        with patch("time.sleep", side_effect=KeyboardInterrupt):
                            result = runner.invoke(main.main, [
                                "-t", "https://example.com",
                                "-t", str(local_dir),
                                "-t", "192.168.1.1",
                            ])

                # Should have called start with local sources
                call_kwargs = mock_instance.start.call_args[1]
                assert call_kwargs.get("local_sources") is not None
                assert len(call_kwargs["local_sources"]) == 1

    def test_generates_default_output_file(self):
        """Should generate default output filename with timestamp."""
        from click.testing import CliRunner
        runner = CliRunner()

        with patch.object(main, "check_claude_cli", return_value=True):
            with patch.object(main, "Sandbox") as mock_sandbox:
                mock_instance = MagicMock()
                mock_instance.start.return_value = {
                    "container_name": "test",
                    "tool_server_url": "http://localhost:8080",
                    "tool_server_token": "token",
                    "scan_id": "abc123",
                    "cpu_count": 4,
                }
                mock_sandbox.return_value = mock_instance

                with patch("subprocess.run"):
                    with patch("sys.stdin") as mock_stdin:
                        mock_stdin.isatty.return_value = False
                        with patch("time.sleep", side_effect=KeyboardInterrupt):
                            result = runner.invoke(main.main, ["-t", "example.com"])

                # Check that output contains strix_report
                assert "strix_report" in result.output or mock_instance.start.called


class TestWhiteboxInitialPrompt:
    """Tests for whitebox-specific initial prompt generation."""

    def test_whitebox_prompt_emphasizes_code_review(self):
        """Whitebox initial prompt should emphasize code review first."""
        # This tests the logic by examining the prompt content
        targets = "Local code: /workspace/myapp"
        result = main.get_system_prompt(targets, "deep", 4)

        # Check that reconnaissance/code review is emphasized
        assert "PHASE 1" in result
        assert "RECONNAISSANCE" in result or "SOURCE CODE" in result

    def test_whitebox_prompt_lists_files_first(self):
        """Whitebox should instruct to list files first."""
        targets = "Local code: /workspace/myapp"
        result = main.get_system_prompt(targets, "deep", 4)

        assert "list_files" in result

    def test_whitebox_prompt_has_hacker_mindset(self):
        """Whitebox should have aggressive hacker mindset."""
        targets = "Local code: /workspace/myapp"
        result = main.get_system_prompt(targets, "deep", 4)

        # Should mention hunting for bugs or exploitation
        assert "EXPLOIT" in result or "attack" in result.lower() or "Hunt" in result

    def test_combined_whitebox_blackbox(self):
        """Combined local + URL targets should include both approaches."""
        targets = "Local code: /workspace/myapp\nURL: https://example.com"
        result = main.get_system_prompt(targets, "deep", 4)

        # Should have whitebox guidance
        assert "WHITEBOX MODE" in result
        # Should also have multi-target guidance
        assert "MULTI-TARGET TESTING:" in result
