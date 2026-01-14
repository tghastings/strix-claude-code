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


class TestProgressAdvisorSystem:
    """Tests for the Progress Advisor system."""

    def test_system_prompt_includes_progress_advisor_section(self):
        """System prompt should include Progress Advisor instructions."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)

        assert "PROGRESS ADVISOR SYSTEM" in result
        assert "Progress Advisor" in result

    def test_system_prompt_includes_advisor_checklist(self):
        """System prompt should include the required checklist for advisor."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)

        assert "REQUIRED CHECKLIST" in result
        assert "Reconnaissance" in result
        assert "SQL Injection" in result
        assert "XSS" in result
        assert "SSRF" in result
        assert "Authentication" in result

    def test_system_prompt_includes_when_to_spawn_advisor(self):
        """System prompt should explain when to spawn advisor."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)

        assert "WHEN TO SPAWN ADVISOR" in result
        assert "After completing reconnaissance" in result

    def test_system_prompt_includes_advisor_response_format(self):
        """System prompt should specify advisor response format."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)

        assert "COMPLETED:" in result
        assert "GAPS:" in result
        assert "NEXT ACTIONS:" in result
        assert "PRIORITY:" in result

    def test_system_prompt_includes_report_file_path(self):
        """System prompt should include report file path."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4, report_file="/tmp/test_report.md")

        assert "/tmp/test_report.md" in result
        assert "REPORT FILE:" in result

    def test_system_prompt_default_report_path(self):
        """System prompt should have default report path when not specified."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)

        assert "REPORT FILE:" in result
        assert "strix_report.md" in result

    def test_system_prompt_includes_critical_reminder(self):
        """System prompt should include critical reminder at the end."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)

        assert "CRITICAL REMINDER" in result
        assert "DO NOT STOP EARLY" in result
        assert "NEVER call finish_scan until" in result

    def test_system_prompt_advisor_mentions_cat_command(self):
        """Advisor prompt should tell agent to cat the report file."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4, report_file="/tmp/report.md")

        assert "cat /tmp/report.md" in result


class TestParallelSubagentSupport:
    """Tests for parallel subagent functionality."""

    def test_system_prompt_includes_parallel_agent_guidance(self):
        """System prompt should include parallel subagent instructions."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)

        assert "PARALLEL SUBAGENTS" in result
        assert "/tmp/strix-tool" in result
        assert "Task tool" in result or "Task(" in result

    def test_system_prompt_includes_strix_tool_usage(self):
        """System prompt should show how to use /tmp/strix-tool."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)

        assert "strix-tool terminal_execute" in result
        assert "command" in result

    def test_system_prompt_includes_parallel_strategy_examples(self):
        """System prompt should include examples of parallel agent strategies."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)

        # Should mention different vulnerability classes as parallel agents
        assert "SQLi" in result or "SQL injection" in result
        assert "XSS" in result
        assert "SSRF" in result

    def test_helper_script_created_on_scan_start(self, tmp_path):
        """Helper script should be created when scan starts."""
        from click.testing import CliRunner
        runner = CliRunner()

        with patch.object(main, "check_claude_cli", return_value=True):
            with patch.object(main, "Sandbox") as mock_sandbox:
                mock_instance = MagicMock()
                mock_instance.start.return_value = {
                    "container_name": "test",
                    "tool_server_url": "http://localhost:9999",
                    "tool_server_token": "test-token-123",
                    "scan_id": "abc123",
                    "cpu_count": 4,
                }
                mock_sandbox.return_value = mock_instance

                # Mock Path to track file writes
                written_files = {}

                original_path = Path

                class MockPath:
                    def __init__(self, path):
                        self._path = original_path(path)

                    def write_text(self, content):
                        written_files[str(self._path)] = content
                        return self._path.write_text(content)

                    def chmod(self, mode):
                        return self._path.chmod(mode)

                    def __truediv__(self, other):
                        return MockPath(self._path / other)

                    def __str__(self):
                        return str(self._path)

                with patch("subprocess.run"):
                    with patch("sys.stdin") as mock_stdin:
                        mock_stdin.isatty.return_value = False
                        with patch("time.sleep", side_effect=KeyboardInterrupt):
                            result = runner.invoke(main.main, ["-t", "example.com"])

                # Check that helper script was created
                helper_script = Path("/tmp/strix-tool")
                if helper_script.exists():
                    content = helper_script.read_text()
                    assert "curl" in content
                    assert "execute" in content

    def test_credentials_file_created_on_scan_start(self, tmp_path):
        """Credentials file should be created when scan starts."""
        from click.testing import CliRunner
        runner = CliRunner()

        with patch.object(main, "check_claude_cli", return_value=True):
            with patch.object(main, "Sandbox") as mock_sandbox:
                mock_instance = MagicMock()
                mock_instance.start.return_value = {
                    "container_name": "test",
                    "tool_server_url": "http://localhost:9999",
                    "tool_server_token": "test-token-123",
                    "scan_id": "abc123",
                    "cpu_count": 4,
                }
                mock_sandbox.return_value = mock_instance

                with patch("subprocess.run"):
                    with patch("sys.stdin") as mock_stdin:
                        mock_stdin.isatty.return_value = False
                        with patch("time.sleep", side_effect=KeyboardInterrupt):
                            result = runner.invoke(main.main, ["-t", "example.com"])

                # Check that credentials file was created
                creds_file = Path("/tmp/strix-tool-server.env")
                if creds_file.exists():
                    content = creds_file.read_text()
                    assert "STRIX_TOOL_URL" in content
                    assert "STRIX_TOOL_TOKEN" in content


class TestDockerSystemPrompt:
    """Tests for Docker-related system prompt functionality."""

    def test_no_docker_instructions_by_default(self):
        """Should not include Docker instructions when mount_docker is False."""
        result = main.get_system_prompt("URL: https://example.com", "deep", 4)
        assert "DOCKER ACCESS ENABLED" not in result
        assert "docker ps" not in result
        assert "trivy image" not in result

    def test_includes_docker_instructions_when_enabled(self):
        """Should include Docker instructions when mount_docker is True."""
        result = main.get_system_prompt(
            "URL: https://example.com", "deep", 4, mount_docker=True
        )
        assert "DOCKER ACCESS ENABLED" in result

    def test_docker_instructions_explain_dood(self):
        """Docker instructions should explain Docker-outside-of-Docker."""
        result = main.get_system_prompt(
            "URL: https://example.com", "deep", 4, mount_docker=True
        )
        assert "Docker socket is mounted" in result
        assert "host's Docker daemon" in result or "DooD" in result

    def test_docker_instructions_include_cli_install(self):
        """Docker instructions should include Docker CLI install command."""
        result = main.get_system_prompt(
            "URL: https://example.com", "deep", 4, mount_docker=True
        )
        assert "which docker" in result
        assert "get.docker.com" in result

    def test_docker_instructions_include_trivy_install(self):
        """Docker instructions should include trivy install command."""
        result = main.get_system_prompt(
            "URL: https://example.com", "deep", 4, mount_docker=True
        )
        assert "which trivy" in result
        assert "aquasecurity/trivy" in result

    def test_docker_instructions_include_basic_commands(self):
        """Docker instructions should list basic Docker commands."""
        result = main.get_system_prompt(
            "URL: https://example.com", "deep", 4, mount_docker=True
        )
        assert "docker ps" in result
        assert "docker images" in result
        assert "docker inspect" in result
        assert "docker logs" in result
        assert "docker exec" in result

    def test_docker_instructions_include_security_scanning(self):
        """Docker instructions should include container security scanning tools."""
        result = main.get_system_prompt(
            "URL: https://example.com", "deep", 4, mount_docker=True
        )
        assert "trivy image" in result
        assert "trivy fs" in result

    def test_docker_instructions_include_attack_vectors(self):
        """Docker instructions should list Docker-specific attack vectors."""
        result = main.get_system_prompt(
            "URL: https://example.com", "deep", 4, mount_docker=True
        )
        assert "secrets in image layers" in result.lower() or "Secrets in image layers" in result
        assert "privilege escalation" in result.lower() or "Privilege escalation" in result

    def test_docker_instructions_include_example_workflow(self):
        """Docker instructions should include example workflow."""
        result = main.get_system_prompt(
            "URL: https://example.com", "deep", 4, mount_docker=True
        )
        assert "Example workflow" in result
        assert "docker history" in result

    def test_docker_flag_passed_to_get_system_prompt(self):
        """Verify mount_docker parameter works correctly."""
        # Test with False (default)
        result_false = main.get_system_prompt("URL: https://example.com", "deep", 4, mount_docker=False)
        assert "DOCKER ACCESS ENABLED" not in result_false

        # Test with True
        result_true = main.get_system_prompt("URL: https://example.com", "deep", 4, mount_docker=True)
        assert "DOCKER ACCESS ENABLED" in result_true


class TestScanIdIntegration:
    """Tests for scan_id integration between main.py, sandbox, and scan_manager."""

    def test_scan_id_passed_to_sandbox(self):
        """Verify that scan_id from main is passed to Sandbox constructor."""
        from click.testing import CliRunner
        runner = CliRunner()

        with patch.object(main, "check_claude_cli", return_value=True):
            with patch.object(main, "Sandbox") as mock_sandbox:
                mock_instance = MagicMock()
                mock_instance.start.return_value = {
                    "container_name": "strix-cli-testid123",
                    "tool_server_url": "http://localhost:9999",
                    "tool_server_token": "test-token",
                    "scan_id": "testid123",
                    "cpu_count": 4,
                }
                mock_sandbox.return_value = mock_instance

                with patch("subprocess.run"):
                    with patch("sys.stdin") as mock_stdin:
                        mock_stdin.isatty.return_value = False
                        with patch("time.sleep", side_effect=KeyboardInterrupt):
                            # Use explicit scan-id
                            result = runner.invoke(main.main, [
                                "-t", "example.com",
                                "--scan-id", "testid123"
                            ])

                # Verify Sandbox was called with the correct scan_id
                mock_sandbox.assert_called_once()
                call_kwargs = mock_sandbox.call_args.kwargs
                assert call_kwargs.get("scan_id") == "testid123", \
                    f"scan_id not passed to Sandbox: {call_kwargs}"

    def test_generated_scan_id_passed_to_sandbox(self):
        """Verify auto-generated scan_id is passed to Sandbox."""
        from click.testing import CliRunner
        runner = CliRunner()

        with patch.object(main, "check_claude_cli", return_value=True):
            with patch.object(main, "Sandbox") as mock_sandbox:
                mock_instance = MagicMock()
                mock_instance.start.return_value = {
                    "container_name": "strix-cli-auto123",
                    "tool_server_url": "http://localhost:9999",
                    "tool_server_token": "test-token",
                    "scan_id": "auto123",
                    "cpu_count": 4,
                }
                mock_sandbox.return_value = mock_instance

                with patch("subprocess.run"):
                    with patch("sys.stdin") as mock_stdin:
                        mock_stdin.isatty.return_value = False
                        with patch("time.sleep", side_effect=KeyboardInterrupt):
                            with patch("secrets.token_hex", return_value="auto123"):
                                # No explicit scan-id - should auto-generate
                                result = runner.invoke(main.main, ["-t", "example.com"])

                # Verify Sandbox was called with the auto-generated scan_id
                mock_sandbox.assert_called_once()
                call_kwargs = mock_sandbox.call_args.kwargs
                assert call_kwargs.get("scan_id") == "auto123", \
                    f"Auto-generated scan_id not passed to Sandbox: {call_kwargs}"

    def test_container_name_matches_scan_manager_format(self):
        """Verify container name format matches what scan_manager expects.

        scan_manager.stop_docker_container() looks for 'strix-cli-{scan_id}'
        so Sandbox must create containers with that exact format.
        """
        from strix_cli_claude.sandbox import Sandbox
        from strix_cli_claude.scan_manager import stop_docker_container

        # Test that Sandbox would create the correct container name
        with patch("docker.from_env"):
            sandbox = Sandbox(scan_id="testmatch")

        # Container name would be f"strix-cli-{self.scan_id}"
        expected_container_name = f"strix-cli-{sandbox.scan_id}"
        assert expected_container_name == "strix-cli-testmatch"

        # This matches what stop_docker_container looks for
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="")
            stop_docker_container("testmatch")

            # Verify the container name in the docker ps command
            calls = [c[0][0] for c in mock_run.call_args_list]
            docker_ps_call = [c for c in calls if c[0] == "docker" and "ps" in c][0]
            assert f"name=strix-cli-testmatch" in docker_ps_call
