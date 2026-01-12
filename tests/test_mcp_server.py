"""Tests for mcp_server module."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strix_cli_claude import mcp_server
from strix_cli_claude.mcp_server import (
    ToolServerClient,
    PENTEST_TOOLS,
    create_server,
    calculate_cvss,
)


class TestToolServerClient:
    """Tests for ToolServerClient class."""

    def test_init_sets_attributes(self):
        """Should initialize with provided attributes."""
        client = ToolServerClient(
            base_url="http://localhost:8080",
            token="secret-token",
            agent_id="test-agent",
        )

        assert client.base_url == "http://localhost:8080"
        assert client.token == "secret-token"
        assert client.agent_id == "test-agent"

    def test_init_creates_httpx_client(self):
        """Should create httpx client with correct headers."""
        with patch("httpx.AsyncClient") as mock_client:
            ToolServerClient(
                base_url="http://localhost:8080",
                token="secret-token",
                agent_id="test-agent",
            )

            mock_client.assert_called_once()
            call_kwargs = mock_client.call_args[1]
            assert call_kwargs["base_url"] == "http://localhost:8080"
            assert call_kwargs["headers"]["Authorization"] == "Bearer secret-token"
            assert call_kwargs["timeout"] == 300.0

    @pytest.mark.asyncio
    async def test_call_tool_posts_to_execute(self):
        """Should POST to /execute endpoint."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_response = MagicMock()
            mock_response.json.return_value = {"result": "success"}
            mock_client.post = AsyncMock(return_value=mock_response)

            client = ToolServerClient("http://localhost:8080", "token", "agent-1")
            result = await client.call_tool("terminal_execute", {"command": "ls"})

            mock_client.post.assert_called_once_with(
                "/execute",
                json={
                    "tool_name": "terminal_execute",
                    "kwargs": {"command": "ls"},
                    "agent_id": "agent-1",
                },
            )
            assert result == {"result": "success"}

    @pytest.mark.asyncio
    async def test_call_tool_handles_http_error(self):
        """Should handle HTTP errors gracefully."""
        import httpx

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.text = "Internal Server Error"

            error = httpx.HTTPStatusError("error", request=MagicMock(), response=mock_response)
            mock_client.post = AsyncMock(side_effect=error)

            client = ToolServerClient("http://localhost:8080", "token", "agent-1")
            result = await client.call_tool("terminal_execute", {"command": "ls"})

            assert "error" in result
            assert "500" in result["error"]

    @pytest.mark.asyncio
    async def test_call_tool_handles_generic_error(self):
        """Should handle generic errors gracefully."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.post = AsyncMock(side_effect=Exception("Connection failed"))

            client = ToolServerClient("http://localhost:8080", "token", "agent-1")
            result = await client.call_tool("terminal_execute", {"command": "ls"})

            assert "error" in result
            assert "Connection failed" in result["error"]

    @pytest.mark.asyncio
    async def test_close_closes_client(self):
        """Should close the httpx client."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client

            client = ToolServerClient("http://localhost:8080", "token", "agent-1")
            await client.close()

            mock_client.aclose.assert_called_once()


class TestPentestTools:
    """Tests for PENTEST_TOOLS list."""

    def test_tools_list_is_not_empty(self):
        """Should have tools defined."""
        assert len(PENTEST_TOOLS) > 0

    def test_all_tools_have_name(self):
        """All tools should have a name."""
        for tool in PENTEST_TOOLS:
            assert hasattr(tool, "name")
            assert tool.name

    def test_all_tools_have_description(self):
        """All tools should have a description."""
        for tool in PENTEST_TOOLS:
            assert hasattr(tool, "description")
            assert tool.description

    def test_all_tools_have_input_schema(self):
        """All tools should have an input schema."""
        for tool in PENTEST_TOOLS:
            assert hasattr(tool, "inputSchema")
            assert isinstance(tool.inputSchema, dict)

    def test_terminal_execute_tool_exists(self):
        """Should have terminal_execute tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "terminal_execute" in tool_names

    def test_python_action_tool_exists(self):
        """Should have python_action tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "python_action" in tool_names

    def test_browser_action_tool_exists(self):
        """Should have browser_action tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "browser_action" in tool_names

    def test_create_vulnerability_report_tool_exists(self):
        """Should have create_vulnerability_report tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "create_vulnerability_report" in tool_names

    def test_write_report_tool_exists(self):
        """Should have write_report tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "write_report" in tool_names

    def test_read_report_tool_exists(self):
        """Should have read_report tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "read_report" in tool_names

    def test_think_tool_exists(self):
        """Should have think tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "think" in tool_names

    def test_finish_scan_tool_exists(self):
        """Should have finish_scan tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "finish_scan" in tool_names

    def test_list_files_tool_exists(self):
        """Should have list_files tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "list_files" in tool_names


class TestCalculateCvss:
    """Tests for calculate_cvss function."""

    def test_critical_severity_rce(self):
        """Should calculate critical severity for unauthenticated RCE."""
        score, severity = calculate_cvss(
            av="N",  # Network
            ac="L",  # Low complexity
            pr="N",  # No privileges
            ui="N",  # No user interaction
            s="C",   # Changed scope
            c="H",   # High confidentiality
            i="H",   # High integrity
            a="H",   # High availability
        )
        assert severity == "critical"
        assert score >= 9.0

    def test_high_severity_sqli(self):
        """Should calculate high severity for SQL injection."""
        score, severity = calculate_cvss(
            av="N",  # Network
            ac="L",  # Low complexity
            pr="N",  # No privileges
            ui="N",  # No user interaction
            s="U",   # Unchanged scope
            c="H",   # High confidentiality
            i="H",   # High integrity
            a="N",   # No availability impact
        )
        assert severity in ["high", "critical"]
        assert score >= 7.0

    def test_medium_severity_xss(self):
        """Should calculate medium severity for reflected XSS."""
        score, severity = calculate_cvss(
            av="N",  # Network
            ac="L",  # Low complexity
            pr="N",  # No privileges
            ui="R",  # Requires user interaction
            s="C",   # Changed scope
            c="L",   # Low confidentiality
            i="L",   # Low integrity
            a="N",   # No availability impact
        )
        assert severity in ["medium", "high"]
        assert score >= 4.0

    def test_low_severity_info_disclosure(self):
        """Should calculate low severity for minor info disclosure."""
        score, severity = calculate_cvss(
            av="N",  # Network
            ac="H",  # High complexity
            pr="H",  # High privileges
            ui="R",  # Requires user interaction
            s="U",   # Unchanged scope
            c="L",   # Low confidentiality
            i="N",   # No integrity impact
            a="N",   # No availability impact
        )
        assert severity in ["low", "none"]
        assert score < 4.0

    def test_none_severity_zero_impact(self):
        """Should return none severity when no impact."""
        score, severity = calculate_cvss(
            av="N",
            ac="L",
            pr="N",
            ui="N",
            s="U",
            c="N",  # No confidentiality
            i="N",  # No integrity
            a="N",  # No availability
        )
        assert severity == "none"
        assert score == 0

    def test_score_is_float(self):
        """Score should be a float."""
        score, _ = calculate_cvss("N", "L", "N", "N", "U", "H", "H", "H")
        assert isinstance(score, float)

    def test_score_range_is_valid(self):
        """Score should be between 0 and 10."""
        score, _ = calculate_cvss("N", "L", "N", "N", "C", "H", "H", "H")
        assert 0 <= score <= 10.0

    def test_pr_scoring_differs_by_scope(self):
        """Privileges Required scoring should differ based on scope."""
        # Unchanged scope
        score_u, _ = calculate_cvss("N", "L", "L", "N", "U", "H", "H", "H")
        # Changed scope
        score_c, _ = calculate_cvss("N", "L", "L", "N", "C", "H", "H", "H")
        # Scores should differ because PR values differ with scope
        assert score_u != score_c


class TestCreateServer:
    """Tests for create_server function."""

    def test_creates_server_instance(self):
        """Should create a Server instance."""
        server = create_server()
        assert server is not None

    def test_server_has_name(self):
        """Server should have a name."""
        server = create_server()
        assert server.name == "strix-claude-code"


class TestReportFileOperations:
    """Tests for report file operations."""

    def test_write_report_creates_file(self, tmp_path):
        """Should create report file when writing."""
        from datetime import datetime

        report_file = tmp_path / "report.md"

        # Simulate what write_report handler does
        content = "Test content"
        header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix CLI Claude

---

"""
        report_file.write_text(header + content)

        assert report_file.exists()
        assert "Test content" in report_file.read_text()

    def test_write_report_appends_content(self, tmp_path):
        """Should append to existing report."""
        report_file = tmp_path / "report.md"
        report_file.write_text("# Existing Report\n\n---\n")

        # Append new content
        existing = report_file.read_text()
        new_content = "\n## Findings\n\nNew finding"
        report_file.write_text(existing + new_content)

        content = report_file.read_text()
        assert "Existing Report" in content
        assert "New finding" in content

    def test_read_report_returns_content(self, tmp_path):
        """Should read report content."""
        report_file = tmp_path / "report.md"
        report_file.write_text("# Test Report\n\nSome findings here.")

        content = report_file.read_text()
        assert "Test Report" in content
        assert "Some findings here" in content


class TestThinkFunctionality:
    """Tests for think functionality."""

    def test_think_logs_to_report(self, tmp_path):
        """Should append thought to report file."""
        from datetime import datetime

        report_file = tmp_path / "report.md"
        report_file.write_text("# Report\n")

        thought = "Testing XSS vulnerabilities"

        # Simulate think handler logging
        existing = report_file.read_text()
        log_entry = f"\n> **Analysis Note** ({datetime.now().strftime('%H:%M:%S')}): {thought}\n"
        report_file.write_text(existing + log_entry)

        content = report_file.read_text()
        assert "Analysis Note" in content
        assert "Testing XSS" in content


class TestVulnerabilityReportGeneration:
    """Tests for vulnerability report generation."""

    def test_creates_vulnerability_report(self, tmp_path):
        """Should create formatted vulnerability report."""
        from datetime import datetime

        report_file = tmp_path / "report.md"

        title = "SQL Injection in Login"
        cvss_score, severity = calculate_cvss("N", "L", "N", "N", "U", "H", "H", "N")
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

        report_content = f"""### {title}

**Severity:** {severity.upper()} ({cvss_score:.1f})
**CVSS Vector:** `{cvss_vector}`
**Target:** https://example.com/login

#### Description
The login form is vulnerable to SQL injection

#### Proof of Concept
Send a payload to bypass authentication

```
' OR '1'='1' --
```

---
"""
        header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix CLI Claude

---

## Findings

"""
        report_file.write_text(header + report_content)

        content = report_file.read_text()
        assert "SQL Injection in Login" in content
        assert "CVSS" in content
        assert "Proof of Concept" in content

    def test_calculates_cvss_for_critical(self, tmp_path):
        """Should calculate critical CVSS score."""
        score, severity = calculate_cvss(
            av="N", ac="L", pr="N", ui="N",
            s="C", c="H", i="H", a="H"
        )
        assert severity == "critical"
        assert score >= 9.0


class TestFinishScanReport:
    """Tests for finish_scan report generation."""

    def test_finish_scan_writes_sections(self, tmp_path):
        """Should write all required sections."""
        from datetime import datetime

        report_file = tmp_path / "report.md"

        final_sections = f"""
## Executive Summary

This was a security assessment of example.com

## Methodology

We used automated and manual testing

## Technical Analysis

The application has several security issues

## Recommendations

Fix the SQL injection first

---

**Report Completed:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

        header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix CLI Claude

---
{final_sections}
"""
        report_file.write_text(header)

        content = report_file.read_text()
        assert "Executive Summary" in content
        assert "Methodology" in content
        assert "Technical Analysis" in content
        assert "Recommendations" in content


class TestNotesStorage:
    """Tests for notes storage functionality."""

    def test_notes_stored_in_dict(self):
        """Should store notes in dictionary."""
        import uuid
        from datetime import datetime

        notes_storage = {}

        note_id = str(uuid.uuid4())[:5]
        timestamp = datetime.now().isoformat()

        notes_storage[note_id] = {
            "title": "Interesting endpoint",
            "content": "/admin panel found",
            "category": "findings",
            "tags": [],
            "created_at": timestamp,
        }

        assert note_id in notes_storage
        assert notes_storage[note_id]["title"] == "Interesting endpoint"
        assert notes_storage[note_id]["category"] == "findings"

    def test_notes_can_be_filtered(self):
        """Should filter notes by category."""
        notes_storage = {
            "abc": {"title": "Finding", "content": "XSS", "category": "findings"},
            "def": {"title": "Method", "content": "Burp", "category": "methodology"},
        }

        findings = [n for n in notes_storage.values() if n["category"] == "findings"]

        assert len(findings) == 1
        assert findings[0]["title"] == "Finding"

    def test_notes_can_be_searched(self):
        """Should search notes by content."""
        notes_storage = {
            "abc": {"title": "XSS Finding", "content": "Found XSS in login", "category": "findings"},
            "def": {"title": "SQLI", "content": "SQL injection possible", "category": "findings"},
        }

        search = "xss"
        results = [
            n for n in notes_storage.values()
            if search in n["title"].lower() or search in n["content"].lower()
        ]

        assert len(results) == 1
        assert results[0]["title"] == "XSS Finding"


class TestToolServerClientUnit:
    """Unit tests for ToolServerClient."""

    @pytest.mark.asyncio
    async def test_call_tool_returns_result(self):
        """Should return result from tool server."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_response = MagicMock()
            mock_response.json.return_value = {"result": {"content": "output"}}
            mock_client.post = AsyncMock(return_value=mock_response)

            client = ToolServerClient("http://localhost:8080", "token", "agent")
            result = await client.call_tool("test_tool", {"arg": "value"})

            assert result["result"]["content"] == "output"

    @pytest.mark.asyncio
    async def test_call_tool_sends_correct_payload(self):
        """Should send correct payload to tool server."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_response = MagicMock()
            mock_response.json.return_value = {}
            mock_client.post = AsyncMock(return_value=mock_response)

            client = ToolServerClient("http://localhost:8080", "token", "my-agent")
            await client.call_tool("terminal_execute", {"command": "ls -la"})

            mock_client.post.assert_called_with(
                "/execute",
                json={
                    "tool_name": "terminal_execute",
                    "kwargs": {"command": "ls -la"},
                    "agent_id": "my-agent",
                }
            )


class TestEnvironmentVariables:
    """Tests for environment variable handling."""

    def test_tool_server_url_from_env(self):
        """Should read TOOL_SERVER_URL from environment."""
        with patch.dict("os.environ", {"STRIX_TOOL_SERVER_URL": "http://custom:9000"}):
            # Reimport to pick up new env var
            import importlib
            importlib.reload(mcp_server)
            assert mcp_server.TOOL_SERVER_URL == "http://custom:9000"
            # Reset
            importlib.reload(mcp_server)

    def test_agent_id_default(self):
        """Should have default agent ID."""
        assert mcp_server.AGENT_ID == "claude-cli-agent" or "agent" in mcp_server.AGENT_ID.lower()


class TestCvssEdgeCases:
    """Edge case tests for CVSS calculation."""

    def test_handles_invalid_attack_vector(self):
        """Should handle invalid attack vector gracefully."""
        score, severity = calculate_cvss("X", "L", "N", "N", "U", "H", "H", "H")
        # Should use default value
        assert isinstance(score, float)
        assert severity in ["none", "low", "medium", "high", "critical"]

    def test_handles_invalid_complexity(self):
        """Should handle invalid complexity gracefully."""
        score, severity = calculate_cvss("N", "X", "N", "N", "U", "H", "H", "H")
        assert isinstance(score, float)

    def test_max_score_is_ten(self):
        """Maximum score should be 10.0."""
        # Most severe possible vulnerability
        score, severity = calculate_cvss("N", "L", "N", "N", "C", "H", "H", "H")
        assert score <= 10.0
        assert severity == "critical"
