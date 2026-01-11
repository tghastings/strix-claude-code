"""MCP server that exposes penetration testing tools to Claude CLI."""

import asyncio
import json
import logging
import os
import sys
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

logger = logging.getLogger(__name__)

# Tool server connection info (set by main.py before starting MCP server)
TOOL_SERVER_URL = os.getenv("STRIX_TOOL_SERVER_URL", "")
TOOL_SERVER_TOKEN = os.getenv("STRIX_TOOL_SERVER_TOKEN", "")
AGENT_ID = os.getenv("STRIX_AGENT_ID", "claude-cli-agent")
REPORT_FILE = os.getenv("STRIX_REPORT_FILE", "")


class ToolServerClient:
    """Client to communicate with the sandbox tool server."""

    def __init__(self, base_url: str, token: str, agent_id: str):
        self.base_url = base_url
        self.token = token
        self.agent_id = agent_id
        self.client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=300.0,
        )

    async def call_tool(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Call a tool on the sandbox tool server."""
        try:
            response = await self.client.post(
                "/execute",
                json={
                    "tool_name": tool_name,
                    "kwargs": params,
                    "agent_id": self.agent_id,
                },
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            return {"error": f"HTTP error: {e.response.status_code} - {e.response.text}"}
        except Exception as e:
            return {"error": str(e)}

    async def close(self):
        await self.client.aclose()


# Define the tools available for pen testing
PENTEST_TOOLS = [
    Tool(
        name="terminal_execute",
        description="""Execute shell commands in the Kali Linux sandbox.

Available tools include:
- Reconnaissance: nmap, subfinder, httpx, gospider, katana
- Vulnerability scanning: nuclei, sqlmap, zaproxy, wapiti
- Fuzzing: ffuf, dirsearch, arjun
- Code analysis: semgrep, bandit, trufflehog
- JWT: jwt_tool
- WAF detection: wafw00f

The /workspace directory is shared and persistent.""",
        inputSchema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute",
                },
                "terminal_id": {
                    "type": "string",
                    "description": "Terminal session ID (default: 'main')",
                    "default": "main",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Command timeout in seconds (default: 300)",
                    "default": 300,
                },
            },
            "required": ["command"],
        },
    ),
    Tool(
        name="python_action",
        description="""Execute Python code in the sandbox.

Pre-imported libraries:
- requests, httpx, aiohttp for HTTP
- bs4 (BeautifulSoup) for HTML parsing
- json, base64, hashlib for encoding
- re for regex
- asyncio for async operations

Use for:
- Custom exploit scripts
- Payload generation
- Automated testing loops
- Data processing

Actions: "execute" (run code), "new_session" (create session), "list_sessions", "close" """,
        inputSchema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["execute", "new_session", "list_sessions", "close"],
                    "description": "Action to perform (use 'execute' to run code)",
                },
                "code": {
                    "type": "string",
                    "description": "Python code to execute",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default: 30)",
                    "default": 30,
                },
                "session_id": {
                    "type": "string",
                    "description": "Session ID for persistent sessions",
                },
            },
            "required": ["action"],
        },
    ),
    Tool(
        name="browser_action",
        description="""Control a Playwright browser for web testing.

Actions:
- launch: Start browser (headless)
- goto: Navigate to URL
- click: Click element by selector
- type: Type text into element
- scroll: Scroll page (up/down/to element)
- screenshot: Take screenshot
- execute_js: Run JavaScript
- get_html: Get page HTML
- close: Close browser

The browser uses the Caido proxy automatically.""",
        inputSchema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["launch", "goto", "click", "type", "scroll", "screenshot", "execute_js", "get_html", "close"],
                    "description": "Browser action to perform",
                },
                "url": {"type": "string", "description": "URL for goto action"},
                "selector": {"type": "string", "description": "CSS selector for click/type actions"},
                "text": {"type": "string", "description": "Text for type action"},
                "script": {"type": "string", "description": "JavaScript for execute_js action"},
                "direction": {"type": "string", "description": "Scroll direction: up, down, or selector"},
            },
            "required": ["action"],
        },
    ),
    Tool(
        name="list_requests",
        description="""List HTTP requests captured by the Caido proxy.

Filter by:
- host: Filter by hostname
- method: GET, POST, PUT, DELETE, etc.
- path: URL path pattern
- status_code: Response status

Returns request/response summary for analysis.""",
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Filter by hostname"},
                "method": {"type": "string", "description": "Filter by HTTP method"},
                "path": {"type": "string", "description": "Filter by path pattern"},
                "status_code": {"type": "integer", "description": "Filter by status code"},
                "limit": {"type": "integer", "description": "Max results (default: 50)", "default": 50},
            },
        },
    ),
    Tool(
        name="view_request",
        description="""View detailed request/response from proxy history.

Returns full headers and body for both request and response.""",
        inputSchema={
            "type": "object",
            "properties": {
                "request_id": {
                    "type": "string",
                    "description": "Request ID from list_requests",
                },
            },
            "required": ["request_id"],
        },
    ),
    Tool(
        name="send_request",
        description="""Send an HTTP request through the proxy.

For manual testing and exploitation.
Supports all HTTP methods and custom headers.""",
        inputSchema={
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "HTTP method"},
                "url": {"type": "string", "description": "Full URL"},
                "headers": {"type": "object", "description": "Request headers"},
                "body": {"type": "string", "description": "Request body"},
            },
            "required": ["method", "url"],
        },
    ),
    Tool(
        name="repeat_request",
        description="""Modify and replay a captured request.

Useful for testing parameter variations and payloads.""",
        inputSchema={
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "Original request ID"},
                "modifications": {
                    "type": "object",
                    "description": "Modifications: {headers: {}, params: {}, body: string}",
                },
            },
            "required": ["request_id"],
        },
    ),
    Tool(
        name="str_replace_editor",
        description="""View, create, or edit files in the sandbox.

Commands:
- view: Read file contents (use view_range for specific lines)
- create: Create a new file with file_text content
- str_replace: Replace old_str with new_str in file
- insert: Insert new_str at insert_line

All paths relative to /workspace.""",
        inputSchema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["view", "create", "str_replace", "insert"],
                    "description": "File operation command",
                },
                "path": {"type": "string", "description": "File path"},
                "file_text": {"type": "string", "description": "Content for create command"},
                "view_range": {"type": "array", "items": {"type": "integer"}, "description": "[start_line, end_line] for view"},
                "old_str": {"type": "string", "description": "String to replace (str_replace)"},
                "new_str": {"type": "string", "description": "Replacement string (str_replace/insert)"},
                "insert_line": {"type": "integer", "description": "Line number for insert"},
            },
            "required": ["command", "path"],
        },
    ),
    Tool(
        name="list_files",
        description="""List files in a directory in the sandbox.""",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory path"},
                "recursive": {"type": "boolean", "description": "List recursively", "default": False},
            },
            "required": ["path"],
        },
    ),
    Tool(
        name="create_vulnerability_report",
        description="""Create a formal vulnerability report. REQUIRED for every confirmed vulnerability.

This writes a detailed finding to the markdown report file with CVSS scoring.
Include complete technical details and proof-of-concept code.""",
        inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Vulnerability title"},
                "description": {"type": "string", "description": "What the vulnerability is"},
                "impact": {"type": "string", "description": "Business/security impact"},
                "target": {"type": "string", "description": "Affected endpoint/component"},
                "technical_analysis": {"type": "string", "description": "Technical details of how it works"},
                "poc_description": {"type": "string", "description": "PoC explanation"},
                "poc_script_code": {"type": "string", "description": "Actual exploit/PoC code"},
                "remediation_steps": {"type": "string", "description": "How to fix"},
                "attack_vector": {
                    "type": "string",
                    "enum": ["N", "A", "L", "P"],
                    "description": "CVSS Attack Vector: N=Network, A=Adjacent, L=Local, P=Physical",
                },
                "attack_complexity": {
                    "type": "string",
                    "enum": ["L", "H"],
                    "description": "CVSS Attack Complexity: L=Low, H=High",
                },
                "privileges_required": {
                    "type": "string",
                    "enum": ["N", "L", "H"],
                    "description": "CVSS Privileges Required: N=None, L=Low, H=High",
                },
                "user_interaction": {
                    "type": "string",
                    "enum": ["N", "R"],
                    "description": "CVSS User Interaction: N=None, R=Required",
                },
                "scope": {
                    "type": "string",
                    "enum": ["U", "C"],
                    "description": "CVSS Scope: U=Unchanged, C=Changed",
                },
                "confidentiality": {
                    "type": "string",
                    "enum": ["N", "L", "H"],
                    "description": "CVSS Confidentiality Impact: N=None, L=Low, H=High",
                },
                "integrity": {
                    "type": "string",
                    "enum": ["N", "L", "H"],
                    "description": "CVSS Integrity Impact: N=None, L=Low, H=High",
                },
                "availability": {
                    "type": "string",
                    "enum": ["N", "L", "H"],
                    "description": "CVSS Availability Impact: N=None, L=Low, H=High",
                },
                "endpoint": {"type": "string", "description": "Specific endpoint/URL affected"},
                "method": {"type": "string", "description": "HTTP method if applicable"},
            },
            "required": ["title", "description", "impact", "target", "technical_analysis", "poc_description", "poc_script_code", "remediation_steps", "attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope", "confidentiality", "integrity", "availability"],
        },
    ),
    Tool(
        name="write_report",
        description="""Write findings to the markdown report file on the host machine.

Use this to document all findings, vulnerabilities, and scan results.
The report is saved to the location specified when starting the scan.

Call this tool to:
- Add a new finding/vulnerability
- Update the executive summary
- Add reconnaissance results
- Document the methodology used

Content should be valid markdown.""",
        inputSchema={
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Markdown content to append to the report",
                },
                "section": {
                    "type": "string",
                    "enum": ["header", "executive_summary", "findings", "reconnaissance", "methodology", "appendix"],
                    "description": "Report section (findings is default)",
                    "default": "findings",
                },
                "overwrite": {
                    "type": "boolean",
                    "description": "If true, overwrite the entire report instead of appending",
                    "default": False,
                },
            },
            "required": ["content"],
        },
    ),
    Tool(
        name="read_report",
        description="""Read the current contents of the security report file.

Use this to review what has been documented so far.""",
        inputSchema={
            "type": "object",
            "properties": {},
        },
    ),
    Tool(
        name="create_note",
        description="""Create a note to save information during the assessment.

Use for:
- Saving interesting findings for later investigation
- Recording observations and hypotheses
- Tracking attack paths to explore
- Documenting methodology decisions""",
        inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Note title"},
                "content": {"type": "string", "description": "Note content"},
                "category": {
                    "type": "string",
                    "enum": ["general", "findings", "methodology", "questions", "plan"],
                    "description": "Note category",
                    "default": "general",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Tags for organization",
                },
            },
            "required": ["title", "content"],
        },
    ),
    Tool(
        name="list_notes",
        description="""List saved notes, optionally filtered by category or search.""",
        inputSchema={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["general", "findings", "methodology", "questions", "plan"],
                    "description": "Filter by category",
                },
                "search": {"type": "string", "description": "Search in title/content"},
            },
        },
    ),
    Tool(
        name="think",
        description="""Use this tool for complex reasoning, planning, and analysis.

Call this when you need to:
- Plan your attack strategy
- Analyze findings before reporting
- Work through complex logic
- Reason about potential vulnerabilities

Your thought will be logged to the report for documentation.""",
        inputSchema={
            "type": "object",
            "properties": {
                "thought": {
                    "type": "string",
                    "description": "Your reasoning, analysis, or planning thoughts",
                },
            },
            "required": ["thought"],
        },
    ),
    Tool(
        name="finish_scan",
        description="""Finalize the security assessment and write the complete report.

Call this when you have completed all testing and want to finalize the report.
This writes the executive summary, methodology, analysis, and recommendations.

ONLY call this when you are completely done with the assessment.""",
        inputSchema={
            "type": "object",
            "properties": {
                "executive_summary": {
                    "type": "string",
                    "description": "High-level summary of findings for executives (2-3 paragraphs)",
                },
                "methodology": {
                    "type": "string",
                    "description": "Testing methodology used (tools, techniques, approach)",
                },
                "technical_analysis": {
                    "type": "string",
                    "description": "Detailed technical analysis of the security posture",
                },
                "recommendations": {
                    "type": "string",
                    "description": "Prioritized recommendations for remediation",
                },
            },
            "required": ["executive_summary", "methodology", "technical_analysis", "recommendations"],
        },
    ),
]


def create_server() -> Server:
    """Create the MCP server with pentest tools."""
    server = Server("strix-cli-claude")

    tool_client: ToolServerClient | None = None

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return PENTEST_TOOLS

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        nonlocal tool_client

        # Handle local tools (write to host filesystem)
        if name == "write_report":
            return await handle_write_report(arguments)

        if name == "create_vulnerability_report":
            return await handle_create_vulnerability_report(arguments)

        if name == "think":
            return await handle_think(arguments)

        if name == "finish_scan":
            return await handle_finish_scan(arguments)

        if name == "create_note":
            return await handle_create_note(arguments)

        if name == "list_notes":
            return await handle_list_notes(arguments)

        if name == "read_report":
            return await handle_read_report()

        if not TOOL_SERVER_URL or not TOOL_SERVER_TOKEN:
            return [TextContent(
                type="text",
                text="Error: Tool server not configured. Make sure STRIX_TOOL_SERVER_URL and STRIX_TOOL_SERVER_TOKEN are set.",
            )]

        if tool_client is None:
            tool_client = ToolServerClient(TOOL_SERVER_URL, TOOL_SERVER_TOKEN, AGENT_ID)

        result = await tool_client.call_tool(name, arguments)

        # Check for error in response
        if result.get("error"):
            return [TextContent(type="text", text=f"Error: {result['error']}")]

        # Extract the actual result - tool server returns {"result": {...}, "error": null}
        tool_result = result.get("result", result)

        # Format output - look for content field first (terminal_execute, etc.)
        if isinstance(tool_result, dict):
            if "content" in tool_result:
                output = tool_result["content"]
                # Add status info if available
                if tool_result.get("status") == "error":
                    output = f"Error: {output}"
                elif tool_result.get("exit_code") is not None and tool_result.get("exit_code") != 0:
                    output = f"{output}\n[Exit code: {tool_result['exit_code']}]"
            elif "error" in tool_result and tool_result["error"]:
                output = f"Error: {tool_result['error']}"
            else:
                output = json.dumps(tool_result, indent=2)
        else:
            output = str(tool_result)

        return [TextContent(type="text", text=output)]

    async def handle_write_report(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle write_report tool - writes to host filesystem."""
        if not REPORT_FILE:
            return [TextContent(type="text", text="Error: No report file configured")]

        content = arguments.get("content", "")
        section = arguments.get("section", "findings")
        overwrite = arguments.get("overwrite", False)

        try:
            from pathlib import Path
            from datetime import datetime

            report_path = Path(REPORT_FILE)

            # Create report with header if it doesn't exist or overwriting
            if overwrite or not report_path.exists():
                header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix CLI Claude

---

"""
                report_path.write_text(header + content)
                return [TextContent(type="text", text=f"Report created: {REPORT_FILE}")]

            # Append to existing report
            existing = report_path.read_text()

            # Add section header if needed
            section_headers = {
                "executive_summary": "\n## Executive Summary\n\n",
                "findings": "\n## Findings\n\n",
                "reconnaissance": "\n## Reconnaissance\n\n",
                "methodology": "\n## Methodology\n\n",
                "appendix": "\n## Appendix\n\n",
            }

            section_header = section_headers.get(section, "\n")

            # Only add section header if it's not already in the report
            if section != "header" and section_header.strip() not in existing:
                content = section_header + content
            else:
                content = "\n" + content

            report_path.write_text(existing + content)
            return [TextContent(type="text", text=f"Appended to report: {REPORT_FILE}")]

        except Exception as e:
            return [TextContent(type="text", text=f"Error writing report: {e}")]

    async def handle_create_vulnerability_report(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle create_vulnerability_report - calculates CVSS and writes to report."""
        if not REPORT_FILE:
            return [TextContent(type="text", text="Error: No report file configured")]

        try:
            from pathlib import Path
            from datetime import datetime

            # Extract arguments
            title = arguments.get("title", "")
            description = arguments.get("description", "")
            impact = arguments.get("impact", "")
            target = arguments.get("target", "")
            technical_analysis = arguments.get("technical_analysis", "")
            poc_description = arguments.get("poc_description", "")
            poc_script_code = arguments.get("poc_script_code", "")
            remediation_steps = arguments.get("remediation_steps", "")
            endpoint = arguments.get("endpoint", "")
            method = arguments.get("method", "")

            # CVSS parameters
            av = arguments.get("attack_vector", "N")
            ac = arguments.get("attack_complexity", "L")
            pr = arguments.get("privileges_required", "N")
            ui = arguments.get("user_interaction", "N")
            s = arguments.get("scope", "U")
            c = arguments.get("confidentiality", "H")
            i = arguments.get("integrity", "H")
            a = arguments.get("availability", "N")

            # Calculate CVSS 3.1 score
            cvss_vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
            cvss_score, severity = calculate_cvss(av, ac, pr, ui, s, c, i, a)

            # Format the vulnerability report
            report_content = f"""
### {title}

**Severity:** {severity.upper()} ({cvss_score:.1f})
**CVSS Vector:** `{cvss_vector}`
**Target:** {target}
{f"**Endpoint:** {endpoint}" if endpoint else ""}
{f"**Method:** {method}" if method else ""}

#### Description
{description}

#### Impact
{impact}

#### Technical Analysis
{technical_analysis}

#### Proof of Concept
{poc_description}

```
{poc_script_code}
```

#### Remediation
{remediation_steps}

---
"""

            # Write to report file
            report_path = Path(REPORT_FILE)

            if not report_path.exists():
                header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix CLI Claude

---

## Findings

"""
                report_path.write_text(header + report_content)
            else:
                existing = report_path.read_text()
                if "## Findings" not in existing:
                    existing += "\n## Findings\n"
                report_path.write_text(existing + report_content)

            return [TextContent(
                type="text",
                text=f"Vulnerability report created: {title}\nSeverity: {severity.upper()} (CVSS {cvss_score:.1f})\nSaved to: {REPORT_FILE}"
            )]

        except Exception as e:
            return [TextContent(type="text", text=f"Error creating vulnerability report: {e}")]

    async def handle_think(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle think tool - logs reasoning to report."""
        thought = arguments.get("thought", "")

        if not thought or not thought.strip():
            return [TextContent(type="text", text="Error: Thought cannot be empty")]

        # Optionally log to report file
        if REPORT_FILE:
            try:
                from pathlib import Path
                from datetime import datetime

                report_path = Path(REPORT_FILE)

                if report_path.exists():
                    existing = report_path.read_text()
                    # Add to methodology/analysis section if exists, otherwise just append
                    log_entry = f"\n> **Analysis Note** ({datetime.now().strftime('%H:%M:%S')}): {thought[:500]}{'...' if len(thought) > 500 else ''}\n"
                    report_path.write_text(existing + log_entry)
            except Exception:
                pass  # Non-critical, just skip logging

        return [TextContent(
            type="text",
            text=f"Thought recorded ({len(thought.strip())} chars). Continue with your analysis."
        )]

    async def handle_finish_scan(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle finish_scan - writes final report sections."""
        if not REPORT_FILE:
            return [TextContent(type="text", text="Error: No report file configured")]

        executive_summary = arguments.get("executive_summary", "")
        methodology = arguments.get("methodology", "")
        technical_analysis = arguments.get("technical_analysis", "")
        recommendations = arguments.get("recommendations", "")

        # Validate
        errors = []
        if not executive_summary.strip():
            errors.append("Executive summary cannot be empty")
        if not methodology.strip():
            errors.append("Methodology cannot be empty")
        if not technical_analysis.strip():
            errors.append("Technical analysis cannot be empty")
        if not recommendations.strip():
            errors.append("Recommendations cannot be empty")

        if errors:
            return [TextContent(type="text", text=f"Validation errors: {', '.join(errors)}")]

        try:
            from pathlib import Path
            from datetime import datetime

            report_path = Path(REPORT_FILE)

            # Build final report sections
            final_sections = f"""
## Executive Summary

{executive_summary}

## Methodology

{methodology}

## Technical Analysis

{technical_analysis}

## Recommendations

{recommendations}

---

**Report Completed:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

            if report_path.exists():
                existing = report_path.read_text()
                # Insert executive summary at the beginning (after header)
                if "## Executive Summary" not in existing:
                    # Find end of header section
                    if "---" in existing:
                        parts = existing.split("---", 2)
                        if len(parts) >= 2:
                            new_content = parts[0] + "---" + final_sections + "\n---".join(parts[2:]) if len(parts) > 2 else parts[0] + "---" + final_sections
                            report_path.write_text(new_content)
                        else:
                            report_path.write_text(existing + final_sections)
                    else:
                        report_path.write_text(existing + final_sections)
                else:
                    # Already has sections, append recommendations update
                    report_path.write_text(existing + f"\n\n---\n**Report Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            else:
                # Create new report with all sections
                header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix CLI Claude

---
{final_sections}
"""
                report_path.write_text(header)

            return [TextContent(
                type="text",
                text=f"Scan completed successfully!\nReport saved to: {REPORT_FILE}\n\nThe report includes:\n- Executive Summary\n- Methodology\n- Technical Analysis\n- Recommendations\n- All vulnerability findings"
            )]

        except Exception as e:
            return [TextContent(type="text", text=f"Error finishing scan: {e}")]

    async def handle_read_report() -> list[TextContent]:
        """Handle read_report - reads the report from host filesystem."""
        if not REPORT_FILE:
            return [TextContent(type="text", text="Error: No report file configured")]

        try:
            from pathlib import Path
            report_path = Path(REPORT_FILE)

            if not report_path.exists():
                return [TextContent(type="text", text=f"Report file does not exist yet: {REPORT_FILE}")]

            content = report_path.read_text()
            return [TextContent(type="text", text=f"**Report: {REPORT_FILE}**\n\n{content}")]

        except Exception as e:
            return [TextContent(type="text", text=f"Error reading report: {e}")]

    # In-memory notes storage
    notes_storage: dict[str, dict[str, Any]] = {}

    async def handle_create_note(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle create_note - saves notes in memory and to report."""
        import uuid
        from datetime import datetime

        title = arguments.get("title", "")
        content = arguments.get("content", "")
        category = arguments.get("category", "general")
        tags = arguments.get("tags", [])

        if not title.strip():
            return [TextContent(type="text", text="Error: Title cannot be empty")]
        if not content.strip():
            return [TextContent(type="text", text="Error: Content cannot be empty")]

        valid_categories = ["general", "findings", "methodology", "questions", "plan"]
        if category not in valid_categories:
            return [TextContent(type="text", text=f"Error: Invalid category. Must be one of: {', '.join(valid_categories)}")]

        note_id = str(uuid.uuid4())[:5]
        timestamp = datetime.now().isoformat()

        notes_storage[note_id] = {
            "title": title.strip(),
            "content": content.strip(),
            "category": category,
            "tags": tags,
            "created_at": timestamp,
        }

        # Also append to report file
        if REPORT_FILE:
            try:
                from pathlib import Path
                report_path = Path(REPORT_FILE)
                if report_path.exists():
                    existing = report_path.read_text()
                    note_entry = f"\n> **Note [{category}]** - {title}: {content[:200]}{'...' if len(content) > 200 else ''}\n"
                    report_path.write_text(existing + note_entry)
            except Exception:
                pass

        return [TextContent(
            type="text",
            text=f"Note created: {title} (ID: {note_id}, Category: {category})"
        )]

    async def handle_list_notes(arguments: dict[str, Any]) -> list[TextContent]:
        """Handle list_notes - lists saved notes."""
        category = arguments.get("category")
        search = arguments.get("search", "").lower()

        filtered = []
        for note_id, note in notes_storage.items():
            if category and note.get("category") != category:
                continue
            if search:
                if search not in note.get("title", "").lower() and search not in note.get("content", "").lower():
                    continue
            filtered.append({"id": note_id, **note})

        if not filtered:
            return [TextContent(type="text", text="No notes found.")]

        output = f"Found {len(filtered)} note(s):\n\n"
        for note in filtered:
            output += f"- [{note['id']}] **{note['title']}** ({note['category']})\n  {note['content'][:100]}{'...' if len(note['content']) > 100 else ''}\n\n"

        return [TextContent(type="text", text=output)]

    return server


def calculate_cvss(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> tuple[float, str]:
    """Calculate CVSS 3.1 base score and severity."""
    # Attack Vector scores
    av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    # Attack Complexity scores
    ac_scores = {"L": 0.77, "H": 0.44}
    # Privileges Required scores (depends on Scope)
    pr_scores_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_scores_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
    # User Interaction scores
    ui_scores = {"N": 0.85, "R": 0.62}
    # CIA Impact scores
    cia_scores = {"N": 0, "L": 0.22, "H": 0.56}

    # Get base metric scores
    av_score = av_scores.get(av, 0.85)
    ac_score = ac_scores.get(ac, 0.77)
    ui_score = ui_scores.get(ui, 0.85)

    # PR depends on scope
    if s == "C":
        pr_score = pr_scores_changed.get(pr, 0.85)
    else:
        pr_score = pr_scores_unchanged.get(pr, 0.85)

    c_score = cia_scores.get(c, 0)
    i_score = cia_scores.get(i, 0)
    a_score = cia_scores.get(a, 0)

    # Calculate ISS (Impact Sub-Score)
    iss = 1 - ((1 - c_score) * (1 - i_score) * (1 - a_score))

    # Calculate Impact
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # Calculate Exploitability
    exploitability = 8.22 * av_score * ac_score * pr_score * ui_score

    # Calculate Base Score
    if impact <= 0:
        base_score = 0
    elif s == "U":
        base_score = min(impact + exploitability, 10)
    else:
        base_score = min(1.08 * (impact + exploitability), 10)

    # Round up to 1 decimal
    import math
    base_score = math.ceil(base_score * 10) / 10

    # Determine severity
    if base_score == 0:
        severity = "none"
    elif base_score < 4.0:
        severity = "low"
    elif base_score < 7.0:
        severity = "medium"
    elif base_score < 9.0:
        severity = "high"
    else:
        severity = "critical"

    return base_score, severity


async def run_server():
    """Run the MCP server."""
    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    """Entry point for MCP server."""
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
