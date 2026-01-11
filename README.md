# Strix CLI Claude

AI-powered penetration testing using the Claude CLI tool. This is a companion to [Strix](https://github.com/usestrix/strix) that lets you run security assessments using the Claude CLI instead of direct API calls.

## Overview

Strix CLI Claude provides:
- A Docker sandbox with Kali Linux and comprehensive security tools
- MCP (Model Context Protocol) server exposing pen testing tools to Claude
- System prompts optimized for security assessment
- Interactive sessions with Claude for guided penetration testing

## Prerequisites

1. **Docker**: Install and run Docker Desktop
2. **Claude CLI**: Install and authenticate
   ```bash
   npm install -g @anthropic-ai/claude-cli
   claude login
   ```
3. **Python 3.11+**: Required for the wrapper

## Installation

```bash
cd strix-cli-claude
pip install -e .
```

## Usage

### Basic Usage

```bash
# Full penetration test on a target
strix-cli -t https://example.com

# Quick scan for CI/CD
strix-cli -t https://example.com -m quick

# Standard scan with custom instructions
strix-cli -t https://example.com -m standard --instruction "Focus on authentication bypass"
```

### Options

```
-t, --target          Target URL, domain, or IP (required)
-m, --scan-mode       Scan mode: quick, standard, deep (default: deep)
--instruction         Custom instructions for the scan
--instruction-file    File containing custom instructions
--image               Custom Docker sandbox image
--keep-container      Keep container running after scan
-v, --verbose         Verbose output
```

### Scan Modes

- **quick**: Fast assessment for CI/CD. Basic scans, critical vulns only.
- **standard**: Balanced coverage. Automated + targeted manual testing.
- **deep**: Exhaustive assessment. Full reconnaissance, comprehensive testing, vulnerability chaining.

## How It Works

1. **Sandbox Setup**: Starts a Docker container with Kali Linux and security tools
2. **MCP Server**: Exposes penetration testing tools via Model Context Protocol
3. **Claude CLI**: Runs Claude with the MCP tools and pen testing system prompt
4. **Interactive Session**: You interact with Claude, which uses the tools autonomously

## Available Tools

Claude has access to these tools in the sandbox:

### Terminal Execution
- `terminal_execute`: Run shell commands (nmap, nuclei, sqlmap, ffuf, etc.)

### Python Execution
- `python_execute`: Run custom Python scripts for exploits and automation

### Browser Control
- `browser_action`: Control Playwright browser for web testing

### HTTP Proxy (Caido)
- `list_requests`: View captured HTTP traffic
- `view_request`: Inspect request/response details
- `send_request`: Send custom HTTP requests
- `repeat_request`: Modify and replay requests

### File Operations
- `file_edit`: Read/write files in /workspace

### Reporting
- `create_vulnerability_report`: Document confirmed vulnerabilities

## Sandbox Environment

The Docker sandbox includes:

**Reconnaissance & Scanning:**
- nmap, subfinder, httpx, gospider, katana

**Vulnerability Scanning:**
- nuclei, sqlmap, zaproxy, wapiti, trivy

**Fuzzing & Discovery:**
- ffuf, dirsearch, arjun

**Code Analysis:**
- semgrep, bandit, trufflehog

**Specialized:**
- jwt_tool, wafw00f, interactsh-client

## Example Session

```bash
$ strix-cli -t https://vulnerable-app.example.com -m deep

Strix CLI Claude - Penetration Testing
Target: https://vulnerable-app.example.com
Scan Mode: deep
Custom Instructions: No

Starting Docker sandbox...
Sandbox ready!
  Container: strix-cli-scan-abc123
  Tool server: http://127.0.0.1:54321

Starting Claude CLI...
============================================================

# Claude takes over here, running tools autonomously:
# - Runs nmap for port scanning
# - Uses nuclei for vulnerability scanning
# - Tests for SQL injection with sqlmap
# - Fuzzes parameters with ffuf
# - Creates vulnerability reports for findings

============================================================
Scan session ended.
Sandbox stopped.
```

## Tips

1. **Be specific**: Provide clear targets and instructions
2. **Let it work**: Claude will run many steps autonomously
3. **Check reports**: Vulnerability reports are created in /workspace
4. **Keep container**: Use `--keep-container` to examine findings after the session

## Troubleshooting

### Docker not found
Make sure Docker Desktop is installed and running.

### Claude CLI not found
Install with: `npm install -g @anthropic-ai/claude-cli`

### Container fails to start
Check if the strix sandbox image is available:
```bash
docker pull ghcr.io/usestrix/strix-sandbox:0.1.10
```

### Tools not responding
The tool server inside the container may need more time to start. Try running with `-v` for verbose output.

## Credits

Based on [Strix](https://github.com/usestrix/strix) by OmniSecure Labs.
