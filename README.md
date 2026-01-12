# Strix CLI Claude

AI-powered penetration testing using the Claude CLI tool. This is a companion to [Strix](https://github.com/usestrix/strix) that lets you run security assessments using the Claude CLI instead of direct API calls.

## Overview

Strix CLI Claude provides:
- **TUI Dashboard**: Terminal UI for managing multiple scans
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
4. **screen**: Required for TUI (usually pre-installed on Linux/macOS)
   ```bash
   # Ubuntu/Debian
   sudo apt install screen
   # macOS
   brew install screen
   ```

## Installation

```bash
cd strix-claude-code
pip install -e .
```

## Quick Start: TUI Dashboard

The easiest way to use Strix CLI Claude is through the TUI (Terminal User Interface):

```bash
strix-tui
```

This launches an interactive dashboard where you can:
- Start new scans with a guided wizard
- View all running and completed scans
- Attach to running scans to watch Claude work
- View scan logs and details
- Stop or delete scans

### TUI Commands

| Key | Action |
|-----|--------|
| `n` | New scan - launch the scan wizard |
| `a <num>` | Attach to a running scan (e.g., `a 1`) |
| `v <num>` | View scan details and logs |
| `s <num>` | Stop a running scan |
| `d <num>` | Delete a scan |
| `r` | Refresh the scan list |
| `q` | Quit the TUI |

When attached to a scan, press `Ctrl+A` then `D` to detach and return to the TUI.

## CLI Usage

For direct command-line usage without the TUI:

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
-t, --target          Target URL, domain, IP, or local path (required, can specify multiple)
-m, --scan-mode       Scan mode: quick, standard, deep (default: deep)
-o, --output          Output file for vulnerability report (default: ~/strix_report_<timestamp>.md)
--instruction         Custom instructions for the scan
--instruction-file    File containing custom instructions
--image               Custom Docker sandbox image
--keep-container      Keep container running after scan
-v, --verbose         Verbose output
```

### Multiple Targets

You can scan multiple targets (URLs, domains, local code) in a single session:

```bash
# Scan a web app and its source code (whitebox + blackbox)
strix-cli -t https://myapp.com -t ./myapp-source

# Scan multiple endpoints
strix-cli -t https://api.example.com -t https://admin.example.com

# Clone and scan a GitHub repo
strix-cli -t https://github.com/user/repo -m deep
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

1. **Use the TUI**: The TUI dashboard is the easiest way to manage scans
2. **Be specific**: Provide clear targets and instructions
3. **Let it work**: Claude will run many steps autonomously
4. **Check reports**: Vulnerability reports are saved to your home directory (or custom path with `-o`)
5. **Keep container**: Use `--keep-container` to examine findings after the session
6. **Whitebox testing**: Point to local source code for deeper analysis (`-t ./your-code`)

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
