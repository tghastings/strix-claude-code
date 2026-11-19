---
name: strix-pentest
description: Run AI-powered penetration testing and security scans using Strix Claude Code. Use when asked to pen test, security scan, vulnerability assess, or run security audits against web applications, APIs, domains, IPs, or source code repositories.
---

# Strix Penetration Testing

Run security assessments using [Strix Claude Code](https://github.com/tghastings/strix-claude-code) — an AI-powered pen testing tool that uses Claude CLI inside a Kali Linux Docker sandbox.

## Prerequisites

- **Docker** running
- **Claude CLI** authenticated (`npm install -g @anthropic-ai/claude-cli && claude login`)
- **Python 3.11+**
- **screen** (`sudo apt install screen`)
- **Strix** installed: `pip install -e .` (from this repo)

## Installation

```bash
git clone https://github.com/tghastings/strix-claude-code.git
cd strix-claude-code
pip install -e .
```

## Usage

### TUI Dashboard (recommended)
```bash
strix-claude-tui
```
Keys: `n` new scan, `a <num>` attach, `v <num>` view, `s <num>` stop, `d <num>` delete, `r` refresh, `q` quit. Detach from scan: `Ctrl+A` then `D`.

### CLI Direct
```bash
# Deep scan (default)
strix-claude-cli -t https://target.com

# Quick scan (CI/CD)
strix-claude-cli -t https://target.com -m quick

# Standard scan with focus area
strix-claude-cli -t https://target.com -m standard --instruction "Focus on authentication bypass"

# Multiple targets / whitebox
strix-claude-cli -t https://app.com -t ./source-code

# GitHub repo scan
strix-claude-cli -t https://github.com/user/repo -m deep

# Custom output path
strix-claude-cli -t https://target.com -o ~/reports/scan.md
```

### Scan Modes
- **quick** — Fast CI/CD check, critical vulns only (~5-10 min)
- **standard** — Balanced automated + targeted manual testing (~15-30 min)
- **deep** — Exhaustive: full recon, comprehensive testing, vuln chaining (~30-60+ min)

## What Happens During a Scan

1. Docker sandbox starts (Kali Linux + security tools)
2. MCP server exposes pen testing tools to Claude
3. Claude autonomously runs recon, scanning, exploitation, and reporting
4. Vulnerability report saved (default: `~/strix_report_<timestamp>.md`)

## Available Tools in Sandbox

Claude gets access to: nmap, nuclei, sqlmap, ffuf, dirsearch, subfinder, httpx, semgrep, bandit, trufflehog, zaproxy, wapiti, trivy, jwt_tool, Playwright browser, Caido HTTP proxy, and more.

See the MCP server implementation for the full tool inventory.

## OpenClaw Agent Integration

### Via coding-agent skill (recommended)
Spawn a Claude CLI agent to run Strix interactively:
```bash
# Use coding-agent skill with PTY
exec command="claude --model claude-mythos-5-2" pty=true
# Then at the Claude Code prompt:
# > strix-claude-cli -t https://target.com -m deep
```

### Direct execution
For automated scans without TUI interaction:
```bash
# Background exec with PTY (required for interactive Claude CLI)
exec command="ANTHROPIC_MODEL=claude-mythos-5-2 strix-claude-cli -t https://target.com -o report.md" pty=true background=true
```

**Important**: Always use `pty=true` when running Strix from OpenClaw — Claude CLI requires a TTY. Without PTY, the scan will fall back to non-interactive mode and print manual instructions instead of executing.

### Permissions Bypass for Headless Operation

The main branch includes fixes to suppress all interactive prompts (workspace trust, environment commands, file permissions):

- `--permission-mode bypassPermissions` flag
- `CLAUDE_CODE_SKIP_TRUST_DIALOG=1` environment variable
- Auto-approval of all file operations

This enables true headless/automated security scanning without manual intervention.

### Example: OpenClaw Agent Workflow

```python
# In an OpenClaw agent session:

# 1. Run the scan on Claude Mythos 5.2 (strix-claude-cli has no --model flag; ANTHROPIC_MODEL picks the model)
exec(
    command="ANTHROPIC_MODEL=claude-mythos-5-2 strix-claude-cli -t https://juice-shop.herokuapp.com -m deep -o juice-shop-report.md",
    pty=True,
    background=True
)

# 2. Monitor progress
process(action="list")

# 3. When complete, share results via GitHub gist
# (use OpenClaw's message tool with GitHub API)
```

## Tips

- Use `--keep-container` to examine findings post-scan
- Point `-t` at local source code for whitebox analysis
- Reports use CVSS scoring — check for anything ≥7.0
- Use `-v` for verbose output when troubleshooting
- **GitHub gist sharing**: Create private gists for security reports (never public)
- **Claude Max limits**: Deep scans can hit rate limits; they'll pause and resume after limit resets (~5 hours)

## Example Report Output

```markdown
# Security Assessment Report

**Target:** OWASP Juice Shop v19.1.1
**Scan Mode:** Deep

## Findings

### SQL Injection in Login Endpoint
**Severity:** CRITICAL (9.8)
**CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

#### Impact
Complete authentication bypass...

#### Proof of Concept
POST /login with {"email": "' OR 1=1--", "password": "x"}
```

## Ethical Use

This tool is for **authorized security testing only**. Always:
- Obtain written permission before testing
- Respect scope boundaries
- Follow responsible disclosure practices
- Comply with applicable laws (CFAA, GDPR, etc.)

Unauthorized access to computer systems is illegal.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT License - see [LICENSE](LICENSE)
