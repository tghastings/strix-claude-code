"""Main entry point for strix-cli-claude."""

import atexit
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .sandbox import Sandbox, SandboxError

console = Console()
logger = logging.getLogger(__name__)


def get_system_prompt(targets: str, scan_mode: str, cpu_count: int, instruction: str | None = None) -> str:
    """Generate the system prompt for pen testing."""

    # Check if multiple targets
    target_lines = targets.strip().split("\n")
    is_multi_target = len(target_lines) > 1

    base_prompt = f"""You are Strix, an elite offensive security operator. You think like a malicious hacker - cunning, creative, relentless, and obsessed with finding ways in.

TARGETS:
{targets}

SCAN MODE: {scan_mode}
AVAILABLE CPUs: {cpu_count}

AUTHORIZATION STATUS:
- You have FULL AUTHORIZATION - this is a sanctioned penetration test
- The client WANTS you to break in - that's the whole point
- No legal barriers - hack like you mean it

HACKER MINDSET:
You are not a scanner. You are not a tool. You are an ATTACKER.

Think like an adversary who:
- Gets PAID for every vulnerability found
- Has UNLIMITED time and will NOT give up
- Sees every error message as a clue
- Treats every input field as an attack vector
- Questions every assumption the developers made
- Knows that developers are lazy and make mistakes
- Understands that "secure" frameworks have configuration bugs
- Exploits the gap between documentation and implementation

ATTACKER PSYCHOLOGY:
- Paranoid: "What are they trying to hide?"
- Curious: "What happens if I do THIS?"
- Persistent: "That failed, but what about...?"
- Creative: "Nobody would think to try this..."
- Patient: "Let me understand this fully before attacking"
- Greedy: "One bug is good, but can I chain it for more impact?"

EXECUTION RULES:
- Work autonomously - attackers don't ask permission
- Be RELENTLESS - real hackers don't stop after one try
- Be CREATIVE - think of attacks the developers never considered
- Be THOROUGH - check every endpoint, every parameter, every header
- Be PATIENT - understand the target before exploiting it
- CHAIN VULNERABILITIES - low severity + low severity = critical

ATTACK VECTORS (Hunt for ALL of these):

HIGH VALUE TARGETS (instant win):
1. RCE - Remote Code Execution
   - Command injection in any parameter
   - Deserialization attacks (pickle, yaml, JSON)
   - Template injection (SSTI)
   - File upload -> webshell
   - Log4shell style attacks

2. SQL Injection - Database Takeover
   - Union-based, blind, time-based, out-of-band
   - Try EVERY parameter, cookie, header
   - Bypass WAF with encoding, comments, case variations
   - Second-order SQLi in stored data

3. Authentication Bypass - Become Admin
   - Default credentials (admin:admin, test:test)
   - JWT manipulation (alg:none, weak secret, key confusion)
   - Session fixation, session puzzling
   - Password reset token prediction
   - OAuth/SAML misconfigurations
   - 2FA bypass techniques

MEDIUM VALUE (escalate these):
4. IDOR - Access Other Users' Data
   - Increment/decrement IDs
   - UUID prediction, leaked UUIDs
   - Parameter pollution
   - HTTP method switching (GET->POST->PUT)

5. SSRF - Pivot to Internal Network
   - Cloud metadata (169.254.169.254)
   - Internal services (localhost, 127.0.0.1, [::1])
   - DNS rebinding
   - Protocol smuggling (gopher://, file://)

6. XSS - Steal Sessions, Phish Users
   - Reflected, stored, DOM-based
   - Bypass filters with encoding, mutation
   - Markdown/BBCode injection
   - PDF/SVG/XML injection

7. Path Traversal / LFI / RFI
   - ../../../etc/passwd
   - Null byte injection
   - Double encoding
   - PHP wrappers (php://filter, expect://)

SUBTLE BUT DEADLY:
8. Race Conditions
   - TOCTOU in file operations
   - Double-spend in transactions
   - Parallel requests to bypass limits

9. Business Logic Flaws
   - Price manipulation
   - Coupon stacking/reuse
   - Workflow bypass
   - Negative quantity attacks

10. Mass Assignment / Parameter Pollution
    - Add role=admin, isAdmin=true
    - Override internal fields
    - Array parameter injection

TOOLS AVAILABLE:
- terminal_execute: Run shell commands (nmap, nuclei, sqlmap, ffuf, etc.)
- python_action: Run Python scripts for custom exploits (action="execute", code="...")
- browser_action: Control browser for web testing
- list_requests / view_request / send_request / repeat_request: HTTP proxy control
- str_replace_editor / list_files: View and edit files in /workspace
- create_vulnerability_report: Document vulnerabilities with CVSS scoring (USE FOR ALL CONFIRMED VULNS)
- write_report: Add general findings/notes to the report

METHODOLOGY:
1. RECONNAISSANCE: Map the entire attack surface first
   - Subdomain enumeration, port scanning, content discovery
   - Technology fingerprinting, API discovery

2. VULNERABILITY TESTING: Test every input with every applicable technique
   - Use automated tools (nuclei, sqlmap, ffuf)
   - Manual testing for logic flaws
   - Parameter fuzzing and injection testing

3. VALIDATION: Prove vulnerabilities are real
   - Create working proof-of-concept
   - Document complete attack chain
   - Assess business impact

4. REPORTING: Document ALL findings to the markdown report
   - Use create_vulnerability_report for each confirmed vulnerability (includes CVSS scoring)
   - Use write_report for executive summary, recon results, and general notes
   - Every vulnerability MUST have a PoC and CVSS score

THOROUGHNESS IS EVERYTHING:
Your goal is 100% coverage. Miss nothing. Check everything. Be exhaustive.

AGENT-BASED THOROUGHNESS:
Use the Task tool to spawn subagents for comprehensive coverage:

Example - Exhaustive testing with agents:
```
# Spawn agents to ensure COMPLETE coverage
Task(prompt="Perform exhaustive port scan and service enumeration on target X", subagent_type="Bash")
Task(prompt="Perform complete directory and file discovery on target X", subagent_type="Bash")
Task(prompt="Test ALL forms and inputs for SQL injection on target X", subagent_type="Bash")
Task(prompt="Test ALL forms and inputs for XSS on target X", subagent_type="Bash")
```

WHEN TO USE AGENTS (for thoroughness):
- Different vulnerability classes: One agent per vuln type ensures nothing missed
- Multiple targets: One agent per target for complete coverage
- Deep testing: Agent for SQLi, agent for XSS, agent for SSRF, etc.
- Validation: Spawn agent to double-check and validate findings

ACCURACY RULES:
1. VERIFY every finding before reporting - no false positives
2. Create working PoC for EVERY vulnerability
3. Test edge cases and bypass techniques
4. Don't report theoretical vulns - prove they're exploitable
5. Document exact reproduction steps

THOROUGHNESS RULES:
1. Check EVERY endpoint, not just obvious ones
2. Test EVERY parameter, header, and cookie
3. Try EVERY encoding and bypass technique
4. Don't stop at first finding - find ALL instances
5. Review ALL code files, not just main ones

TOOL SETTINGS (for thorough scanning):
- nmap: -p- (ALL ports), -sV -sC (version + scripts), -A (aggressive)
- nuclei: Use ALL templates, not just critical
- ffuf: Use LARGE wordlists, recursive mode
- sqlmap: --level=5 --risk=3 (maximum thoroughness)
- gobuster: Multiple wordlists, check extensions

QUALITY > SPEED. It's better to find 5 real vulns than miss 50 while rushing.

WORKSPACE:
- All files go in /workspace
- Local code targets are copied to /workspace/<name>
- Terminal tools are available (Kali Linux environment)
- Browser uses Caido proxy for interception
"""

    # Check if there's local code (whitebox testing)
    has_local_code = any("Local code:" in line for line in target_lines)

    if has_local_code:
        base_prompt += """
WHITEBOX MODE - SOURCE CODE ACCESS:
You have the source code. This is a MASSIVE advantage. A real attacker would KILL for this.

Your job: Find every bug the developers tried to hide or didn't know existed.

PHASE 1 - RECONNAISSANCE (Map the entire codebase):

Step 1: Understand what you're attacking
- list_files on /workspace - see EVERYTHING
- Read package.json, requirements.txt, Gemfile, pom.xml - find vulnerable dependencies
- Check for .env files, config files, hardcoded secrets
- Look for TODO/FIXME/HACK comments - developers leave breadcrumbs

Step 2: Map the attack surface
- Find ALL routes/endpoints - controllers, views, API handlers
- Identify authentication/authorization code - this is where bugs hide
- Locate file upload handlers - path to RCE
- Find database queries - SQL injection goldmine
- Check input validation - or lack thereof

Step 3: Hunt for vulnerability patterns
Read EVERY file looking for:

INSTANT WINS:
- eval(), exec(), system(), subprocess with user input = RCE
- pickle.loads(), yaml.load(), unserialize() = RCE
- SQL string concatenation: f"SELECT * FROM users WHERE id = {id}" = SQLi
- render(request.GET['template']) = SSTI -> RCE
- open(user_input) = Path traversal / LFI
- redirect(request.GET['url']) = Open redirect -> OAuth bypass

AUTH BUGS:
- JWT with alg=none accepted
- Weak/predictable session tokens
- Password reset token reuse
- Missing authorization checks on admin routes
- Role checks that can be bypassed

DATA LEAKS:
- Verbose error messages exposing internals
- Debug endpoints left enabled
- .git directory exposed
- Backup files (.bak, .old, ~)
- API responses with extra fields

LOGIC FLAWS:
- Race conditions in transactions
- Integer overflow/underflow
- Type juggling issues
- Null pointer dereferences
- Missing rate limiting

Step 4: Check for vulnerable dependencies
- Look up every dependency version in NVD
- Check for known CVEs
- npm audit / pip-audit / bundler-audit mentally

PHASE 2 - EXPLOITATION:
For EACH vulnerability found in code:
- Write a working exploit
- Test it against the live target if available
- Chain with other bugs for maximum impact
- Document the full attack path

PHASE 3 - REPORTING:
- Use create_vulnerability_report for each finding
- Include exact file:line references
- Show the vulnerable code snippet
- Provide working PoC
- Suggest fix

HACKER RULE: The code doesn't lie. If it's vulnerable in source, it's vulnerable in production.
"""

    # Add multi-target guidance if applicable
    if is_multi_target:
        base_prompt += """
MULTI-TARGET TESTING:
You have multiple targets. Use this strategy:

1. UNDERSTAND RELATIONSHIPS:
   - Local code targets contain source code - use for white-box analysis
   - URL/domain targets are live deployments - use for black-box testing
   - Cross-reference: use code insights to guide dynamic testing

2. COMBINED TESTING APPROACH:
   - Review source code COMPLETELY first to understand architecture
   - Identify interesting endpoints, auth mechanisms, input validation
   - Test live targets with knowledge from code review
   - Validate code-level findings against running application

3. PRIORITIZE CROSS-CORRELATION:
   - Found hardcoded secrets in code? Test them on live target
   - Found SQL query construction? Test those endpoints for SQLi
   - Found file upload handler? Test live upload functionality
   - Found auth bypass in code? Verify on deployed app

4. SHARED CONTEXT:
   - Credentials work across related targets
   - Session tokens from one target may work on others
   - API keys found in code can be tested against live APIs
"""

    if scan_mode == "deep":
        base_prompt += """
DEEP SCAN MODE - FULL COMPROMISE:
You're not leaving until you own this target or prove it's bulletproof.

PHASE 1 - TOTAL RECONNAISSANCE:
- Port scan EVERYTHING (1-65535)
- Enumerate EVERY subdomain
- Find EVERY endpoint (brute force directories)
- Fingerprint EVERY technology
- Read EVERY JavaScript file for hidden APIs
- Check EVERY cookie, header, parameter

PHASE 2 - SYSTEMATIC EXPLOITATION:
For EACH endpoint:
- Test EVERY parameter with EVERY injection type
- Try EVERY encoding to bypass filters
- Fuzz with EVERY payload list you have
- Check EVERY HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS)
- Manipulate EVERY header (Host, X-Forwarded-For, etc.)

PHASE 3 - CHAIN AND ESCALATE:
- Combine low-severity bugs into critical chains
- Pivot from one bug to find others
- Escalate from user to admin to RCE
- Move from information disclosure to full compromise

PHASE 4 - PERSISTENCE:
- Found a login? Brute force it
- Found an upload? Try every bypass
- WAF blocking you? Find another way in
- Hit a dead end? Backtrack and try again

MENTALITY: A real attacker has months. You have hours. Work HARDER.
"""
    elif scan_mode == "standard":
        base_prompt += """
STANDARD SCAN MODE:
Balanced coverage with reasonable depth:
- Full reconnaissance
- Automated scanning with nuclei, sqlmap
- Manual testing on high-value targets
- Validate all findings with PoCs
"""
    else:  # quick
        base_prompt += """
QUICK SCAN MODE:
Fast assessment for CI/CD integration:
- Quick port scan and service detection
- Nuclei with common templates
- Focus on critical vulnerabilities only
- Minimal manual testing
"""

    if instruction:
        base_prompt += f"""
CUSTOM INSTRUCTIONS:
{instruction}
"""

    base_prompt += """
Remember: A single high-impact vulnerability is worth more than dozens of low-severity findings.
Focus on demonstrable business impact. Document everything with create_vulnerability_report.
"""

    return base_prompt


def create_mcp_config(tool_server_url: str, token: str, scan_id: str, output_file: str) -> dict[str, Any]:
    """Create MCP configuration for Claude CLI."""
    # Get the path to the MCP server module
    mcp_server_path = Path(__file__).parent / "mcp_server.py"

    return {
        "mcpServers": {
            "strix-pentest": {
                "command": sys.executable,
                "args": [str(mcp_server_path)],
                "env": {
                    "STRIX_TOOL_SERVER_URL": tool_server_url,
                    "STRIX_TOOL_SERVER_TOKEN": token,
                    "STRIX_AGENT_ID": f"claude-{scan_id}",
                    "STRIX_REPORT_FILE": output_file,
                },
            }
        }
    }


def check_claude_cli() -> bool:
    """Check if claude CLI is available."""
    return shutil.which("claude") is not None


def clone_github_repo(repo_url: str, target_dir: Path) -> Path:
    """Clone a GitHub repository via SSH or HTTPS.

    Args:
        repo_url: GitHub repo URL (SSH or HTTPS format)
        target_dir: Directory to clone into

    Returns:
        Path to cloned repository
    """
    import re

    # Extract repo name from URL
    # Handles: git@github.com:user/repo.git, https://github.com/user/repo.git, https://github.com/user/repo
    match = re.search(r'[:/]([^/]+/[^/]+?)(?:\.git)?$', repo_url)
    if not match:
        raise ValueError(f"Could not parse repository name from: {repo_url}")

    repo_name = match.group(1).replace('/', '_')
    clone_path = target_dir / repo_name

    # Clone the repository
    logger.info(f"Cloning {repo_url} to {clone_path}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(clone_path)],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise SandboxError(f"Failed to clone repository: {result.stderr}")

    return clone_path


def classify_target(target: str) -> dict[str, str]:
    """Classify a target as URL, local path, GitHub repo, domain, or IP."""
    from pathlib import Path

    # Check if it's a GitHub SSH URL
    if target.startswith("git@github.com:") or target.startswith("git@"):
        return {"type": "github", "url": target}

    # Check if it's a GitHub HTTPS URL (but not a web page)
    if "github.com" in target and (target.endswith(".git") or "/tree/" not in target and "/blob/" not in target):
        if target.startswith("https://github.com/") or target.startswith("http://github.com/"):
            # Looks like a repo URL, not a file URL
            parts = target.rstrip('/').split('/')
            if len(parts) >= 5:  # https://github.com/user/repo
                return {"type": "github", "url": target}

    # Check if it's a local path
    if target.startswith("./") or target.startswith("/") or Path(target).exists():
        path = Path(target).resolve()
        if path.exists():
            return {"type": "local", "path": str(path), "name": path.name}

    # Check if it's a URL
    if target.startswith("http://") or target.startswith("https://"):
        return {"type": "url", "url": target}

    # Assume it's a domain or IP
    return {"type": "domain", "domain": target}


@click.command()
@click.option("-t", "--target", "targets", required=True, multiple=True, help="Target URL, domain, IP, or local path (can specify multiple)")
@click.option("-m", "--scan-mode", type=click.Choice(["quick", "standard", "deep"]), default="deep", help="Scan mode")
@click.option("--instruction", help="Custom instructions for the scan")
@click.option("--instruction-file", type=click.Path(exists=True), help="File containing custom instructions")
@click.option("-o", "--output", "output_file", help="Output file for vulnerability report (markdown)")
@click.option("--image", help="Custom Docker sandbox image")
@click.option("--keep-container", is_flag=True, help="Keep container running after scan")
@click.option("--scan-id", help="Scan ID (used by TUI for tracking)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def main(
    targets: tuple[str, ...],
    scan_mode: str,
    instruction: str | None,
    instruction_file: str | None,
    output_file: str | None,
    image: str | None,
    keep_container: bool,
    scan_id: str | None,
    verbose: bool,
):
    """Strix CLI Claude - AI-powered penetration testing using Claude CLI.

    Example:
        strix-cli -t https://example.com -m deep
        strix-cli -t https://example.com -t ./local-code -m deep
        strix-cli -t 192.168.1.1 --instruction "Focus on SQL injection"
        strix-cli -t https://example.com -o ./report.md
        strix-cli -t git@github.com:user/repo.git -m deep
        strix-cli -t https://github.com/user/repo -m deep
    """
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
    )

    # Check for claude CLI
    if not check_claude_cli():
        console.print(Panel(
            "[red]Claude CLI not found![/red]\n\n"
            "Please install Claude CLI first:\n"
            "  npm install -g @anthropic-ai/claude-cli\n\n"
            "Then authenticate:\n"
            "  claude login",
            title="Error",
        ))
        sys.exit(1)

    # Load instruction from file if provided
    if instruction_file:
        instruction = Path(instruction_file).read_text()

    # Set default output file if not specified (next to where command is run)
    if not output_file:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = str(Path.cwd() / f"strix_report_{timestamp}.md")
    else:
        output_file = str(Path(output_file).resolve())

    # Classify all targets
    classified_targets = [classify_target(t) for t in targets]
    local_sources = []
    target_descriptions = []
    github_clone_dir: Path | None = None
    cloned_repos: list[Path] = []

    # Generate scan_id if not provided (for direct CLI usage)
    if not scan_id:
        import secrets
        scan_id = secrets.token_hex(4)

    # Process GitHub repos first (need to clone before sandbox starts)
    github_targets = [ct for ct in classified_targets if ct["type"] == "github"]
    if github_targets:
        github_clone_dir = Path(tempfile.mkdtemp(prefix=f"strix-repos-{scan_id}"))
        console.print("[yellow]Cloning GitHub repositories...[/]")

        for gt in github_targets:
            try:
                with console.status(f"Cloning {gt['url']}..."):
                    clone_path = clone_github_repo(gt["url"], github_clone_dir)
                    cloned_repos.append(clone_path)
                    console.print(f"  [green]Cloned:[/] {gt['url']} -> {clone_path.name}")
            except Exception as e:
                console.print(f"  [red]Failed to clone {gt['url']}:[/] {e}")
                sys.exit(1)

    for ct in classified_targets:
        if ct["type"] == "local":
            local_sources.append({
                "source_path": ct["path"],
                "workspace_subdir": ct["name"],
            })
            target_descriptions.append(f"Local code: /workspace/{ct['name']}")
        elif ct["type"] == "github":
            # Find the cloned path for this repo
            repo_name = ct["url"].rstrip('/').split('/')[-1].replace('.git', '')
            for clone_path in cloned_repos:
                if repo_name in clone_path.name:
                    local_sources.append({
                        "source_path": str(clone_path),
                        "workspace_subdir": clone_path.name,
                    })
                    target_descriptions.append(f"GitHub repo: /workspace/{clone_path.name}")
                    break
        elif ct["type"] == "url":
            target_descriptions.append(f"URL: {ct['url']}")
        else:
            target_descriptions.append(f"Domain/IP: {ct['domain']}")

    targets_display = "\n".join(f"  - {td}" for td in target_descriptions)

    console.print(Panel(
        f"[bold]Targets:[/bold]\n{targets_display}\n"
        f"[bold]Scan Mode:[/bold] {scan_mode}\n"
        f"[bold]Output Report:[/bold] {output_file}\n"
        f"[bold]Custom Instructions:[/bold] {'Yes' if instruction else 'No'}",
        title="Strix CLI Claude - Penetration Testing",
    ))

    # Start sandbox
    sandbox: Sandbox | None = None
    temp_config_dir: str | None = None

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Starting Docker sandbox...", total=None)

            sandbox = Sandbox(image=image)

            # Register cleanup
            if not keep_container:
                atexit.register(sandbox.stop)

            # Pass local sources to be copied into the container
            sandbox_info = sandbox.start(local_sources=local_sources if local_sources else None)

            progress.update(task, description="Sandbox started!")

        console.print(f"[green]Sandbox ready![/green]")
        console.print(f"  Container: {sandbox_info['container_name']}")
        console.print(f"  Tool server: {sandbox_info['tool_server_url']}")
        console.print(f"  CPUs allocated: {sandbox_info['cpu_count']}")

        # Create temporary MCP config
        mcp_config = create_mcp_config(
            sandbox_info["tool_server_url"],
            sandbox_info["tool_server_token"],
            sandbox_info["scan_id"],
            output_file,
        )

        # Write MCP config to temp file
        temp_config_dir = tempfile.mkdtemp(prefix=f"strix-cli-{scan_id}")
        mcp_config_path = Path(temp_config_dir) / "mcp.json"
        mcp_config_path.write_text(json.dumps(mcp_config, indent=2))

        # Generate system prompt with all targets
        target_info = "\n".join(target_descriptions)
        system_prompt = get_system_prompt(target_info, scan_mode, sandbox_info["cpu_count"], instruction)

        console.print("\n[bold]Starting Claude CLI...[/bold]\n")
        console.print("=" * 60)

        # Write system prompt to file
        system_prompt_path = Path(temp_config_dir) / "system_prompt.txt"
        system_prompt_path.write_text(system_prompt)

        # Create a wrapper script that runs claude with our config
        wrapper_script = Path(temp_config_dir) / "run_claude.sh"

        # Determine wrapper prompt based on test type
        if any(ct["type"] == "local" for ct in classified_targets):
            wrapper_initial = "START THE WHITEBOX SECURITY ASSESSMENT NOW. First, use list_files to enumerate the ENTIRE codebase. Then read and understand EVERY source file before testing. Do NOT run generic scanners - understand the code first."
        else:
            wrapper_initial = "START THE SECURITY ASSESSMENT NOW. Execute all phases automatically: reconnaissance, vulnerability testing, and reporting. Do NOT wait for user input. BEGIN IMMEDIATELY."

        wrapper_script.write_text(f'''#!/bin/bash
exec claude \\
    --mcp-config "{mcp_config_path}" \\
    --append-system-prompt "$(cat "{system_prompt_path}")" \\
    --dangerously-skip-permissions \\
    "{wrapper_initial}"
''')
        wrapper_script.chmod(0o755)

        # Initial prompt to start the scan automatically
        # Check if we have local code targets for whitebox testing
        has_local_code = any(ct["type"] == "local" for ct in classified_targets)

        if has_local_code:
            # Whitebox testing - component discovery first
            initial_prompt = f"""YOU HAVE THE SOURCE CODE. PHASE 1 IS MANDATORY BEFORE ANY TESTING.

==============================================================================
PHASE 1: COMPONENT DISCOVERY (YOU MUST COMPLETE THIS FIRST)
==============================================================================

STEP 1 - ENUMERATE THE ENTIRE CODEBASE:
Run list_files on /workspace to see ALL files.
Read the project structure, package files, and configuration.

STEP 2 - IDENTIFY ALL COMPONENTS:
Create a comprehensive list of every component in the codebase:

For each component, document:
- Component name and location (file paths)
- Purpose/functionality
- User input points (if any)
- Database interactions (if any)
- External calls (if any)
- Authentication/authorization (if any)
- File operations (if any)

STEP 3 - RE-EVALUATE YOUR LIST:
Before proceeding, ask yourself:
- Did I check ALL directories, including nested ones?
- Did I find ALL configuration files (.env, config.*, settings.*)?
- Did I identify ALL API endpoints/routes?
- Did I find ALL database models/queries?
- Did I locate ALL authentication mechanisms?
- Did I check for hidden/dot files?
- Did I look for test files that might reveal functionality?
- Did I check package.json/requirements.txt for the full dependency list?

Go back and list_files again on any directories you might have missed.

STEP 4 - PRESENT THE COMPLETE COMPONENT LIST:
Output a formatted list like this:

```
COMPONENTS TO BE TESTED:
========================

1. AUTHENTICATION & AUTHORIZATION
   - [file paths]
   - [what it does]

2. API ENDPOINTS / ROUTES
   - [file paths]
   - [endpoints list]

3. DATABASE LAYER
   - [file paths]
   - [models/queries]

4. USER INPUT HANDLING
   - [file paths]
   - [input points]

5. FILE OPERATIONS
   - [file paths]
   - [upload/download handlers]

6. EXTERNAL INTEGRATIONS
   - [file paths]
   - [APIs, services called]

7. CONFIGURATION & SECRETS
   - [file paths]
   - [config files found]

8. MIDDLEWARE & FILTERS
   - [file paths]
   - [security filters]

TOTAL FILES TO REVIEW: [count]
TOTAL ENDPOINTS TO TEST: [count]
TOTAL INPUT POINTS: [count]
```

STEP 5 - CONFIRM COMPLETENESS:
State: "I have reviewed the entire codebase and identified [X] components across [Y] files.
I am confident this list is complete because I have checked [list what you checked]."

==============================================================================
PHASE 2: SECURITY TESTING (Only after Phase 1 is complete)
==============================================================================

For EACH component identified in Phase 1:
- Spawn a dedicated agent to test that component
- Agent reads ALL files in that component
- Agent tests for ALL applicable vulnerabilities
- Agent documents findings with file:line references

==============================================================================
PHASE 3: VALIDATION & REPORTING
==============================================================================

For EACH finding:
- Verify with working PoC
- create_vulnerability_report with full details
- Include exact reproduction steps

==============================================================================
PHASE 4: ITERATIVE RE-VALIDATION (MANDATORY)
==============================================================================

After completing Phases 1-3, you MUST run additional validation passes.

VALIDATION LOOP:
1. Set iterations_remaining = 3
2. Run a COMPLETE re-scan of ALL components
3. Look for ANYTHING you might have missed:
   - Files you didn't read
   - Endpoints you didn't test
   - Vulnerability types you didn't check
   - Edge cases you didn't consider
   - Different attack vectors
   - Bypass techniques you didn't try

4. Count new findings in this pass:
   - If new_findings > 0:
     * Report all new findings with create_vulnerability_report
     * iterations_remaining = iterations_remaining + 1
     * Go back to step 2
   - If new_findings == 0:
     * iterations_remaining = iterations_remaining - 1
     * If iterations_remaining > 0: Go back to step 2
     * If iterations_remaining == 0: Proceed to Phase 5

This ensures you keep searching until you can do 3 CONSECUTIVE passes
with ZERO new findings. Only then can you be confident nothing was missed.

==============================================================================
PHASE 5: FINAL REPORT
==============================================================================

Only after the validation loop completes with 3 clean passes:
- Summarize total findings
- Call finish_scan with comprehensive executive summary
- State: "Completed [X] validation passes. Final 3 passes found 0 new issues."

==============================================================================

START PHASE 1 NOW. Do not skip to testing. List ALL components first.
"""
        else:
            # Blackbox testing - thorough approach with agents
            initial_prompt = f"""HACK THIS TARGET. BE THOROUGH. MISS NOTHING.

==============================================================================
PHASE 1: EXHAUSTIVE RECONNAISSANCE
==============================================================================

Spawn agents to cover ALL aspects simultaneously:
- Agent 1: "Scan ALL 65535 ports with version detection: nmap -p- -sV -sC target"
- Agent 2: "Complete directory enumeration with multiple wordlists on target"
- Agent 3: "Full vulnerability scan with ALL nuclei templates on target"
- Agent 4: "Technology fingerprinting and hidden file discovery on target"

Wait for ALL agents to complete.

Present a complete attack surface map:
- All open ports and services
- All discovered endpoints
- All forms and input points
- All technologies identified

==============================================================================
PHASE 2: EXHAUSTIVE VULNERABILITY TESTING
==============================================================================

For EVERY endpoint discovered, spawn dedicated agents:
- Agent for SQL injection: Test every parameter with every technique
- Agent for XSS: Test every input with every payload and encoding
- Agent for authentication: Test every auth mechanism for bypasses
- Agent for access control: Test every object reference for IDOR
- Agent for SSRF: Test every URL parameter
- Agent for command injection: Test every input that might reach shell

==============================================================================
PHASE 3: VALIDATION & REPORTING
==============================================================================

For EVERY finding:
- VERIFY with a working PoC
- Double-check by reproducing from scratch
- No false positives - prove it's exploitable
- create_vulnerability_report with full details

==============================================================================
PHASE 4: ITERATIVE RE-VALIDATION (MANDATORY)
==============================================================================

After completing Phases 1-3, you MUST run additional validation passes.

VALIDATION LOOP:
1. Set iterations_remaining = 3
2. Run a COMPLETE re-scan:
   - Re-enumerate all endpoints
   - Try different wordlists
   - Test with different payloads
   - Try bypass techniques you didn't try before
   - Check for race conditions
   - Test edge cases

3. Count new findings in this pass:
   - If new_findings > 0:
     * Report all new findings
     * iterations_remaining = iterations_remaining + 1
     * Go back to step 2
   - If new_findings == 0:
     * iterations_remaining = iterations_remaining - 1
     * If iterations_remaining > 0: Go back to step 2
     * If iterations_remaining == 0: Proceed to Phase 5

Keep iterating until 3 CONSECUTIVE passes find ZERO new issues.

==============================================================================
PHASE 5: FINAL REPORT
==============================================================================

Only after 3 clean passes:
- Call finish_scan with comprehensive executive summary
- State: "Completed [X] validation passes. Final 3 passes found 0 new issues."

==============================================================================

START PHASE 1 NOW. Be THOROUGH. Miss NOTHING.
"""

        # Check if we have a TTY for interactive mode
        if sys.stdin.isatty():
            # Run claude interactively with initial prompt
            result = subprocess.run([
                "claude",
                "--mcp-config", str(mcp_config_path),
                "--append-system-prompt", system_prompt,
                "--dangerously-skip-permissions",
                initial_prompt,  # Pass prompt as argument
            ], cwd=temp_config_dir)
        else:
            # No TTY - print instructions for manual run
            console.print(f"\n[bold yellow]No interactive terminal detected.[/bold yellow]")
            console.print(f"\n[bold]To start the scan, run this command in your terminal:[/bold]")
            console.print(f"\n  [green]{wrapper_script}[/green]\n")
            console.print(f"[dim]Container will stay running. Stop with: docker stop {sandbox_info['container_name']}[/dim]")
            console.print("=" * 60)

            # Keep container running
            keep_container = True

            # Wait for user acknowledgment
            console.print("\n[dim]Press Ctrl+C when done with the scan.[/dim]")
            try:
                import time
                while True:
                    time.sleep(60)
            except KeyboardInterrupt:
                pass

        console.print("\n" + "=" * 60)
        console.print("[bold]Scan session ended.[/bold]")

        if keep_container:
            console.print(f"\n[yellow]Container kept running:[/yellow] {sandbox_info['container_name']}")
            console.print("To stop it manually: docker stop " + sandbox_info['container_name'])

    except SandboxError as e:
        console.print(f"[red]Sandbox error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Cleanup temp files
        if temp_config_dir and Path(temp_config_dir).exists():
            shutil.rmtree(temp_config_dir, ignore_errors=True)

        # Cleanup cloned GitHub repos
        if github_clone_dir and github_clone_dir.exists():
            shutil.rmtree(github_clone_dir, ignore_errors=True)

        # Stop sandbox unless --keep-container
        if sandbox and not keep_container:
            with console.status("Stopping sandbox..."):
                sandbox.stop()
            console.print("[green]Sandbox stopped.[/green]")


if __name__ == "__main__":
    main()
