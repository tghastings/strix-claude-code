#!/usr/bin/env python3
"""Self-contained Strix tool-server shim (compatible with strix-sandbox 1.x).

The original Strix sandbox (0.1.x) baked its own ``strix.runtime.tool_server``
and ``strix.tools.*`` into the image, and ``sandbox.py`` launched it with
``poetry run``. The 1.x sandbox image dropped all of that: no ``strix`` package,
no ``poetry``, no ``fastapi``/``uvicorn``. This shim reimplements the exact HTTP
contract that ``mcp_server.py`` speaks to (``POST /execute`` + ``GET /health``)
using ONLY the Python standard library plus binaries that ship in the 1.x image
(bash, the Kali tools, and ``agent-browser``). It deliberately does not import
``strix`` — that package is absent from the sandbox.

Request:  POST /execute  {"tool_name": str, "kwargs": {...}, "agent_id": str}
Response:                 {"result": <any>|null, "error": <str>|null}

Forwarded tools implemented (everything ``mcp_server.py`` does NOT handle host-side):
  terminal_execute, python_action, str_replace_editor, list_files,
  send_request, browser_action, list_requests, view_request, repeat_request

Run:  python3 sandbox_tool_server.py --token <tok> --host 0.0.0.0 --port <p>
"""

from __future__ import annotations

import argparse
import json
import os
import pty
import re
import select
import signal
import subprocess
import sys
import termios
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

WORKSPACE = "/workspace"
DEFAULT_TERMINAL_TIMEOUT = 300.0

# Strip ANSI CSI/OSC escape sequences and bare carriage returns from pty output.
_ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[=>]")


def _strip_ansi(data: bytes) -> str:
    data = _ANSI_RE.sub(b"", data)
    text = data.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


# --------------------------------------------------------------------------- #
# Persistent terminal (pty-backed bash) — replaces the 0.1.x libtmux sessions.
# --------------------------------------------------------------------------- #
class PtyShell:
    """A persistent interactive bash running on a pty.

    A unique per-session marker is emitted by bash's PS1 (installed via
    PROMPT_COMMAND) after every command, carrying that command's exit code.
    Because the marker is bash *output* — not a queued input line — commands
    that read stdin (nmap, sqlmap prompts, REPLs) cannot swallow it. Input echo
    is disabled so captured output is exactly the command's own output. Timeouts
    interrupt only the foreground command tree (via /proc), never the shell.
    """

    POLL = 0.2
    TAG = "STRIXPS1_"
    END = "_STRIXEND"

    def __init__(self, terminal_id: str, work_dir: str = WORKSPACE) -> None:
        self.terminal_id = terminal_id
        self.work_dir = work_dir if Path(work_dir).is_dir() else "/"
        self.lock = threading.Lock()
        self.busy = False  # a command exceeded its timeout and is still live
        self.sid = uuid.uuid4().hex
        self._mre = re.compile(
            self.TAG.encode() + self.sid.encode() + rb":(-?\d+)" + self.END.encode()
        )
        self._spawn()

    def _spawn(self) -> None:
        pid, fd = pty.fork()
        if pid == 0:  # child
            env = dict(os.environ)
            env["PS1"] = ""
            env["PS2"] = ""
            env["PROMPT_COMMAND"] = ""
            env["TERM"] = "dumb"
            env["PAGER"] = "cat"
            env["GIT_PAGER"] = "cat"
            try:
                os.chdir(self.work_dir)
            except OSError:
                pass
            os.execvpe("/bin/bash", ["/bin/bash", "--norc", "--noprofile", "-i"], env)
            os._exit(127)  # unreachable
        self.pid = pid
        self.fd = fd
        # Disable input echo so captured output is only the command's own output.
        try:
            attrs = termios.tcgetattr(fd)
            attrs[3] &= ~termios.ECHO  # lflags
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except (termios.error, OSError):
            pass
        # Install the PS1 marker; printed after every command with its exit code.
        setup = (
            "export PROMPT_COMMAND='export PS1=\""
            f"{self.TAG}{self.sid}:$?{self.END}\"'\n"
        )
        os.write(fd, setup.encode())
        self._read_until_marker(5.0)  # sync to the first prompt

    def _read_until_marker(
        self, timeout: float
    ) -> tuple[re.Match[bytes] | None, bytes]:
        """Read pty output until the PS1 marker appears or `timeout` elapses."""
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select(
                [self.fd], [], [], min(self.POLL, max(0.0, deadline - time.time()))
            )
            if self.fd in r:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                m = self._mre.search(buf)
                if m:
                    return m, buf
        return None, buf

    def _drain(self, quiet_for: float) -> bytes:
        buf = b""
        last = time.time()
        while time.time() - last < quiet_for:
            r, _, _ = select.select([self.fd], [], [], quiet_for)
            if self.fd in r:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                last = time.time()
        return buf

    def _clean(self, raw: bytes) -> str:
        text = _strip_ansi(raw)
        # Echo is off, so this is command output only; just drop marker framing.
        lines = [ln for ln in text.split("\n") if self.TAG not in ln]
        return "\n".join(lines).strip("\n")

    def _poll_pending(self, wait: float) -> None:
        """If a prior command timed out, see whether it has since finished."""
        if not self.busy:
            return
        m, _ = self._read_until_marker(wait)
        if m is not None:
            self.busy = False

    def execute(
        self,
        command: str,
        timeout: float,
        is_input: bool = False,
        no_enter: bool = False,
    ) -> dict[str, Any]:
        with self.lock:
            if is_input:
                return self._send_input(command, no_enter)

            if self.busy:
                # A prior command timed out — it may well have finished by now.
                self._poll_pending(1.0)
            if self.busy:
                if command.strip() in ("C-c", "^C"):
                    return self._send_input(command, no_enter=True)
                return {
                    "content": (
                        "A command is already running in this terminal. Send is_input=true "
                        "to feed it input, or interrupt it first (command 'C-c')."
                    ),
                    "status": "error",
                    "exit_code": None,
                    "working_dir": self._cwd(),
                }

            os.write(self.fd, (command + "\n").encode())
            m, buf = self._read_until_marker(timeout)
            if m is not None:
                return {
                    "content": self._clean(buf[: m.start()]),
                    "status": "completed",
                    "exit_code": int(m.group(1)),
                    "working_dir": self._cwd(),
                }

            # Timed out: kill the foreground command tree, then resync to the marker.
            self._interrupt()
            m2, buf2 = self._read_until_marker(2.5)
            combined = buf + buf2
            m2 = self._mre.search(combined)
            self.busy = m2 is None
            content = self._clean(combined if m2 is None else combined[: m2.start()])
            note = (
                f"\n[Command still running after {timeout:.0f}s; interrupt sent.]"
                if self.busy
                else f"\n[Command exceeded {timeout:.0f}s and was interrupted.]"
            )
            return {
                "content": content + note,
                "status": "running" if self.busy else "timeout",
                "exit_code": None,
                "working_dir": self._cwd(),
            }

    def _send_input(self, data: str, no_enter: bool) -> dict[str, Any]:
        if data.strip() in ("C-c", "^C"):
            self._interrupt()
            m, out = self._read_until_marker(2.5)
            if m is not None:
                self.busy = False
            content = self._clean(out if m is None else out[: m.start()])
            return {
                "content": (content + "\n[Interrupted.]").strip("\n"),
                "status": "running" if self.busy else "completed",
                "exit_code": None,
                "working_dir": self._cwd(),
            }
        special = _special_key_bytes(data)
        if special is not None:
            os.write(self.fd, special)
        else:
            os.write(self.fd, data.encode() + (b"" if no_enter else b"\n"))
        # Did the program return to a prompt (marker) within a short window?
        m, out = self._read_until_marker(2.0)
        if m is not None:
            self.busy = False
        return {
            "content": self._clean(out if m is None else out[: m.start()]),
            "status": "running" if self.busy else "completed",
            "exit_code": None,
            "working_dir": self._cwd(),
        }

    def _child_pids(self) -> list[int]:
        """Direct child PIDs of the shell (the current foreground command tree)."""
        pids: list[int] = []
        try:
            entries = os.listdir("/proc")
        except OSError:
            return pids
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/stat", "rb") as f:
                    data = f.read()
            except OSError:
                continue
            try:
                ppid = int(data.rsplit(b")", 1)[1].split()[1])  # after comm: state, ppid
            except (IndexError, ValueError):
                continue
            if ppid == self.pid:
                pids.append(int(entry))
        return pids

    def _interrupt(self) -> None:
        """Terminate the running foreground command (not the shell itself).

        Signals descendants directly via /proc instead of relying on the pty's
        Ctrl-C path, which is not reliable across job-control edge cases.
        """
        children = self._child_pids()
        for pid in children:
            try:
                os.kill(pid, signal.SIGINT)
            except OSError:
                pass
        time.sleep(0.3)
        for pid in children:
            try:
                os.kill(pid, 0)
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    def _cwd(self) -> str:
        try:
            return os.readlink(f"/proc/{self.pid}/cwd")
        except OSError:
            return self.work_dir

    def close(self) -> None:
        with self.lock:
            try:
                os.write(self.fd, b"exit\n")
            except OSError:
                pass
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(self.pid, sig)
                except OSError:
                    break
                time.sleep(0.05)
            try:
                os.close(self.fd)
            except OSError:
                pass


# Map friendly key names (as the 0.1.x tool accepted) to the bytes to write.
_CTRL = {f"C-{c}": bytes([ord(c) - 96]) for c in "abcdefghijklmnopqrstuvwxyz"}
_NAMED_KEYS = {
    "Enter": b"\n", "Tab": b"\t", "Escape": b"\x1b", "Space": b" ",
    "BSpace": b"\x7f", "Up": b"\x1b[A", "Down": b"\x1b[B",
    "Right": b"\x1b[C", "Left": b"\x1b[D",
}


def _special_key_bytes(command: str) -> bytes | None:
    c = command.strip()
    if c in _CTRL:
        return _CTRL[c]
    if c in _NAMED_KEYS:
        return _NAMED_KEYS[c]
    if len(c) >= 2 and c.startswith("^") and f"C-{c[1:].lower()}" in _CTRL:
        return _CTRL[f"C-{c[1:].lower()}"]
    return None


# --------------------------------------------------------------------------- #
# Terminal manager (one PtyShell per terminal_id, created on demand).
# --------------------------------------------------------------------------- #
_shells: dict[str, PtyShell] = {}
_shells_lock = threading.Lock()


def _get_shell(terminal_id: str | None) -> PtyShell:
    tid = terminal_id or "main"
    with _shells_lock:
        shell = _shells.get(tid)
        if shell is None:
            shell = PtyShell(tid)
            _shells[tid] = shell
        return shell


# --------------------------------------------------------------------------- #
# Tool implementations. Each returns a dict; mcp_server.py renders result.content
# (or a plain string, or result.output/result.data, or json-dumps the dict).
# --------------------------------------------------------------------------- #
def tool_terminal_execute(
    command: str = "",
    terminal_id: str | None = None,
    timeout: float | None = None,
    is_input: bool = False,
    no_enter: bool = False,
    **_: Any,
) -> dict[str, Any]:
    shell = _get_shell(terminal_id)
    to = float(timeout) if timeout else DEFAULT_TERMINAL_TIMEOUT
    try:
        return shell.execute(command, timeout=to, is_input=is_input, no_enter=no_enter)
    except OSError as e:
        # pty died — respawn once so the terminal self-heals.
        with _shells_lock:
            _shells.pop(terminal_id or "main", None)
        return {"content": f"Terminal error ({e}); terminal was reset. Retry the command.",
                "status": "error", "exit_code": None, "working_dir": WORKSPACE}


def tool_python_action(
    action: str = "execute",
    code: str = "",
    timeout: int = 30,
    session_id: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    if action == "list_sessions":
        return {"content": "Python sessions are stateless in this build (each execute runs "
                           "fresh). Persist state via /workspace files or terminal_execute."}
    if action in ("new_session", "close"):
        return {"content": f"OK ({action}). Note: python sessions are stateless in this build; "
                           f"session_id is accepted but not persisted."}
    if not code.strip():
        return {"error": "No code provided for python_action execute."}
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", code],
            capture_output=True, text=True, timeout=max(1, int(timeout)),
            cwd=WORKSPACE if Path(WORKSPACE).is_dir() else None,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Python execution timed out after {timeout}s."}
    out = proc.stdout
    if proc.stderr:
        out = (out + "\n" if out else "") + proc.stderr
    return {"content": out or "(no output)", "exit_code": proc.returncode,
            "status": "completed" if proc.returncode == 0 else "error"}


def _resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else Path(WORKSPACE) / p


def tool_str_replace_editor(
    command: str,
    path: str,
    file_text: str | None = None,
    view_range: list[int] | None = None,
    old_str: str | None = None,
    new_str: str | None = None,
    insert_line: int | None = None,
    **_: Any,
) -> dict[str, Any]:
    target = _resolve(path)
    try:
        if command == "create":
            if file_text is None:
                return {"error": "file_text is required for create."}
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(file_text)
            return {"content": f"Created {target} ({len(file_text)} bytes)."}

        if command == "view":
            if target.is_dir():
                items = sorted(os.listdir(target))
                return {"content": f"Directory {target}:\n" + "\n".join(items)}
            text = target.read_text(errors="replace")
            lines = text.split("\n")
            start, end = 1, len(lines)
            if view_range and len(view_range) == 2:
                start, end = view_range
                start = max(1, start)
                end = len(lines) if end == -1 else min(end, len(lines))
            numbered = [f"{i:6d}\t{lines[i - 1]}" for i in range(start, end + 1)]
            return {"content": "\n".join(numbered)}

        if command == "str_replace":
            if old_str is None:
                return {"error": "old_str is required for str_replace."}
            text = target.read_text(errors="replace")
            count = text.count(old_str)
            if count == 0:
                return {"error": f"old_str not found in {target}."}
            if count > 1:
                return {"error": f"old_str is not unique in {target} ({count} matches)."}
            target.write_text(text.replace(old_str, new_str or ""))
            return {"content": f"Replaced 1 occurrence in {target}."}

        if command == "insert":
            if insert_line is None or new_str is None:
                return {"error": "insert_line and new_str are required for insert."}
            lines = target.read_text(errors="replace").split("\n")
            idx = max(0, min(insert_line, len(lines)))
            lines[idx:idx] = new_str.split("\n")
            target.write_text("\n".join(lines))
            return {"content": f"Inserted text at line {insert_line} in {target}."}

        return {"error": f"Unknown command '{command}'."}
    except OSError as e:
        return {"error": f"Error in {command} on {target}: {e}"}


def tool_list_files(path: str = ".", recursive: bool = False, **_: Any) -> dict[str, Any]:
    target = _resolve(path)
    if not target.exists():
        return {"error": f"Directory not found: {target}"}
    if not target.is_dir():
        return {"error": f"Path is not a directory: {target}"}
    files: list[str] = []
    dirs: list[str] = []
    try:
        if recursive:
            for root, dnames, fnames in os.walk(target):
                for d in dnames:
                    dirs.append(os.path.relpath(os.path.join(root, d), target))
                for f in fnames:
                    files.append(os.path.relpath(os.path.join(root, f), target))
                if len(files) + len(dirs) > 2000:
                    break
        else:
            for name in os.listdir(target):
                (dirs if (target / name).is_dir() else files).append(name)
    except OSError as e:
        return {"error": f"Error listing {target}: {e}"}
    return {"files": sorted(files), "directories": sorted(dirs),
            "total_files": len(files), "total_dirs": len(dirs),
            "path": str(target), "recursive": recursive}


def tool_send_request(
    method: str = "GET",
    url: str = "",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    if not url:
        return {"error": "url is required."}
    data = body.encode() if isinstance(body, str) else body
    req = urlrequest.Request(url, data=data, method=method.upper(),
                             headers=headers or {})
    try:
        with urlrequest.urlopen(req, timeout=60) as resp:  # noqa: S310
            return {"content": _format_http_response(resp.status, resp.reason,
                                                     resp.headers.items(), resp.read())}
    except urlerror.HTTPError as e:  # non-2xx still carries a full response
        return {"content": _format_http_response(e.code, e.reason,
                                                 e.headers.items() if e.headers else [],
                                                 e.read())}
    except (urlerror.URLError, OSError, ValueError) as e:
        return {"error": f"Request failed: {e}"}


def _format_http_response(status: Any, reason: Any, header_items: Any, body: bytes) -> str:
    head = f"HTTP {status} {reason or ''}".rstrip()
    hdrs = "\n".join(f"{k}: {v}" for k, v in header_items)
    text = body.decode("utf-8", errors="replace")
    if len(text) > 100_000:
        text = text[:100_000] + "\n...[truncated]"
    return f"{head}\n{hdrs}\n\n{text}"


# --- Browser: thin wrapper over the image's `agent-browser` CLI. ------------ #
_BROWSER_MAP = {
    "launch": ["open", "about:blank"],
    "close": ["close"],
    "get_html": ["eval", "document.documentElement.outerHTML"],
}


def tool_browser_action(
    action: str = "",
    url: str | None = None,
    selector: str | None = None,
    text: str | None = None,
    script: str | None = None,
    direction: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    if action == "goto":
        args = ["open", url or ""]
    elif action == "click":
        args = ["click", selector or ""]
    elif action == "type":
        args = ["type", selector or "", text or ""]
    elif action == "scroll":
        args = ["scroll", direction or "down"]
    elif action == "screenshot":
        out = f"{WORKSPACE}/screenshot-{uuid.uuid4().hex[:8]}.png"
        args = ["screenshot", out]
    elif action == "execute_js":
        args = ["eval", script or ""]
    elif action in _BROWSER_MAP:
        args = _BROWSER_MAP[action]
    else:
        return {"error": f"Unknown browser action '{action}'."}
    try:
        proc = subprocess.run(["agent-browser", *args], capture_output=True,
                              text=True, timeout=120,
                              cwd=WORKSPACE if Path(WORKSPACE).is_dir() else None)
    except FileNotFoundError:
        return {"error": "agent-browser is not available in this sandbox image."}
    except subprocess.TimeoutExpired:
        return {"error": f"browser action '{action}' timed out."}
    out = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    if action == "screenshot" and proc.returncode == 0:
        out = f"Screenshot saved to {args[1]} (inside sandbox).\n{out}".rstrip()
    if proc.returncode != 0 and not out.strip():
        out = f"browser action '{action}' failed (exit {proc.returncode})."
    return {"content": out or f"browser action '{action}' completed."}


# --- Proxy history: degraded. Caido request-history is not wired in 1.x. ----- #
_PROXY_NOTE = (
    "Proxy request-history is not available in the 1.x-compatible tool server. "
    "Use send_request for manual HTTP, or run curl/httpx/ffuf via terminal_execute. "
    "(The 1.x sandbox exposes Caido only over its GraphQL sidecar, which this "
    "self-contained shim does not integrate.)"
)


def tool_list_requests(**_: Any) -> dict[str, Any]:
    return {"content": _PROXY_NOTE}


def tool_view_request(**_: Any) -> dict[str, Any]:
    return {"content": _PROXY_NOTE}


def tool_repeat_request(**_: Any) -> dict[str, Any]:
    return {"content": _PROXY_NOTE + " To replay, re-issue it with send_request."}


TOOLS = {
    "terminal_execute": tool_terminal_execute,
    "python_action": tool_python_action,
    "str_replace_editor": tool_str_replace_editor,
    "list_files": tool_list_files,
    "send_request": tool_send_request,
    "browser_action": tool_browser_action,
    "list_requests": tool_list_requests,
    "view_request": tool_view_request,
    "repeat_request": tool_repeat_request,
}


# --------------------------------------------------------------------------- #
# HTTP server (stdlib) — mirrors the 0.1.x FastAPI /execute + /health contract.
# --------------------------------------------------------------------------- #
EXPECTED_TOKEN = ""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a: Any) -> None:  # silence default stderr logging
        pass

    def _json(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        auth = self.headers.get("Authorization", "")
        return auth.startswith("Bearer ") and auth[7:] == EXPECTED_TOKEN

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"status": "healthy", "environment": "sandbox",
                             "terminals": len(_shells)})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/execute":
            self._json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._json(401, {"error": "invalid or missing bearer token"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError) as e:
            self._json(400, {"error": f"bad request: {e}"})
            return

        tool_name = payload.get("tool_name", "")
        kwargs = payload.get("kwargs", {}) or {}
        func = TOOLS.get(tool_name)
        if func is None:
            self._json(200, {"result": None, "error": f"Tool '{tool_name}' not found"})
            return
        try:
            result = func(**kwargs)
            self._json(200, {"result": result, "error": None})
        except TypeError as e:
            self._json(200, {"result": None, "error": f"Invalid arguments for {tool_name}: {e}"})
        except Exception as e:  # noqa: BLE001 — never let a tool crash the server
            self._json(200, {"result": None, "error": f"Tool execution error: {e}"})


def main() -> None:
    global EXPECTED_TOKEN
    parser = argparse.ArgumentParser(description="Strix 1.x-compatible tool server shim")
    parser.add_argument("--token", required=True)
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    EXPECTED_TOKEN = args.token

    def _shutdown(*_a: Any) -> None:
        for shell in list(_shells.values()):
            shell.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[tool-server] listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
