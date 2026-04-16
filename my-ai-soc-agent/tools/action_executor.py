"""
Action Executor Tool
====================
Provides ``execute_remediation(command, dry_run)`` — the bridge between
the AI-generated mitigation plan and remote defensive actions over SSH.

This is what turns the pipeline from a **passive advisor** into an
**active SOAR** (Security Orchestration, Automation and Response) system.

Security model
--------------
* ``dry_run=True``  (default) — the command is *printed and validated*
  but **never executed**.  Safe for all environments.
* ``dry_run=False`` — the command is executed over SSH on the target
    host using ``paramiko`` with a 30-second timeout.  Only set this to
    ``False`` after the human operator has explicitly approved execution.

SSH configuration
-----------------
The target host, user, and private key are read from environment
variables:

        TARGET_HOST, TARGET_USER, SSH_KEY_PATH

Safety guard
------------
Execution is blocked if the configured target resolves to the local
machine unless ``ALLOW_LOCAL_EXECUTION=true`` is explicitly set.

Allowed commands
----------------
Only a hard-coded allowlist of *prefixes* may be executed even in live
mode.  Any command that does not start with one of the permitted tokens
is rejected and logged as ``BLOCKED``.

Allowed prefixes
~~~~~~~~~~~~~~~~
    iptables, ip6tables, ufw, firewall-cmd, nft,
    aws ec2, systemctl, service,
    apt-get, apt, yum, dnf,
    sudo iptables, sudo ip6tables, sudo ufw, sudo firewall-cmd,
    sudo nft, sudo systemctl, sudo service,
    sudo apt-get, sudo apt, sudo yum, sudo dnf

Return value
------------
Every call returns an ``ExecutionResult`` dict::

    {
        "command":     str,          # the original command string
        "dry_run":     bool,         # True → simulated, False → real
        "status":      str,          # "DRY_RUN" | "SUCCESS" | "FAILED" | "TIMEOUT" | "BLOCKED" | "ERROR"
        "returncode":  int | None,   # subprocess return code (None for dry_run / blocked)
        "stdout":      str,          # captured stdout
        "stderr":      str,          # captured stderr
        "duration_ms": int,          # wall-clock time in milliseconds
    }
"""

from __future__ import annotations

import os
import re
import shlex
import socket
import time
from pathlib import Path
from typing import TypedDict

import paramiko

from config import settings


# ---------------------------------------------------------------------------
# Return-type definition
# ---------------------------------------------------------------------------
class ExecutionResult(TypedDict):
    command: str
    dry_run: bool
    status: str          # DRY_RUN | SUCCESS | FAILED | TIMEOUT | BLOCKED | ERROR
    returncode: int | None
    stdout: str
    stderr: str
    duration_ms: int


# ---------------------------------------------------------------------------
# Allowlist — only these command prefixes may be executed in live mode
# ---------------------------------------------------------------------------
_ALLOWED_PREFIXES: tuple[str, ...] = (
    # Firewall
    "iptables ",
    "ip6tables ",
    "ufw ",
    "firewall-cmd ",
    "nft ",
    # Cloud
    "aws ec2 ",
    # Service management
    "systemctl ",
    "service ",
    # Package management
    "apt-get ",
    "apt ",
    "yum ",
    "dnf ",
    # sudo variants — strip sudo and re-check, but also allow directly
    "sudo iptables ",
    "sudo ip6tables ",
    "sudo ufw ",
    "sudo firewall-cmd ",
    "sudo nft ",
    "sudo systemctl ",
    "sudo service ",
    "sudo apt-get ",
    "sudo apt ",
    "sudo yum ",
    "sudo dnf ",
)

# Timeout for live execution (seconds)
_EXEC_TIMEOUT = 30

# ANSI colours (console only)
_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def execute_remediation(
    command: str,
    dry_run: bool = True,
) -> ExecutionResult:
    """
    Execute (or simulate) a single remediation shell command.

    Parameters
    ----------
    command:
        The shell command string to run remotely, e.g.
        ``"iptables -A INPUT -s 10.0.0.1 -p tcp --dport 22 -j DROP"``
    dry_run:
        * ``True``  — print the command but do **not** run it.
        * ``False`` — run the command via ``subprocess.run`` with a
          30-second hard timeout and capture stdout/stderr.

    Returns
    -------
    ExecutionResult
        Dict with ``command``, ``dry_run``, ``status``, ``returncode``,
        ``stdout``, ``stderr``, and ``duration_ms``.
    """
    command = command.strip()
    start = time.monotonic()

    target_host = settings.target_host.strip()
    target_user = settings.target_user.strip()
    ssh_key_path = settings.ssh_key_path.strip()
    allow_local_execution = settings.allow_local_execution

    # ── Allowlist check (applies even in dry_run to flag bad commands) ──
    if not _is_allowed(command):
        elapsed = int((time.monotonic() - start) * 1000)
        result: ExecutionResult = {
            "command":     command,
            "dry_run":     dry_run,
            "status":      "BLOCKED",
            "returncode":  None,
            "stdout":      "",
            "stderr":      f"Command rejected: not in the allowed-command allowlist.",
            "duration_ms": elapsed,
        }
        _print_result(result)
        return result

    # ── Local-host safety gate ──────────────────────────────────────────
    if _is_local_target(target_host) and not allow_local_execution:
        elapsed = int((time.monotonic() - start) * 1000)
        result = {
            "command": command,
            "dry_run": dry_run,
            "status": "BLOCKED",
            "returncode": None,
            "stdout": "",
            "stderr": (
                "Execution blocked: TARGET_HOST resolves to the local machine. "
                "Set ALLOW_LOCAL_EXECUTION=true only if you explicitly want to "
                "authorize local execution."
            ),
            "duration_ms": elapsed,
        }
        _print_result(result)
        return result

    if not target_host or not target_user:
        elapsed = int((time.monotonic() - start) * 1000)
        result = {
            "command": command,
            "dry_run": dry_run,
            "status": "BLOCKED",
            "returncode": None,
            "stdout": "",
            "stderr": "Missing TARGET_HOST or TARGET_USER environment variables.",
            "duration_ms": elapsed,
        }
        _print_result(result)
        return result

    ssh_key_file = Path(ssh_key_path).expanduser() if ssh_key_path else None
    if not ssh_key_file or not ssh_key_file.exists() or not ssh_key_file.is_file():
        elapsed = int((time.monotonic() - start) * 1000)
        missing_path = ssh_key_path or "<empty>"
        result = {
            "command": command,
            "dry_run": dry_run,
            "status": "BLOCKED",
            "returncode": None,
            "stdout": "",
            "stderr": (
                "SSH key file not found or not readable: "
                f"{missing_path}. Set SSH_KEY_PATH to a valid private key file "
                "before running live SSH execution."
            ),
            "duration_ms": elapsed,
        }
        _print_result(result)
        return result

    # ── Dry-run path ────────────────────────────────────────────────────
    if dry_run:
        elapsed = int((time.monotonic() - start) * 1000)
        remote_target = f"{target_user}@{target_host}" if target_user and target_host else "<unset>"
        result = {
            "command":     command,
            "dry_run":     True,
            "status":      "DRY_RUN",
            "returncode":  None,
            "stdout":      (
                f"[DRY RUN] Would execute over SSH on {remote_target}: {command}"
            ),
            "stderr":      "",
            "duration_ms": elapsed,
        }
        _print_result(result)
        return result

    # ── Live execution path ─────────────────────────────────────────────
    ssh_client = None
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": target_host,
            "username": target_user,
            "timeout": _EXEC_TIMEOUT,
            "banner_timeout": _EXEC_TIMEOUT,
            "auth_timeout": _EXEC_TIMEOUT,
        }
        connect_kwargs["key_filename"] = str(ssh_key_file)

        ssh_client.connect(**connect_kwargs)
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=_EXEC_TIMEOUT)
        rc = stdout.channel.recv_exit_status()
        ssh_out = stdout.read().decode("utf-8", errors="replace").strip()
        ssh_err = stderr.read().decode("utf-8", errors="replace").strip()
        ssh_client.close()

        elapsed = int((time.monotonic() - start) * 1000)
        status = "SUCCESS" if rc == 0 else "FAILED"
        result = {
            "command":     command,
            "dry_run":     False,
            "status":      status,
            "returncode":  rc,
            "stdout":      ssh_out,
            "stderr":      ssh_err,
            "duration_ms": elapsed,
        }

    except (paramiko.SSHException, socket.timeout) as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        result = {
            "command":     command,
            "dry_run":     False,
            "status":      "TIMEOUT" if isinstance(exc, socket.timeout) else "ERROR",
            "returncode":  None,
            "stdout":      "",
            "stderr":      str(exc),
            "duration_ms": elapsed,
        }

    except Exception as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        result = {
            "command":     command,
            "dry_run":     False,
            "status":      "ERROR",
            "returncode":  None,
            "stdout":      "",
            "stderr":      str(exc),
            "duration_ms": elapsed,
        }

    finally:
        if ssh_client is not None:
            try:
                ssh_client.close()
            except Exception:
                pass

    _print_result(result)
    return result


def execute_remediation_plan(
    commands: list[str],
    dry_run: bool = True,
) -> list[ExecutionResult]:
    """
    Execute (or simulate) a list of remediation commands in order.

    Execution stops early if a live command returns a non-zero exit code
    (unless it's a dry-run, where all commands are always reported).

    Parameters
    ----------
    commands:
        Ordered list of shell command strings.
    dry_run:
        Passed verbatim to each :func:`execute_remediation` call.

    Returns
    -------
    list[ExecutionResult]
        One result dict per command.
    """
    results: list[ExecutionResult] = []

    print(f"\n{_BOLD}{'─'*60}")
    mode = "DRY-RUN SIMULATION" if dry_run else "⚠️  LIVE EXECUTION"
    print(f"  ACTION EXECUTOR — {mode} ({len(commands)} command(s))")
    print(f"{'─'*60}{_RESET}")

    for idx, cmd in enumerate(commands, 1):
        print(f"\n  [{idx:02d}/{len(commands):02d}] ", end="")
        result = execute_remediation(cmd, dry_run=dry_run)
        results.append(result)

        # Abort on first live failure (dry-run always continues)
        if not dry_run and result["status"] == "FAILED":
            print(
                f"\n{_RED}{_BOLD}  ⛔  Aborting: command {idx} exited "
                f"with code {result['returncode']}.{_RESET}"
            )
            break

    # Summary line
    statuses = [r["status"] for r in results]
    n_ok  = statuses.count("SUCCESS") + statuses.count("DRY_RUN")
    n_err = len(statuses) - n_ok
    colour = _GREEN if n_err == 0 else _RED
    print(f"\n{colour}{_BOLD}  SUMMARY: {n_ok}/{len(results)} commands "
          f"{'simulated' if dry_run else 'succeeded'} — "
          f"{n_err} error(s).{_RESET}\n")

    return results


def format_execution_results(results: list[ExecutionResult]) -> str:
    """
    Render a list of ExecutionResult dicts as a human-readable string
    suitable for storing in ``state['execution_results_text']`` or
    appending to the incident report.
    """
    if not results:
        return "No commands were executed."

    lines: list[str] = [
        "EXECUTION RESULTS",
        "─" * 50,
    ]
    for r in results:
        icon = {
            "DRY_RUN": "🔵",
            "SUCCESS": "✅",
            "FAILED":  "❌",
            "TIMEOUT": "⏱️",
            "BLOCKED": "🚫",
            "ERROR":   "💥",
        }.get(r["status"], "❓")

        lines.append(f"{icon} [{r['status']:8s}] {r['command']}")
        if r["stdout"]:
            for ln in r["stdout"].splitlines():
                lines.append(f"          stdout: {ln}")
        if r["stderr"]:
            for ln in r["stderr"].splitlines():
                lines.append(f"          stderr: {ln}")
        lines.append(f"          duration: {r['duration_ms']}ms  |  "
                     f"returncode: {r['returncode']}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _is_allowed(command: str) -> bool:
    """Return True if *command* starts with a permitted prefix."""
    cmd_lower = command.lower().lstrip()
    return any(cmd_lower.startswith(p.lower()) for p in _ALLOWED_PREFIXES)


def _is_local_target(target_host: str) -> bool:
    """Return True when the configured target resolves to this machine."""
    if not target_host:
        return True

    normalized = target_host.strip().lower()
    local_names = {
        "localhost",
        "127.0.0.1",
        "::1",
        socket.gethostname().lower(),
        socket.getfqdn().lower(),
    }

    try:
        local_names.update({alias.lower() for alias in socket.gethostbyname_ex(socket.gethostname())[1]})
    except Exception:
        pass

    if normalized in local_names:
        return True

    try:
        target_ip = socket.gethostbyname(target_host)
        local_ips = {"127.0.0.1", "::1"}
        try:
            local_ips.add(socket.gethostbyname(socket.gethostname()))
        except Exception:
            pass
        return target_ip in local_ips
    except Exception:
        return normalized in local_names


def _print_result(result: ExecutionResult) -> None:
    """Pretty-print a single ExecutionResult to the console."""
    status_colours = {
        "DRY_RUN": _CYAN,
        "SUCCESS": _GREEN,
        "FAILED":  _RED,
        "TIMEOUT": _YELLOW,
        "BLOCKED": _RED,
        "ERROR":   _RED,
    }
    colour = status_colours.get(result["status"], _RESET)
    tag = f"[{result['status']:8s}]"

    print(f"{colour}{_BOLD}{tag}{_RESET} {result['command']}")
    if result["stdout"] and result["status"] != "DRY_RUN":
        print(f"         stdout → {result['stdout'][:200]}")
    if result["stderr"]:
        print(f"         stderr → {result['stderr'][:200]}")
