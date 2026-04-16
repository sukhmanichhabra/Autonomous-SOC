"""
Response Automation Clients
===========================
Provides live API/SSH integrations for incident response actions so the
Response Agent can perform real defensive controls, not just shell commands.

Integrations
------------
1. Firewall API: block a source IP address.
2. EDR API: isolate a host/container endpoint.
3. Optional SSH fallback: run a remote isolation command.

All functions return the same ExecutionResult schema used by action_executor.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import requests

from config import settings
from tools.action_executor import ExecutionResult

try:
    import paramiko  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    paramiko = None


def _result(
    command: str,
    dry_run: bool,
    status: str,
    returncode: int | None,
    stdout: str,
    stderr: str,
    duration_ms: int,
) -> ExecutionResult:
    """Build a normalized ExecutionResult payload."""
    return {
        "command": command,
        "dry_run": dry_run,
        "status": status,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": duration_ms,
    }


def _truncate(text: str, max_len: int = 500) -> str:
    """Trim long API responses for concise report output."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def execute_firewall_block_api(
    target_ip: str,
    dry_run: bool = True,
    timeout: int | None = None,
) -> ExecutionResult:
    """
    Call a firewall API to block an IP.

    Uses configuration from:
        FIREWALL_API_URL: Base URL (default: http://127.0.0.1:5001)
        FIREWALL_API_TOKEN: Optional bearer token
        FIREWALL_BLOCK_PATH: Endpoint path (default: /api/v1/firewall/block-ip)
        FIREWALL_API_TIMEOUT: Timeout in seconds (default: 10)
    """
    start = time.monotonic()
    timeout = timeout or settings.firewall_api_timeout
    base_url = settings.firewall_api_url.rstrip("/")
    path = settings.firewall_block_path
    url = f"{base_url}{path}"
    command = f"API POST {url} block_ip={target_ip}"

    payload = {
        "ip": target_ip,
        "reason": "Automated SOC mitigation",
        "source": "response_agent",
    }

    if dry_run:
        elapsed = int((time.monotonic() - start) * 1000)
        return _result(
            command,
            True,
            "DRY_RUN",
            None,
            f"[DRY RUN] Would call firewall API with payload: {json.dumps(payload)}",
            "",
            elapsed,
        )

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.firewall_api_token:
        headers["Authorization"] = f"Bearer {settings.firewall_api_token}"

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        elapsed = int((time.monotonic() - start) * 1000)

        body_text = _truncate(resp.text.strip() or "<empty response>")
        if 200 <= resp.status_code < 300:
            return _result(
                command,
                False,
                "SUCCESS",
                0,
                f"HTTP {resp.status_code}: {body_text}",
                "",
                elapsed,
            )

        return _result(
            command,
            False,
            "FAILED",
            resp.status_code,
            "",
            f"HTTP {resp.status_code}: {body_text}",
            elapsed,
        )
    except requests.Timeout:
        elapsed = int((time.monotonic() - start) * 1000)
        return _result(
            command,
            False,
            "TIMEOUT",
            None,
            "",
            f"Firewall API call timed out after {timeout}s.",
            elapsed,
        )
    except Exception as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        return _result(command, False, "ERROR", None, "", str(exc), elapsed)


def execute_edr_isolation_api(
    target_ip: str,
    dry_run: bool = True,
    timeout: int | None = None,
) -> ExecutionResult:
    """
    Call an EDR API to isolate a host/container associated with target_ip.

    Uses configuration from:
        EDR_API_URL: Base URL (default: http://127.0.0.1:5002)
        EDR_API_TOKEN: Optional bearer token
        EDR_ISOLATE_PATH: Endpoint path (default: /api/v1/edr/isolate-host)
        EDR_API_TIMEOUT: Timeout in seconds (default: 10)
    """
    start = time.monotonic()
    timeout = timeout or settings.edr_api_timeout
    base_url = settings.edr_api_url.rstrip("/")
    path = settings.edr_isolate_path
    url = f"{base_url}{path}"
    command = f"API POST {url} isolate_host={target_ip}"

    payload = {
        "host": target_ip,
        "isolation_mode": "network_quarantine",
        "source": "response_agent",
    }

    if dry_run:
        elapsed = int((time.monotonic() - start) * 1000)
        return _result(
            command,
            True,
            "DRY_RUN",
            None,
            f"[DRY RUN] Would call EDR API with payload: {json.dumps(payload)}",
            "",
            elapsed,
        )

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.edr_api_token:
        headers["Authorization"] = f"Bearer {settings.edr_api_token}"

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        elapsed = int((time.monotonic() - start) * 1000)

        body_text = _truncate(resp.text.strip() or "<empty response>")
        if 200 <= resp.status_code < 300:
            return _result(
                command,
                False,
                "SUCCESS",
                0,
                f"HTTP {resp.status_code}: {body_text}",
                "",
                elapsed,
            )

        return _result(
            command,
            False,
            "FAILED",
            resp.status_code,
            "",
            f"HTTP {resp.status_code}: {body_text}",
            elapsed,
        )
    except requests.Timeout:
        elapsed = int((time.monotonic() - start) * 1000)
        return _result(
            command,
            False,
            "TIMEOUT",
            None,
            "",
            f"EDR API call timed out after {timeout}s.",
            elapsed,
        )
    except Exception as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        return _result(command, False, "ERROR", None, "", str(exc), elapsed)


def execute_ssh_isolation(
    target_ip: str,
    dry_run: bool = True,
    timeout: int = 10,
) -> ExecutionResult:
    """
    Optional SSH fallback to run host isolation command remotely via paramiko.

    Environment variables:
        RESPONSE_SSH_HOST: SSH server hostname/IP (required for live run)
        RESPONSE_SSH_PORT: SSH port (default: 22)
        RESPONSE_SSH_USER: SSH username (required for live run)
        RESPONSE_SSH_PASSWORD: SSH password (optional if using key)
        RESPONSE_SSH_KEY_PATH: SSH private key path (optional)
        RESPONSE_SSH_ISOLATION_COMMAND:
            Command template. Supports {target_ip} placeholder.
    """
    start = time.monotonic()
    ssh_host = os.getenv("RESPONSE_SSH_HOST", "").strip()
    ssh_user = os.getenv("RESPONSE_SSH_USER", "").strip()
    ssh_port = int(os.getenv("RESPONSE_SSH_PORT", "22"))
    ssh_password = os.getenv("RESPONSE_SSH_PASSWORD", "")
    ssh_key_path = os.getenv("RESPONSE_SSH_KEY_PATH", "").strip()
    cmd_template = os.getenv(
        "RESPONSE_SSH_ISOLATION_COMMAND",
        "sudo iptables -A INPUT -s {target_ip} -j DROP && sudo iptables -A OUTPUT -d {target_ip} -j DROP",
    )
    remote_cmd = cmd_template.format(target_ip=target_ip)
    command = f"SSH {ssh_user or '<user>'}@{ssh_host or '<host>'}:{ssh_port} '{remote_cmd}'"

    if dry_run:
        elapsed = int((time.monotonic() - start) * 1000)
        return _result(
            command,
            True,
            "DRY_RUN",
            None,
            f"[DRY RUN] Would execute remote SSH isolation command for {target_ip}.",
            "",
            elapsed,
        )

    if not ssh_host or not ssh_user:
        elapsed = int((time.monotonic() - start) * 1000)
        return _result(
            command,
            False,
            "BLOCKED",
            None,
            "",
            "Missing RESPONSE_SSH_HOST or RESPONSE_SSH_USER environment variables.",
            elapsed,
        )

    if paramiko is None:
        elapsed = int((time.monotonic() - start) * 1000)
        return _result(
            command,
            False,
            "ERROR",
            None,
            "",
            "paramiko is not installed. Install it to enable SSH isolation.",
            elapsed,
        )

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict[str, Any] = {
            "hostname": ssh_host,
            "port": ssh_port,
            "username": ssh_user,
            "timeout": timeout,
        }
        if ssh_key_path:
            connect_kwargs["key_filename"] = ssh_key_path
        else:
            connect_kwargs["password"] = ssh_password

        client.connect(**connect_kwargs)
        stdin, stdout, stderr = client.exec_command(remote_cmd, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        out_text = _truncate(stdout.read().decode("utf-8", errors="replace").strip())
        err_text = _truncate(stderr.read().decode("utf-8", errors="replace").strip())
        client.close()

        elapsed = int((time.monotonic() - start) * 1000)
        status = "SUCCESS" if rc == 0 else "FAILED"
        return _result(command, False, status, rc, out_text, err_text, elapsed)
    except Exception as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        return _result(command, False, "ERROR", None, "", str(exc), elapsed)


def execute_api_response_actions(
    target_ip: str,
    dry_run: bool = True,
) -> list[ExecutionResult]:
    """
    Execute API-driven defensive controls for a high-risk incident.

    Order:
        1) Firewall block IP
        2) EDR host/container isolation
        3) Optional SSH isolation fallback (controlled by env flag)
    """
    results: list[ExecutionResult] = []

    results.append(execute_firewall_block_api(target_ip, dry_run=dry_run))
    results.append(execute_edr_isolation_api(target_ip, dry_run=dry_run))

    enable_ssh = os.getenv("RESPONSE_ENABLE_SSH_ACTIONS", "false").strip().lower()
    if enable_ssh in ("1", "true", "yes", "on"):
        results.append(execute_ssh_isolation(target_ip, dry_run=dry_run))

    return results
