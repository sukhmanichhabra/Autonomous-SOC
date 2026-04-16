#!/usr/bin/env python3
"""
Deployment smoke test for the SOC refactor.

Checks:
  1. Required environment variables are loaded.
  2. PostgreSQL connectivity, pgvector extension, and LangGraph setup.
  3. SSH configuration parsing without making a network connection.
  4. Nmap executable resolution and incident directory write access.

Usage:
    python test_deployment.py
"""

from __future__ import annotations

import os
import shutil
import importlib
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR / "my-ai-soc-agent"
ROOT_ENV = BASE_DIR / ".env"
PROJECT_ENV = PROJECT_DIR / ".env"


def _load_project_environment() -> None:
    """Load .env files before importing project settings."""
    try:
        from dotenv import load_dotenv
    except ImportError as exc:  # pragma: no cover - hard dependency check
        print(f"[FAIL] python-dotenv is not installed: {exc}")
        raise SystemExit(1)

    if ROOT_ENV.exists():
        load_dotenv(ROOT_ENV, override=False)
    if PROJECT_ENV.exists():
        load_dotenv(PROJECT_ENV, override=True)


if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

_load_project_environment()

try:
    settings = importlib.import_module("config").settings
except Exception as exc:  # pragma: no cover - import failure is terminal
    print(f"[FAIL] Could not import project settings: {exc}")
    raise SystemExit(1)

try:
    import paramiko
except ImportError as exc:  # pragma: no cover - hard dependency check
    print(f"[FAIL] paramiko is not installed: {exc}")
    raise SystemExit(1)

try:
    from langgraph.checkpoint.postgres import PostgresSaver
except ImportError as exc:  # pragma: no cover - hard dependency check
    print(f"[FAIL] langgraph PostgresSaver is not installed: {exc}")
    raise SystemExit(1)

try:
    from psycopg import connect
except ImportError as exc:  # pragma: no cover - hard dependency check
    print(f"[FAIL] psycopg is not installed: {exc}")
    raise SystemExit(1)


@dataclass
class CheckResult:
    name: str
    passed: bool
    details: str


def _is_non_empty(value: str | None) -> bool:
    return value is not None and value.strip() != ""


def _print_result(result: CheckResult) -> None:
    status = "PASS" if result.passed else "FAIL"
    print(f"[{status}] {result.name}: {result.details}")


def _resolve_required_env() -> list[CheckResult]:
    required_vars = [
        "GROQ_API_KEY",
        "DATABASE_URL",
        "DB_URL",
        "TARGET_HOST",
        "TARGET_USER",
        "SSH_KEY_PATH",
        "NMAP_PATH",
        "INCIDENTS_DIR",
    ]

    results: list[CheckResult] = []
    for name in required_vars:
        value = os.getenv(name)
        results.append(
            CheckResult(
                name=f"Environment variable {name}",
                passed=_is_non_empty(value),
                details="loaded" if _is_non_empty(value) else "missing or empty",
            )
        )

    return results


def _list_checkpoint_tables(conn) -> list[str]:
    with conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT tablename
            FROM pg_tables
            WHERE schemaname = 'public'
              AND (tablename LIKE 'checkpoint%%' OR tablename LIKE 'langgraph%%')
            ORDER BY tablename
            """
        )
        rows = cursor.fetchall()
    return [row[0] for row in rows]


def _check_postgres() -> list[CheckResult]:
    results: list[CheckResult] = []

    db_url = os.getenv("DATABASE_URL") or os.getenv("DB_URL") or settings.database_url
    if not _is_non_empty(db_url):
        return [
            CheckResult(
                name="PostgreSQL connection string",
                passed=False,
                details="DATABASE_URL/DB_URL is missing",
            )
        ]

    try:
        conn = connect(db_url, autocommit=True, connect_timeout=5)
    except Exception as exc:
        return [
            CheckResult(
                name="PostgreSQL connectivity",
                passed=False,
                details=str(exc),
            )
        ]

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        results.append(
            CheckResult(
                name="PostgreSQL connectivity",
                passed=True,
                details="SELECT 1 succeeded",
            )
        )

        with conn.cursor() as cursor:
            cursor.execute("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
            row = cursor.fetchone()
        results.append(
            CheckResult(
                name="pgvector extension",
                passed=row is not None and _is_non_empty(str(row[0]) if row[0] is not None else None),
                details=f"version={row[0]}" if row else "vector extension is not installed",
            )
        )

        checkpoint_tables_before = _list_checkpoint_tables(conn)
        setup_error = None
        try:
            saver = PostgresSaver.from_conn_string(db_url)
            setup_method = getattr(saver, "setup", None)
            if not callable(setup_method):
                raise AttributeError("PostgresSaver.setup() is not available in this version")
            setup_method()
        except Exception as exc:
            setup_error = exc

        checkpoint_tables_after = _list_checkpoint_tables(conn)
        if setup_error is None:
            results.append(
                CheckResult(
                    name="LangGraph PostgresSaver setup",
                    passed=True,
                    details="setup() completed successfully",
                )
            )
        else:
            results.append(
                CheckResult(
                    name="LangGraph PostgresSaver setup",
                    passed=False,
                    details=str(setup_error),
                )
            )

        tables = checkpoint_tables_after or checkpoint_tables_before
        results.append(
            CheckResult(
                name="LangGraph checkpoint tables",
                passed=len(tables) > 0,
                details=", ".join(tables) if tables else "no checkpoint tables found",
            )
        )

    finally:
        conn.close()

    return results


def _parse_ssh_private_key(key_path: Path) -> tuple[bool, str]:
    loaders: list[tuple[str, Callable[..., object]]] = []
    if hasattr(paramiko, "Ed25519Key"):
        loaders.append(("Ed25519", paramiko.Ed25519Key.from_private_key_file))
    if hasattr(paramiko, "ECDSAKey"):
        loaders.append(("ECDSA", paramiko.ECDSAKey.from_private_key_file))
    if hasattr(paramiko, "RSAKey"):
        loaders.append(("RSA", paramiko.RSAKey.from_private_key_file))
    if hasattr(paramiko, "DSSKey"):
        loaders.append(("DSA", paramiko.DSSKey.from_private_key_file))

    last_error: Exception | None = None
    for key_type, loader in loaders:
        try:
            loader(str(key_path))
            return True, f"parsed successfully as {key_type}"
        except Exception as exc:  # try the next key type
            last_error = exc

    return False, str(last_error) if last_error else "unable to parse SSH private key"


def _check_ssh_configuration() -> list[CheckResult]:
    target_host = os.getenv("TARGET_HOST", "").strip()
    ssh_key_path = Path(os.getenv("SSH_KEY_PATH", "").strip()).expanduser()

    results: list[CheckResult] = []
    results.append(
        CheckResult(
            name="TARGET_HOST",
            passed=_is_non_empty(target_host),
            details=target_host or "missing",
        )
    )

    results.append(
        CheckResult(
            name="SSH_KEY_PATH exists",
            passed=ssh_key_path.exists() and ssh_key_path.is_file(),
            details=str(ssh_key_path) if ssh_key_path.exists() else "file not found",
        )
    )

    if ssh_key_path.exists() and ssh_key_path.is_file():
        parsed, details = _parse_ssh_private_key(ssh_key_path)
        results.append(
            CheckResult(
                name="Paramiko SSH key parsing",
                passed=parsed,
                details=details,
            )
        )
    else:
        results.append(
            CheckResult(
                name="Paramiko SSH key parsing",
                passed=False,
                details="cannot parse a missing key file",
            )
        )

    if _is_non_empty(target_host) and ssh_key_path.exists():
        results.append(
            CheckResult(
                name="SSH dry-run readiness",
                passed=True,
                details=f"ready to connect to {target_host} using {ssh_key_path}",
            )
        )
    else:
        results.append(
            CheckResult(
                name="SSH dry-run readiness",
                passed=False,
                details="TARGET_HOST and SSH_KEY_PATH must both be set",
            )
        )

    return results


def _resolve_nmap_path() -> tuple[bool, str]:
    configured = os.getenv("NMAP_PATH", settings.nmap_path).strip()
    if not configured:
        return False, "NMAP_PATH is empty"

    path = Path(configured).expanduser()
    if path.is_file() and os.access(path, os.X_OK):
        return True, str(path)

    resolved = shutil.which(configured)
    if resolved:
        return True, resolved

    return False, f"not executable or not found: {configured}"


def _check_incident_directory() -> tuple[bool, str]:
    incidents_dir = Path(os.getenv("INCIDENTS_DIR", settings.incidents_dir)).expanduser()
    try:
        incidents_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return False, f"could not create directory: {exc}"

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=incidents_dir,
            prefix=".deployment_smoke_",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write("deployment smoke test\n")
            temp_path = Path(handle.name)
        temp_path.unlink(missing_ok=True)
        return True, str(incidents_dir)
    except Exception as exc:
        return False, str(exc)


def _run_checks() -> list[CheckResult]:
    results: list[CheckResult] = []
    results.extend(_resolve_required_env())
    results.extend(_check_postgres())
    results.extend(_check_ssh_configuration())

    nmap_ok, nmap_details = _resolve_nmap_path()
    results.append(
        CheckResult(
            name="NMAP_PATH executable",
            passed=nmap_ok,
            details=nmap_details,
        )
    )

    incidents_ok, incidents_details = _check_incident_directory()
    results.append(
        CheckResult(
            name="Incident directory writable",
            passed=incidents_ok,
            details=incidents_details,
        )
    )

    return results


def main() -> int:
    print("=" * 72)
    print("Deployment Smoke Tests")
    print("=" * 72)
    print(f"Project root: {BASE_DIR}")
    print(f"Loaded env: {ROOT_ENV if ROOT_ENV.exists() else '(missing)'}")
    print(f"Loaded env: {PROJECT_ENV if PROJECT_ENV.exists() else '(missing)'}")
    print()

    results = _run_checks()
    for result in results:
        _print_result(result)

    passed = sum(1 for result in results if result.passed)
    failed = len(results) - passed
    print()
    print("=" * 72)
    print(f"Summary: {passed} passed, {failed} failed")
    print("=" * 72)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())