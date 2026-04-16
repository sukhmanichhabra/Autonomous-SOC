#!/usr/bin/env python3
"""
Simulated Firewall/EDR API Server
=================================
Local demo server that emulates defensive control-plane APIs.

Endpoints
---------
GET  /health
GET  /api/v1/state
POST /api/v1/firewall/block-ip
POST /api/v1/edr/isolate-host

Usage
-----
python simulated_defense_api.py --host 127.0.0.1 --port 5001 --role firewall
python simulated_defense_api.py --host 127.0.0.1 --port 5002 --role edr
python simulated_defense_api.py --host 127.0.0.1 --port 5001 --role both

Optional Auth
-------------
Set SIMULATED_DEFENSE_API_TOKEN to require "Authorization: Bearer <token>".
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


_STATE: dict[str, Any] = {
    "blocked_ips": [],
    "isolated_hosts": [],
    "events": [],
    "role": "both",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2).encode("utf-8")


def _append_unique(lst: list[str], value: str) -> None:
    if value not in lst:
        lst.append(value)


class DefenseAPIHandler(BaseHTTPRequestHandler):
    """HTTP handler for simulated defense control actions."""

    server_version = "SimDefenseAPI/1.0"

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> dict[str, Any]:
        content_len = int(self.headers.get("Content-Length", "0"))
        if content_len <= 0:
            return {}
        body = self.rfile.read(content_len).decode("utf-8", errors="replace")
        if not body.strip():
            return {}
        try:
            parsed = json.loads(body)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}

    def _is_authorized(self) -> bool:
        token = os.getenv("SIMULATED_DEFENSE_API_TOKEN", "").strip()
        if not token:
            return True
        authz = self.headers.get("Authorization", "")
        return authz == f"Bearer {token}"

    def _method_not_allowed(self) -> None:
        self._send_json(405, {"error": "Method not allowed"})

    def do_GET(self) -> None:  # noqa: N802
        if not self._is_authorized():
            self._send_json(401, {"error": "Unauthorized"})
            return

        if self.path == "/health":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "service": "simulated-defense-api",
                    "timestamp": _utc_now(),
                    "role": _STATE.get("role", "both"),
                },
            )
            return

        if self.path == "/api/v1/state":
            self._send_json(
                200,
                {
                    "role": _STATE.get("role", "both"),
                    "blocked_ips": _STATE["blocked_ips"],
                    "isolated_hosts": _STATE["isolated_hosts"],
                    "events": _STATE["events"],
                },
            )
            return

        self._send_json(404, {"error": f"Unknown endpoint: {self.path}"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._is_authorized():
            self._send_json(401, {"error": "Unauthorized"})
            return

        body = self._read_json_body()
        role = str(_STATE.get("role", "both")).lower()

        if self.path == "/api/v1/firewall/block-ip":
            if role not in ("both", "firewall"):
                self._send_json(404, {"error": "Firewall API disabled for this server role"})
                return

            ip = str(body.get("ip", "")).strip()
            if not ip:
                self._send_json(400, {"error": "Missing required field: ip"})
                return

            _append_unique(_STATE["blocked_ips"], ip)
            event = {
                "timestamp": _utc_now(),
                "action": "firewall_block_ip",
                "ip": ip,
                "source": body.get("source", "unknown"),
                "reason": body.get("reason", "unspecified"),
            }
            _STATE["events"].append(event)

            self._send_json(
                200,
                {
                    "status": "success",
                    "action": "firewall_block_ip",
                    "blocked_ip": ip,
                    "total_blocked": len(_STATE["blocked_ips"]),
                    "event": event,
                },
            )
            return

        if self.path == "/api/v1/edr/isolate-host":
            if role not in ("both", "edr"):
                self._send_json(404, {"error": "EDR API disabled for this server role"})
                return

            host = str(body.get("host", "")).strip()
            if not host:
                self._send_json(400, {"error": "Missing required field: host"})
                return

            _append_unique(_STATE["isolated_hosts"], host)
            event = {
                "timestamp": _utc_now(),
                "action": "edr_isolate_host",
                "host": host,
                "source": body.get("source", "unknown"),
                "isolation_mode": body.get("isolation_mode", "network_quarantine"),
            }
            _STATE["events"].append(event)

            self._send_json(
                200,
                {
                    "status": "success",
                    "action": "edr_isolate_host",
                    "isolated_host": host,
                    "total_isolated": len(_STATE["isolated_hosts"]),
                    "event": event,
                },
            )
            return

        self._send_json(404, {"error": f"Unknown endpoint: {self.path}"})

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def log_message(self, format: str, *args: Any) -> None:
        # Keep logs concise and machine-readable for demos/tests.
        print(f"[SimDefenseAPI] {self.address_string()} - {format % args}")


def run_server(host: str, port: int, role: str) -> None:
    _STATE["role"] = role.lower()
    server = HTTPServer((host, port), DefenseAPIHandler)
    print("=" * 70)
    print(" Simulated Defense API Server")
    print("=" * 70)
    print(f" Host : {host}")
    print(f" Port : {port}")
    print(f" Role : {role}")
    print(" Endpoints:")
    print("   GET  /health")
    print("   GET  /api/v1/state")
    if role.lower() in ("both", "firewall"):
        print("   POST /api/v1/firewall/block-ip")
    if role.lower() in ("both", "edr"):
        print("   POST /api/v1/edr/isolate-host")
    token = os.getenv("SIMULATED_DEFENSE_API_TOKEN", "").strip()
    print(f" Auth : {'Bearer token required' if token else 'disabled'}")
    print("=" * 70)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SimDefenseAPI] Stopping server...")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulated firewall/EDR API server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5001, help="Bind port (default: 5001)")
    parser.add_argument(
        "--role",
        choices=("both", "firewall", "edr"),
        default="both",
        help="Enable firewall-only, edr-only, or both endpoints.",
    )
    args = parser.parse_args()
    run_server(args.host, args.port, args.role)


if __name__ == "__main__":
    main()
