#!/usr/bin/env python3
"""
End-to-End API Integration Demo Test
====================================
Calls the Response Agent API automation actions against local simulated
firewall/EDR API servers.

Start servers first:
1) cd my-ai-soc-agent
2) python3 simulated_defense_api.py --port 5001 --role firewall
3) python3 simulated_defense_api.py --port 5002 --role edr

Then run this file from repo root:
python3 test_api_integration.py
"""

from __future__ import annotations

import os
import sys

PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "my-ai-soc-agent")
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from tools.response_automation import execute_api_response_actions


def main() -> int:
    target_ip = os.getenv("DEMO_TARGET_IP", "10.10.10.50")

    # Defaults match the simulator startup shown in this file header.
    os.environ.setdefault("FIREWALL_API_URL", "http://127.0.0.1:5001")
    os.environ.setdefault("EDR_API_URL", "http://127.0.0.1:5002")

    print("=" * 70)
    print(" API Integration Demo")
    print("=" * 70)
    print(f"Target IP: {target_ip}")
    print(f"Firewall API: {os.environ['FIREWALL_API_URL']}")
    print(f"EDR API     : {os.environ['EDR_API_URL']}")
    print("=" * 70)

    results = execute_api_response_actions(target_ip=target_ip, dry_run=False)

    ok = True
    for idx, result in enumerate(results, 1):
        status = result.get("status")
        cmd = result.get("command")
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")

        print(f"\n[{idx:02d}] {cmd}")
        print(f"     status: {status}")
        if stdout:
            print(f"     stdout: {stdout[:220]}")
        if stderr:
            print(f"     stderr: {stderr[:220]}")

        if status != "SUCCESS":
            ok = False

    print("\n" + "=" * 70)
    if ok:
        print("PASS: API automation actions succeeded.")
        return 0

    print("FAIL: One or more API actions failed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
