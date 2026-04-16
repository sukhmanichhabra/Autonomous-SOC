#!/usr/bin/env python3
"""
test_nmap.py — Nmap Installation Test
======================================
Verifies that the python-nmap library AND the system nmap binary
are correctly installed by scanning scanme.nmap.org (a safe,
publicly available test server maintained by the Nmap project)
on ports 22 (SSH) and 80 (HTTP).

Usage:
    python test_nmap.py
"""

import sys
import shutil

# Force unbuffered output (flush after every print)
_print = print
def print(*args, **kwargs):
    kwargs.setdefault("flush", True)
    _print(*args, **kwargs)

# ── Step 1: Check that the python-nmap library is importable ──────────────
print("=" * 55)
print("  Nmap Installation Test")
print("=" * 55)

try:
    import nmap
    print(f"\n✅  python-nmap library imported successfully")
except ImportError:
    print("\n❌  python-nmap library is NOT installed.")
    print("    Fix:  pip install python-nmap")
    sys.exit(1)

# ── Step 2: Check that the nmap binary is on the system PATH ──────────────
nmap_path = shutil.which("nmap")
if nmap_path:
    print(f"✅  nmap binary found at: {nmap_path}")
else:
    print("\n❌  nmap binary is NOT found in your system PATH.")
    print("    The python-nmap library is just a wrapper — it requires")
    print("    the actual nmap program to be installed separately.\n")
    print("    Install it with:")
    print("      macOS  :  brew install nmap")
    print("      Ubuntu :  sudo apt-get install nmap")
    print("      CentOS :  sudo yum install nmap")
    print("      Windows:  Download from https://nmap.org/download.html")
    sys.exit(1)

# ── Step 3: Initialize the scanner ────────────────────────────────────────
try:
    scanner = nmap.PortScanner()
    print(f"✅  nmap.PortScanner() initialised (nmap version: {scanner.nmap_version()})")
except nmap.PortScannerError as exc:
    print(f"\n❌  Failed to initialise PortScanner: {exc}")
    print("    Make sure the nmap binary is accessible and not corrupted.")
    sys.exit(1)

# ── Step 4: Scan scanme.nmap.org on ports 22 and 80 ──────────────────────
TARGET = "scanme.nmap.org"
PORTS = "22,80"

print(f"\n📡  Scanning {TARGET} on ports {PORTS} …\n")

try:
    scanner.scan(hosts=TARGET, ports=PORTS, arguments="-sV --open")
except Exception as exc:
    print(f"❌  Scan failed: {exc}")
    print("    Possible causes:")
    print("      • No internet connection")
    print("      • DNS cannot resolve scanme.nmap.org")
    print("      • A firewall is blocking outbound traffic")
    sys.exit(1)

# ── Step 5: Print results ─────────────────────────────────────────────────
if not scanner.all_hosts():
    print("⚠️   No hosts found — the target may be down or unreachable.")
    sys.exit(0)

for host in scanner.all_hosts():
    hostname = scanner[host].hostname() or "N/A"
    state = scanner[host].state()

    print(f"{'─' * 55}")
    print(f"  Host     : {host} ({hostname})")
    print(f"  State    : {state}")
    print(f"{'─' * 55}")

    if state != "up":
        print("  ⚠️  Host is not up — port results may be unavailable.\n")
        continue

    for proto in scanner[host].all_protocols():
        ports = sorted(scanner[host][proto].keys())
        for port in ports:
            info = scanner[host][proto][port]
            port_state = info.get("state", "unknown")
            service = info.get("name", "unknown")
            version = info.get("version", "")
            product = info.get("product", "")

            detail = f"{product} {version}".strip() or service
            icon = "🟢" if port_state == "open" else ("🟡" if port_state == "filtered" else "🔴")

            print(f"  {icon}  Port {port}/{proto:4s}  {port_state:10s}  {detail}")

print(f"\n{'=' * 55}")
print("  ✅  Nmap test complete!")
print(f"{'=' * 55}")
