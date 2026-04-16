"""
Recon Toolkit
=============
Comprehensive reconnaissance toolkit for the Cybersecurity Defense Agent.

Combines **network scanning** (Nmap) with **web technology fingerprinting**
(HTTP header / HTML analysis) so the Recon Agent can build a complete
picture of the target in a single pipeline step.

Functions:
    Network scanning (Nmap):
        - ``nmap_scan``         — full configurable scan
        - ``quick_scan``        — top-100 ports, fast
        - ``vulnerability_scan``— Nmap vuln scripts
        - ``format_scan_results`` — dict → human-readable string
        - ``run_quick_scan``    — service-detection scan → formatted string

    Web technology fingerprinting:
        - ``scan_web_tech``     — probe port 80/443 HTTP headers + HTML
          meta-tags to identify server software, frameworks, languages,
          CMS platforms, JavaScript libraries, and security headers.
"""

from __future__ import annotations

import json
import os
import re
import ssl
from typing import Optional
from urllib.parse import urlparse

import nmap
import requests

from config import settings


def _build_scanner() -> nmap.PortScanner:
    """Create PortScanner using configured Nmap binary path."""
    nmap_path = os.getenv("NMAP_PATH", settings.nmap_path).strip()
    if nmap_path:
        return nmap.PortScanner(nmap_search_path=(nmap_path,))
    return nmap.PortScanner()


def nmap_scan(target: str, arguments: str = "-sV -sC", stealth: bool = False) -> dict:
    """
    Perform a comprehensive Nmap scan on a target.

    Args:
        target: IP address or hostname to scan (e.g., '192.168.1.1' or '192.168.1.0/24').
        arguments: Nmap arguments (default: '-sV -sC' for version detection + default scripts).
        stealth: If True, override *arguments* with ``-sS -T2 -f`` (SYN Stealth scan,
                 polite timing, fragmented packets) to evade simple firewalls and IDS.

    Returns:
        Dictionary containing scan results with hosts, ports, services, and scripts output.
    """
    if stealth:
        arguments = "-sS -T2 -f"
        print(f"[Nmap] 🥷 Stealth mode enabled — using args: {arguments}")

    scanner = _build_scanner()
    try:
        print(f"[Nmap] Scanning {target} with args: {arguments}")
        scanner.scan(hosts=target, arguments=arguments)

        results = {
            "command_line": scanner.command_line(),
            "scan_info": scanner.scaninfo(),
            "hosts": [],
        }

        for host in scanner.all_hosts():
            host_data = {
                "host": host,
                "hostname": scanner[host].hostname(),
                "state": scanner[host].state(),
                "protocols": {},
            }

            for proto in scanner[host].all_protocols():
                ports_info = []
                for port in sorted(scanner[host][proto].keys()):
                    port_data = scanner[host][proto][port]
                    ports_info.append(
                        {
                            "port": port,
                            "state": port_data.get("state", "unknown"),
                            "service": port_data.get("name", "unknown"),
                            "version": port_data.get("version", ""),
                            "product": port_data.get("product", ""),
                            "extra_info": port_data.get("extrainfo", ""),
                            "scripts": port_data.get("script", {}),
                        }
                    )
                host_data["protocols"][proto] = ports_info

            results["hosts"].append(host_data)

        return results

    except nmap.PortScannerError as e:
        return {"error": f"Nmap scan failed: {str(e)}", "target": target}
    except Exception as e:
        return {"error": f"Unexpected error during scan: {str(e)}", "target": target}


def quick_scan(target: str) -> dict:
    """
    Perform a fast scan to discover open ports (top 100 ports).

    Args:
        target: IP address or hostname to scan.

    Returns:
        Dictionary with quick scan results.
    """
    return nmap_scan(target, arguments="-F -T4")


def vulnerability_scan(target: str) -> dict:
    """
    Perform a vulnerability scan using Nmap's vuln scripts.

    Args:
        target: IP address or hostname to scan.

    Returns:
        Dictionary with vulnerability scan results.
    """
    return nmap_scan(target, arguments="-sV --script=vuln")


def format_scan_results(results: dict) -> str:
    """
    Format scan results into a human-readable string for LLM consumption.

    Args:
        results: Raw scan results dictionary.

    Returns:
        Formatted string summary.
    """
    if "error" in results:
        return f"Scan Error: {results['error']}"

    lines = [f"Nmap Scan Results ({results.get('command_line', 'N/A')})", "=" * 60]

    for host in results.get("hosts", []):
        lines.append(f"\nHost: {host['host']} ({host['hostname']})")
        lines.append(f"State: {host['state']}")

        for proto, ports in host.get("protocols", {}).items():
            lines.append(f"\nProtocol: {proto.upper()}")
            lines.append(f"{'Port':<8} {'State':<10} {'Service':<15} {'Version'}")
            lines.append("-" * 55)

            for p in ports:
                version_str = f"{p['product']} {p['version']}".strip()
                lines.append(
                    f"{p['port']:<8} {p['state']:<10} {p['service']:<15} {version_str}"
                )
                if p.get("scripts"):
                    for script_name, output in p["scripts"].items():
                        lines.append(f"  |_ {script_name}: {output[:200]}")

    return "\n".join(lines)


def run_quick_scan(ip: str, stealth: bool = False) -> str:
    """
    Perform a service-detection scan (-sV) on the given IP and return
    a clean, human-readable string listing open ports and detected services.

    When *stealth* is ``True`` the scan switches to ``-sS -T2 -f``
    (SYN Stealth, polite timing, fragmented packets) to reduce the
    chance of detection by firewalls and IDS/IPS systems.  The trade-off
    is that service-version information may be unavailable.

    Args:
        ip: Target IP address or hostname (e.g., '192.168.1.1').
        stealth: Use stealth scanning arguments instead of ``-sV``.

    Returns:
        A formatted string with open ports/services, or an error message
        if the scan fails.
    """
    scan_args = "-sS -T2 -f" if stealth else "-sV"

    try:
        scanner = _build_scanner()
        mode_label = "stealth SYN" if stealth else "service detection"
        print(f"[Nmap] Running {mode_label} scan on {ip} (args: {scan_args}) ...")
        scanner.scan(hosts=ip, arguments=scan_args)
    except nmap.PortScannerError as e:
        return f"[Error] Nmap scan failed for {ip}: {e}"
    except Exception as e:
        return f"[Error] Unexpected failure while scanning {ip}: {e}"

    # If no hosts were discovered the target is likely unreachable
    if not scanner.all_hosts():
        return f"[Info] No hosts found for {ip}. The target may be down or unreachable."

    lines: list[str] = []
    lines.append(f"Scan Results for {ip}")
    lines.append("-" * 50)

    for host in scanner.all_hosts():
        hostname = scanner[host].hostname()
        state = scanner[host].state()
        host_label = f"{host} ({hostname})" if hostname else host
        lines.append(f"Host: {host_label}  —  Status: {state}")
        lines.append("")

        found_open = False
        for proto in scanner[host].all_protocols():
            lines.append(f"  Protocol: {proto.upper()}")
            lines.append(f"  {'Port':<8} {'State':<10} {'Service':<16} {'Version'}")
            lines.append(f"  {'-'*46}")

            for port in sorted(scanner[host][proto].keys()):
                info = scanner[host][proto][port]
                if info.get("state") != "open":
                    continue
                found_open = True
                service = info.get("name", "unknown")
                product = info.get("product", "")
                version = info.get("version", "")
                extra = info.get("extrainfo", "")
                version_str = " ".join(filter(None, [product, version, extra]))
                lines.append(
                    f"  {port:<8} {'open':<10} {service:<16} {version_str}"
                )

            lines.append("")

        if not found_open:
            lines.append("  No open ports detected.")
            lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# Web Technology Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════

# HTTP headers that reveal server-side technology
_INTERESTING_HEADERS = {
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
    "X-Varnish",
    "X-Cache",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Permissions-Policy",
    "Referrer-Policy",
    "Via",
}

# Security headers whose *absence* is noteworthy
_SECURITY_HEADERS = {
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
}

# Regex patterns to detect technologies in HTML <meta> tags and body
_HTML_TECH_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("WordPress",       re.compile(r'wp-content|wp-includes|wordpress', re.I)),
    ("Drupal",          re.compile(r'Drupal\.settings|sites/default/files', re.I)),
    ("Joomla",          re.compile(r'/media/jui/|/templates/joomla', re.I)),
    ("Shopify",         re.compile(r'cdn\.shopify\.com', re.I)),
    ("Wix",             re.compile(r'static\.wixstatic\.com', re.I)),
    ("Squarespace",     re.compile(r'squarespace\.com|sqsp\.net', re.I)),
    ("React",           re.compile(r'react\.development\.js|react\.production|_next/static|__NEXT_DATA__', re.I)),
    ("Next.js",         re.compile(r'__NEXT_DATA__|/_next/', re.I)),
    ("Vue.js",          re.compile(r'vue\.js|vue\.min\.js|vue\.runtime', re.I)),
    ("Angular",         re.compile(r'ng-version=|angular\.js|angular\.min\.js', re.I)),
    ("jQuery",          re.compile(r'jquery[\.-][\d]', re.I)),
    ("Bootstrap",       re.compile(r'bootstrap\.min\.(css|js)|bootstrap\.css', re.I)),
    ("Tailwind CSS",    re.compile(r'tailwindcss|tailwind\.min\.css', re.I)),
    ("Laravel",         re.compile(r'laravel_session|csrf-token.*content', re.I)),
    ("Django",          re.compile(r'csrfmiddlewaretoken|__django', re.I)),
    ("Ruby on Rails",   re.compile(r'csrf-param.*authenticity_token|data-turbo', re.I)),
    ("ASP.NET",         re.compile(r'__VIEWSTATE|__EVENTVALIDATION|asp\.net', re.I)),
    ("PHP",             re.compile(r'\.php["\s?]|PHPSESSID', re.I)),
    ("Google Analytics", re.compile(r'google-analytics\.com|gtag/js', re.I)),
    ("Google Tag Mgr",  re.compile(r'googletagmanager\.com', re.I)),
    ("Cloudflare",      re.compile(r'cloudflare', re.I)),
]


def scan_web_tech(target_url: str) -> dict:
    """
    Identify web technologies running on a target by probing HTTP(S)
    endpoints and analysing response headers + HTML content.

    The function:
    1. Normalises the URL (adds ``http://`` if no scheme is provided).
    2. Probes both HTTP (port 80) and HTTPS (port 443) endpoints.
    3. Extracts interesting HTTP response headers (server software,
       framework hints, caching layers).
    4. Checks for the *presence or absence* of security headers.
    5. Scans the first 100 KB of HTML body for signatures of known
       CMS platforms, JS frameworks, CSS libraries, and server-side
       languages.
    6. Returns a structured dict ready for injection into ``AgentState``.

    Args:
        target_url: A domain, IP, or full URL to probe.
                    Examples: ``"example.com"``, ``"https://10.0.0.1"``,
                    ``"http://192.168.1.1:8080"``.

    Returns:
        A dict with keys:

        - ``target``            — the original target string.
        - ``endpoints``         — list of dicts, one per probed URL, each
          containing ``url``, ``status_code``, ``headers``, ``technologies``,
          ``security_headers``, and ``cookies``.
        - ``technologies_found``— de-duplicated sorted list of all tech names.
        - ``missing_security_headers`` — security headers missing across
          *all* probed endpoints.
        - ``raw_output``        — human-readable formatted string.
        - ``error``             — error message if both probes failed, else ``None``.
    """
    urls = _normalise_target_urls(target_url)

    result: dict = {
        "target": target_url,
        "endpoints": [],
        "technologies_found": [],
        "missing_security_headers": [],
        "raw_output": "",
        "error": None,
    }

    all_techs: set[str] = set()
    all_missing_sec: set[str] | None = None

    for url in urls:
        endpoint = _probe_endpoint(url)
        if endpoint:
            result["endpoints"].append(endpoint)
            all_techs.update(endpoint["technologies"])
            missing = set(endpoint["security_headers"]["missing"])
            if all_missing_sec is None:
                all_missing_sec = missing
            else:
                all_missing_sec &= missing  # intersection across endpoints

    result["technologies_found"] = sorted(all_techs)
    result["missing_security_headers"] = sorted(all_missing_sec or set())

    if not result["endpoints"]:
        result["error"] = (
            f"Could not reach {target_url} on port 80 or 443. "
            "The target may not be running a web server."
        )

    result["raw_output"] = _format_web_tech_results(result)
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
_TIMEOUT = 8  # seconds per HTTP probe
_MAX_BODY = 102_400  # first 100 KB of HTML
_HEADERS = {
    "User-Agent": "AI-SOC-Agent/1.0 (Recon Toolkit; Web Tech Scanner)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}


def _normalise_target_urls(target: str) -> list[str]:
    """
    Given a user-supplied target (IP, domain, or full URL) return a list
    of URLs to probe — typically ``["https://...", "http://..."]``.
    """
    target = target.strip()

    # Already a full URL?
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        return [target]

    # Bare host / IP — try HTTPS first, then HTTP
    host = target.rstrip("/")
    return [f"https://{host}", f"http://{host}"]


def _probe_endpoint(url: str) -> dict | None:
    """
    Send a GET request to *url* and return a structured endpoint dict,
    or ``None`` if the request fails entirely.
    """
    try:
        resp = requests.get(
            url,
            headers=_HEADERS,
            timeout=_TIMEOUT,
            allow_redirects=True,
            verify=False,  # allow self-signed certs on internal targets
        )
    except requests.RequestException:
        return None

    # ── Interesting headers ───────────────────────────────────────
    detected_headers: dict[str, str] = {}
    for hdr in _INTERESTING_HEADERS:
        val = resp.headers.get(hdr)
        if val:
            detected_headers[hdr] = val

    # ── Security headers ──────────────────────────────────────────
    present_sec = []
    missing_sec = []
    for hdr in sorted(_SECURITY_HEADERS):
        if resp.headers.get(hdr):
            present_sec.append(hdr)
        else:
            missing_sec.append(hdr)

    # ── Technology detection via HTML body ─────────────────────────
    body = resp.text[:_MAX_BODY] if resp.text else ""
    techs: list[str] = []
    for name, pattern in _HTML_TECH_PATTERNS:
        if pattern.search(body):
            techs.append(name)

    # Also infer from headers
    server = resp.headers.get("Server", "")
    powered = resp.headers.get("X-Powered-By", "")
    if server:
        techs.append(f"Server: {server}")
    if powered:
        techs.append(f"Powered-By: {powered}")

    # ── Cookies (session technology hints) ────────────────────────
    cookies: list[dict] = []
    for ck in resp.cookies:
        cookie_info: dict = {"name": ck.name, "secure": ck.secure}
        if ck.name.upper() in ("PHPSESSID",):
            techs.append("PHP")
        elif ck.name.upper() in ("JSESSIONID",):
            techs.append("Java/Servlet")
        elif ck.name.upper() in ("ASP.NET_SESSIONID",):
            techs.append("ASP.NET")
        elif ck.name.startswith("_rails"):
            techs.append("Ruby on Rails")
        cookies.append(cookie_info)

    # De-duplicate tech list
    techs = sorted(set(techs))

    return {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "headers": detected_headers,
        "security_headers": {
            "present": present_sec,
            "missing": missing_sec,
        },
        "technologies": techs,
        "cookies": cookies,
    }


def _format_web_tech_results(result: dict) -> str:
    """Format the web tech scan result dict into a human-readable string."""
    lines: list[str] = []
    lines.append(f"Web Technology Scan — {result['target']}")
    lines.append("=" * 55)

    if result.get("error"):
        lines.append(f"  [Error] {result['error']}")
        return "\n".join(lines)

    for ep in result["endpoints"]:
        lines.append(f"\n  Endpoint  : {ep['url']}")
        if ep["url"] != ep.get("final_url", ep["url"]):
            lines.append(f"  Redirected: {ep['final_url']}")
        lines.append(f"  Status    : {ep['status_code']}")

        if ep["headers"]:
            lines.append("  Response Headers:")
            for k, v in sorted(ep["headers"].items()):
                lines.append(f"    {k}: {v}")

        if ep["technologies"]:
            lines.append("  Technologies Detected:")
            for t in ep["technologies"]:
                lines.append(f"    • {t}")

        sec = ep["security_headers"]
        if sec["present"]:
            lines.append("  Security Headers (present ✅):")
            for h in sec["present"]:
                lines.append(f"    ✅ {h}")
        if sec["missing"]:
            lines.append("  Security Headers (missing ⚠️):")
            for h in sec["missing"]:
                lines.append(f"    ⚠️  {h}")

        if ep["cookies"]:
            lines.append("  Cookies:")
            for c in ep["cookies"]:
                secure_flag = "🔒" if c["secure"] else "⚠️ not Secure"
                lines.append(f"    {c['name']} ({secure_flag})")

    if result["technologies_found"]:
        lines.append(f"\n  All Technologies: {', '.join(result['technologies_found'])}")

    if result["missing_security_headers"]:
        lines.append(f"  Missing Sec Headers (all endpoints): "
                     f"{', '.join(result['missing_security_headers'])}")

    lines.append("")
    return "\n".join(lines)
