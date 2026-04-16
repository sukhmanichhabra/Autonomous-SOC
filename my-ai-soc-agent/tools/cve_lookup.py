"""
CVE Lookup Tool
===============
Fetches live CVE data from public vulnerability databases.

Primary source : CIRCL CVE API  (https://cve.circl.lu/api/cve/<ID>)
Fallback source: NVD 2.0 API   (https://services.nvd.nist.gov/rest/json/cves/2.0)

The main entry point is :func:`fetch_live_cve_data` which accepts a
CVE ID (e.g. ``"CVE-2021-44228"``) and returns a compact dict with
the CVSS score, severity, and a brief description.

A helper :func:`extract_cve_ids_from_text` uses a regex to pull all
``CVE-YYYY-NNNNN`` identifiers out of free-form text (e.g. Nmap scan
output) so the Threat Analysis Agent can call the lookup automatically.

A higher-level helper :func:`bulk_fetch_cve_data` accepts a list of
CVE IDs, fetches them all (with de-duplication), and returns a
formatted string ready for injection into an LLM prompt.
"""

from __future__ import annotations

import re
from typing import Optional

import requests


# ---------------------------------------------------------------------------
# Timeouts & headers
# ---------------------------------------------------------------------------
_TIMEOUT = 10  # seconds per HTTP request
_HEADERS = {
    "User-Agent": "AI-SOC-Agent/1.0 (Cybersecurity Defense Agent)",
    "Accept": "application/json",
}


# ---------------------------------------------------------------------------
# Primary: CIRCL CVE API
# ---------------------------------------------------------------------------
def _fetch_from_circl(cve_id: str) -> Optional[dict]:
    """
    Query the CIRCL CVE API and return a normalised result dict, or
    ``None`` on failure.

    Supports both the **legacy** flat CIRCL response and the current
    **CVE 5.0 JSON** format (``containers.cna`` / ``containers.adp``).
    """
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT)
        if resp.status_code != 200:
            return None

        data = resp.json()
        if not data:
            return None

        cvss_score: float | None = None
        severity: str = "UNKNOWN"
        description: str = ""

        # ----- Detect CVE 5.0 format (current CIRCL API) -----
        if "containers" in data and "cveMetadata" in data:
            containers = data.get("containers", {})

            # CVSS — search adp then cna metrics
            all_metrics = []
            for adp_entry in containers.get("adp", []):
                all_metrics.extend(adp_entry.get("metrics", []))
            cna = containers.get("cna", {})
            all_metrics.extend(cna.get("metrics", []))

            for cvss_key in ("cvssV3_1", "cvssV3_0", "cvssV31", "cvssV30", "cvssV2"):
                if cvss_score is not None:
                    break
                for metric in all_metrics:
                    cvss_obj = metric.get(cvss_key)
                    if cvss_obj and isinstance(cvss_obj, dict):
                        score = cvss_obj.get("baseScore")
                        sev = cvss_obj.get("baseSeverity", "").upper()
                        if score is not None:
                            try:
                                cvss_score = float(score)
                                severity = sev or _severity_from_cvss(cvss_score)
                            except (TypeError, ValueError):
                                continue
                            break

            # Description — from cna.descriptions
            for desc in cna.get("descriptions", []):
                if desc.get("lang", "").startswith("en"):
                    description = (desc.get("value") or "").strip()
                    break
            if not description:
                descs = cna.get("descriptions", [])
                if descs:
                    description = (descs[0].get("value") or "").strip()

        else:
            # ----- Legacy flat CIRCL format -----
            if data.get("cvss3"):
                cvss_score = float(data["cvss3"])
            elif data.get("cvss"):
                cvss_score = float(data["cvss"])

            if data.get("access", {}).get("severity"):
                severity = data["access"]["severity"].upper()
            elif cvss_score is not None:
                severity = _severity_from_cvss(cvss_score)

            description = data.get("summary", "") or ""

        # If CIRCL returned no CVSS score, fall through to NVD which
        # almost always has scores.  We still accept CIRCL if it has
        # a score, even without a description.
        if cvss_score is None:
            return None

        if not description:
            description = "No description available."

        return {
            "cve_id": cve_id.upper(),
            "cvss_score": cvss_score,
            "severity": severity,
            "description": description[:500],  # keep it concise
            "source": "CIRCL",
        }

    except (requests.RequestException, ValueError, KeyError):
        return None


# ---------------------------------------------------------------------------
# Fallback: NVD 2.0 API
# ---------------------------------------------------------------------------
def _fetch_from_nvd(cve_id: str) -> Optional[dict]:
    """
    Query the NVD 2.0 REST API and return a normalised result dict, or
    ``None`` on failure.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    try:
        resp = requests.get(
            url, params=params, headers=_HEADERS, timeout=_TIMEOUT
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_data = vulns[0].get("cve", {})

        # --- Description (prefer English) ---
        descriptions = cve_data.get("descriptions", [])
        description = "No description available."
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break

        # --- CVSS score & severity ---
        cvss_score: float | None = None
        severity: str = "UNKNOWN"

        # Try v3.1 metrics first
        metrics = cve_data.get("metrics", {})
        v31 = metrics.get("cvssMetricV31", [])
        v30 = metrics.get("cvssMetricV30", [])
        v2 = metrics.get("cvssMetricV2", [])

        if v31:
            cvss_data = v31[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
        elif v30:
            cvss_data = v30[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
        elif v2:
            cvss_data = v2[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = _severity_from_cvss(cvss_score) if cvss_score else "UNKNOWN"

        return {
            "cve_id": cve_id.upper(),
            "cvss_score": cvss_score,
            "severity": severity,
            "description": description[:500],
            "source": "NVD",
        }

    except (requests.RequestException, ValueError, KeyError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Public API — single CVE lookup
# ---------------------------------------------------------------------------
def fetch_live_cve_data(cve_id: str) -> dict:
    """
    Fetch live vulnerability data for a given CVE ID.

    Queries the **CIRCL CVE API** first, falling back to the **NVD 2.0
    API** if CIRCL returns nothing.

    Args:
        cve_id: A CVE identifier, e.g. ``"CVE-2021-44228"``.

    Returns:
        A dict with keys:

        - ``cve_id``      — Normalised CVE ID (e.g. ``"CVE-2021-44228"``).
        - ``cvss_score``   — CVSS base score (float) or ``None``.
        - ``severity``     — ``"CRITICAL"`` / ``"HIGH"`` / ``"MEDIUM"`` /
                            ``"LOW"`` / ``"UNKNOWN"``.
        - ``description``  — Brief description (≤ 500 chars).
        - ``source``       — ``"CIRCL"``, ``"NVD"``, or ``"UNAVAILABLE"``.

        If both APIs fail the dict contains
        ``source="UNAVAILABLE"`` and ``severity="UNKNOWN"``.
    """
    cve_id = cve_id.strip().upper()

    # Validate format
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return {
            "cve_id": cve_id,
            "cvss_score": None,
            "severity": "UNKNOWN",
            "description": f"Invalid CVE ID format: {cve_id}",
            "source": "UNAVAILABLE",
        }

    # Try CIRCL first (faster, no rate-limit key needed)
    result = _fetch_from_circl(cve_id)
    if result:
        print(f"[CVE Lookup] {cve_id} — CVSS {result['cvss_score']} "
              f"({result['severity']}) via CIRCL")
        return result

    # Fallback to NVD
    result = _fetch_from_nvd(cve_id)
    if result:
        print(f"[CVE Lookup] {cve_id} — CVSS {result['cvss_score']} "
              f"({result['severity']}) via NVD")
        return result

    # Both failed
    print(f"[CVE Lookup] {cve_id} — data unavailable from both APIs")
    return {
        "cve_id": cve_id,
        "cvss_score": None,
        "severity": "UNKNOWN",
        "description": "CVE data could not be retrieved from CIRCL or NVD.",
        "source": "UNAVAILABLE",
    }


# ---------------------------------------------------------------------------
# Regex helper — extract CVE IDs from arbitrary text
# ---------------------------------------------------------------------------
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cve_ids_from_text(text: str) -> list[str]:
    """
    Extract all unique CVE IDs from free-form text.

    Args:
        text: Any string (Nmap output, LLM response, incident report, …).

    Returns:
        Sorted list of unique, upper-cased CVE IDs found in *text*.
    """
    matches = _CVE_PATTERN.findall(text)
    return sorted(set(cve.upper() for cve in matches))


# ---------------------------------------------------------------------------
# Bulk lookup — fetch multiple CVEs and format for LLM consumption
# ---------------------------------------------------------------------------
def bulk_fetch_cve_data(cve_ids: list[str]) -> str:
    """
    Fetch live data for a list of CVE IDs and return a formatted string
    suitable for injection into an LLM prompt.

    De-duplicates IDs, caps at 15 lookups to avoid rate-limit issues,
    and returns a clean Markdown-style summary.

    Args:
        cve_ids: List of CVE ID strings.

    Returns:
        A multi-line string summarising each CVE's score, severity,
        and description.  Returns an empty string if the list is empty.
    """
    if not cve_ids:
        return ""

    unique_ids = sorted(set(cve.strip().upper() for cve in cve_ids))
    # Cap to avoid hammering public APIs
    if len(unique_ids) > 15:
        print(f"[CVE Lookup] Capping bulk lookup to 15 CVEs "
              f"(requested {len(unique_ids)})")
        unique_ids = unique_ids[:15]

    results: list[dict] = []
    for cve_id in unique_ids:
        result = fetch_live_cve_data(cve_id)
        results.append(result)

    if not results:
        return ""

    lines = [
        "## Live CVE Intelligence (fetched from NVD / CIRCL)",
        "",
    ]
    for r in results:
        score_str = str(r["cvss_score"]) if r["cvss_score"] is not None else "N/A"
        lines.append(
            f"- **{r['cve_id']}** — CVSS: {score_str} | "
            f"Severity: {r['severity']} | Source: {r['source']}"
        )
        lines.append(f"  {r['description']}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helper — derive severity label from a CVSS score
# ---------------------------------------------------------------------------
def _severity_from_cvss(score: float) -> str:
    """Map a CVSS base score to a severity label (CVSS v3 thresholds)."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"


# ---------------------------------------------------------------------------
# Web header scanning — lightweight tech fingerprinting via HTTP headers
# ---------------------------------------------------------------------------

# Headers that reveal server software, frameworks, or security posture
_TECH_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "X-Cache",
    "Via",
]

_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

_WEB_SCAN_TIMEOUT = 3  # seconds per request


def scan_web_headers(target_ip: str) -> dict:
    """
    Probe ``http://{target_ip}`` and ``https://{target_ip}`` and extract
    security-relevant HTTP response headers.

    Performs a simple ``GET`` request to each scheme with a 3-second
    timeout.  Extracts the ``Server``, ``X-Powered-By``, and other
    technology-revealing headers, plus notes which standard security
    headers are present or missing.

    Args:
        target_ip: An IP address or hostname to probe (e.g.
            ``"192.168.1.1"`` or ``"example.com"``).

    Returns:
        A dict with discovered web technologies.  Structure::

            {
                "server": "Apache/2.4.41 (Ubuntu)",
                "x_powered_by": "PHP/7.4.3",
                "technologies": {"Server": "Apache/2.4.41 ...", ...},
                "security_headers_present": ["X-Content-Type-Options", ...],
                "security_headers_missing": ["Strict-Transport-Security", ...],
                "endpoints_reached": ["http://192.168.1.1"],
            }

        Returns an **empty dict** ``{}`` if neither HTTP nor HTTPS
        responded (e.g. no web server running on the target).
    """
    target_ip = target_ip.strip().strip("/")

    # Build candidate URLs
    urls = [f"http://{target_ip}", f"https://{target_ip}"]

    combined_headers: dict[str, str] = {}
    endpoints_reached: list[str] = []

    for url in urls:
        try:
            resp = requests.get(
                url,
                timeout=_WEB_SCAN_TIMEOUT,
                allow_redirects=True,
                verify=False,          # don't fail on self-signed certs
                headers={"User-Agent": "AI-SOC-Agent/1.0 (web-header-scan)"},
            )
            endpoints_reached.append(url)

            # Merge headers (later responses overwrite earlier ones for
            # the same key, which is fine — HTTPS is more authoritative)
            for key, value in resp.headers.items():
                combined_headers[key] = value

        except requests.exceptions.RequestException:
            # Connection refused, timeout, DNS failure, TLS error, etc.
            # — perfectly normal, just means this scheme isn't available.
            continue

    # If neither endpoint responded there is nothing to report
    if not combined_headers:
        return {}

    # --- Extract technology-revealing headers ---
    technologies: dict[str, str] = {}
    for hdr in _TECH_HEADERS:
        value = combined_headers.get(hdr)
        if value:
            technologies[hdr] = value

    # --- Audit security headers ---
    security_present: list[str] = []
    security_missing: list[str] = []
    for hdr in _SECURITY_HEADERS:
        if combined_headers.get(hdr):
            security_present.append(hdr)
        else:
            security_missing.append(hdr)

    # --- Build the result dict ---
    result: dict = {
        "server": technologies.get("Server", ""),
        "x_powered_by": technologies.get("X-Powered-By", ""),
        "technologies": technologies,
        "security_headers_present": security_present,
        "security_headers_missing": security_missing,
        "endpoints_reached": endpoints_reached,
    }

    return result
