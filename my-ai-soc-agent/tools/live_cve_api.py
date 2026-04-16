"""
Live CVE API Tool
=================
Queries the public CIRCL CVE API to retrieve detailed vulnerability
information for a given CVE identifier.

API endpoint: ``https://cve.circl.lu/api/cve/{cve_id}``

The main entry point is :func:`fetch_cve_details` which returns a
dictionary containing the **CVSS score**, **summary description**, and
**vulnerable configurations** (CPE strings / affected-product entries)
for the requested CVE.

Supports both the **legacy** flat CIRCL response format *and* the
current **CVE 5.0 JSON** format (``containers.cna`` / ``containers.adp``).

Usage example::

    >>> from tools.live_cve_api import fetch_cve_details
    >>> result = fetch_cve_details("CVE-2021-44228")
    >>> print(result["cvss_score"])
    10.0
    >>> print(result["vulnerable_configuration"][:2])
    ['Apache Software Foundation / Apache Log4j2 2.0-beta9', ...]

See Also:
    - ``tools/cve_lookup.py`` — higher-level lookup with CIRCL + NVD
      fallback, bulk fetch, and LLM prompt formatting used by the
      Threat Analysis Agent pipeline.
"""

from __future__ import annotations

import re
from typing import Any

import requests


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_CIRCL_BASE_URL = "https://cve.circl.lu/api/cve"
_TIMEOUT = 15  # seconds — generous to avoid flaky failures
_HEADERS = {
    "User-Agent": "AI-SOC-Agent/1.0 (live_cve_api)",
    "Accept": "application/json",
}
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _severity_from_cvss(score):
    """Derive a human-readable severity label from a CVSS base score."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"


def _extract_cvss_from_new_format(data):
    """
    Extract CVSS score and severity from the CVE 5.0 JSON format.

    Searches ``containers.adp[].metrics[]`` and ``containers.cna.metrics[]``
    for ``cvssV3_1``, ``cvssV3_0``, or ``cvssV2`` objects.  Returns
    ``(score, severity)`` or ``(None, None)`` if nothing is found.
    """
    containers = data.get("containers", {})

    # Collect every metrics list: adp entries first (more authoritative),
    # then cna.
    all_metrics = []
    for adp_entry in containers.get("adp", []):
        all_metrics.extend(adp_entry.get("metrics", []))
    cna = containers.get("cna", {})
    all_metrics.extend(cna.get("metrics", []))

    # Walk metrics looking for CVSS v3.1 → v3.0 → v2 (in priority order)
    for cvss_key in ("cvssV3_1", "cvssV3_0", "cvssV31", "cvssV30", "cvssV2"):
        for metric in all_metrics:
            cvss_obj = metric.get(cvss_key)
            if cvss_obj and isinstance(cvss_obj, dict):
                score = cvss_obj.get("baseScore")
                severity = cvss_obj.get("baseSeverity", "").upper() or None
                if score is not None:
                    try:
                        return float(score), severity or _severity_from_cvss(float(score))
                    except (TypeError, ValueError):
                        continue

    # Fallback: check "other" metrics for a textual severity (e.g. "critical")
    for metric in all_metrics:
        other = metric.get("other", {})
        content = other.get("content", {})
        if isinstance(content, dict) and content.get("other"):
            sev_text = str(content["other"]).strip().upper()
            if sev_text in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return None, sev_text

    return None, None


def _extract_description_from_new_format(data):
    """
    Extract the English description from the CVE 5.0 ``containers.cna.descriptions``.
    Returns the description string or an empty string.
    """
    containers = data.get("containers", {})
    cna = containers.get("cna", {})
    for desc in cna.get("descriptions", []):
        if desc.get("lang", "").startswith("en"):
            return (desc.get("value") or "").strip()
    # If no English description, take the first available
    descs = cna.get("descriptions", [])
    if descs:
        return (descs[0].get("value") or "").strip()
    return ""


def _extract_vulnerable_configs_from_new_format(data):
    """
    Build human-readable vulnerable-configuration strings from the
    CVE 5.0 ``containers.cna.affected`` list.

    Each entry typically has ``vendor``, ``product``, and ``versions``.
    We also check ``containers.adp[].affected`` as a fallback.
    """
    containers = data.get("containers", {})
    configs = []

    # Gather affected lists from cna and all adp entries
    affected_lists = []
    cna = containers.get("cna", {})
    if cna.get("affected"):
        affected_lists.append(cna["affected"])
    for adp_entry in containers.get("adp", []):
        if adp_entry.get("affected"):
            affected_lists.append(adp_entry["affected"])

    seen = set()
    for affected in affected_lists:
        for entry in affected:
            vendor = entry.get("vendor", "Unknown Vendor")
            product = entry.get("product", "Unknown Product")
            versions = entry.get("versions", [])
            if versions:
                for ver in versions:
                    ver_str = ver.get("version", "")
                    status = ver.get("status", "")
                    less_than = ver.get("lessThan", "")
                    label = f"{vendor} / {product} {ver_str}"
                    if less_than:
                        label += f" (< {less_than})"
                    if status:
                        label += f" [{status}]"
                    if label not in seen:
                        seen.add(label)
                        configs.append(label)
            else:
                label = f"{vendor} / {product}"
                if label not in seen:
                    seen.add(label)
                    configs.append(label)

    return configs


def _extract_vulnerable_configurations_legacy(data):
    """
    Pull CPE URIs out of the legacy CIRCL ``vulnerable_configuration``
    field.  CIRCL used to store them as plain strings or dicts with an
    ``id`` key.
    """
    raw = data.get("vulnerable_configuration") or []
    configs = []
    for item in raw:
        if isinstance(item, str):
            configs.append(item)
        elif isinstance(item, dict):
            cpe = item.get("id") or item.get("cpe23Uri") or item.get("title", "")
            if cpe:
                configs.append(str(cpe))
    return configs


def _format_as_string(result):
    """
    Pretty-print a result dict as a human-readable multi-line string
    suitable for terminal output or agent logging.
    """
    lines = [
        f"CVE ID        : {result['cve_id']}",
        f"CVSS Score    : {result['cvss_score'] if result['cvss_score'] is not None else 'N/A'}",
        f"Severity      : {result['severity']}",
        f"Description   : {result['description']}",
    ]

    configs = result.get("vulnerable_configuration") or []
    if configs:
        lines.append(f"Vulnerable Configurations ({len(configs)}):")
        for cfg in configs[:25]:  # cap display to keep output manageable
            lines.append(f"  - {cfg}")
        if len(configs) > 25:
            lines.append(f"  ... and {len(configs) - 25} more")
    else:
        lines.append("Vulnerable Configurations: none listed")

    return "\n".join(lines)


def _build_error_result(cve_id, error_message):
    """Return a result dict representing a failed lookup."""
    result = {
        "cve_id": cve_id,
        "cvss_score": None,
        "severity": "UNKNOWN",
        "description": "Lookup failed — see 'error' field.",
        "vulnerable_configuration": [],
        "source": "UNAVAILABLE",
        "error": error_message,
        "formatted": "",
    }
    result["formatted"] = _format_as_string(result)
    return result


def _is_new_cve5_format(data):
    """Return True if the CIRCL response uses the CVE 5.0 JSON schema."""
    return "containers" in data and "cveMetadata" in data


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def fetch_cve_details(cve_id: str) -> dict[str, Any]:
    """
    Fetch detailed vulnerability information for a single CVE ID from
    the CIRCL CVE API (``https://cve.circl.lu/api/cve/{cve_id}``).

    Extracts:
        * **cvss_score** — CVSS v3 base score (preferred) or v2 score.
        * **description** — Summary text describing the vulnerability.
        * **vulnerable_configuration** — List of CPE strings identifying
          affected software / hardware configurations.

    Args:
        cve_id: A CVE identifier such as ``"CVE-2021-44228"``.  The
            value is case-insensitive and leading/trailing whitespace
            is stripped automatically.

    Returns:
        A dict with the following keys:

        =========================================  ================================
        Key                                        Type / Description
        =========================================  ================================
        ``cve_id``                                 ``str`` — Normalised CVE ID.
        ``cvss_score``                             ``float | None`` — CVSS base
                                                   score, or ``None`` if
                                                   unavailable.
        ``severity``                               ``str`` — One of CRITICAL,
                                                   HIGH, MEDIUM, LOW, UNKNOWN.
        ``description``                            ``str`` — Summary text
                                                   (≤ 600 chars).
        ``vulnerable_configuration``               ``list[str]`` — CPE URIs of
                                                   affected products.
        ``source``                                 ``str`` — Always ``"CIRCL"``
                                                   on success, ``"UNAVAILABLE"``
                                                   on failure.
        ``error``                                  ``str | None`` — Error message
                                                   when the lookup fails,
                                                   ``None`` on success.
        ``formatted``                              ``str`` — Pre-built
                                                   human-readable string.
        =========================================  ================================

    Raises:
        Nothing — all exceptions are caught and reported via the
        ``error`` key in the returned dict.

    Examples:
        >>> details = fetch_cve_details("CVE-2021-44228")
        >>> details["cvss_score"]
        10.0
        >>> details["severity"]
        'CRITICAL'
        >>> len(details["vulnerable_configuration"]) > 0
        True

        >>> bad = fetch_cve_details("not-a-cve")
        >>> bad["error"]
        'Invalid CVE ID format: NOT-A-CVE'
    """
    cve_id = cve_id.strip().upper()

    # ------------------------------------------------------------------
    # Guard: validate CVE ID format before making a network call
    # ------------------------------------------------------------------
    if not _CVE_ID_RE.match(cve_id):
        err = _build_error_result(cve_id, f"Invalid CVE ID format: {cve_id}")
        print(f"[Live CVE API] ✗ {err['error']}")
        return err

    # ------------------------------------------------------------------
    # Query the CIRCL CVE API
    # ------------------------------------------------------------------
    url = f"{_CIRCL_BASE_URL}/{cve_id}"

    try:
        response = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT)

        # --- HTTP-level errors ---
        if response.status_code == 404:
            err = _build_error_result(
                cve_id,
                f"CVE not found in CIRCL database: {cve_id}",
            )
            print(f"[Live CVE API] ✗ {cve_id} — not found (HTTP 404)")
            return err

        if response.status_code != 200:
            err = _build_error_result(
                cve_id,
                f"CIRCL API returned HTTP {response.status_code} for {cve_id}",
            )
            print(f"[Live CVE API] ✗ {cve_id} — HTTP {response.status_code}")
            return err

        data = response.json()
        if not data:
            err = _build_error_result(
                cve_id,
                f"CIRCL returned empty payload for {cve_id}",
            )
            print(f"[Live CVE API] ✗ {cve_id} — empty response body")
            return err

        # ---- Detect format and extract fields ----
        if _is_new_cve5_format(data):
            # ── CVE 5.0 JSON format (current CIRCL API) ──────────
            cvss_score, severity = _extract_cvss_from_new_format(data)
            if severity is None:
                severity = _severity_from_cvss(cvss_score)

            description = _extract_description_from_new_format(data)
            if not description:
                description = "No description available."
            description = description[:600]

            vuln_configs = _extract_vulnerable_configs_from_new_format(data)

        else:
            # ── Legacy flat CIRCL format ──────────────────────────
            cvss_score = None
            if data.get("cvss3"):
                try:
                    cvss_score = float(data["cvss3"])
                except (TypeError, ValueError):
                    pass
            if cvss_score is None and data.get("cvss"):
                try:
                    cvss_score = float(data["cvss"])
                except (TypeError, ValueError):
                    pass

            severity = _severity_from_cvss(cvss_score)

            description = (data.get("summary") or "").strip()
            if not description:
                description = "No description available."
            description = description[:600]

            vuln_configs = _extract_vulnerable_configurations_legacy(data)

        result: dict[str, Any] = {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "description": description,
            "vulnerable_configuration": vuln_configs,
            "source": "CIRCL",
            "error": None,
            "formatted": "",  # filled below
        }
        result["formatted"] = _format_as_string(result)

        print(
            f"[Live CVE API] ✓ {cve_id} — CVSS {cvss_score} "
            f"({severity}), {len(vuln_configs)} vulnerable config(s)"
        )
        return result

    # ------------------------------------------------------------------
    # Exception handling — network and parsing errors
    # ------------------------------------------------------------------
    except requests.exceptions.Timeout:
        msg = f"Request timed out after {_TIMEOUT}s for {cve_id}"
        print(f"[Live CVE API] ✗ {cve_id} — timeout")
        return _build_error_result(cve_id, msg)

    except requests.exceptions.ConnectionError as exc:
        msg = f"Connection error querying CIRCL for {cve_id}: {exc}"
        print(f"[Live CVE API] ✗ {cve_id} — connection error")
        return _build_error_result(cve_id, msg)

    except requests.exceptions.RequestException as exc:
        msg = f"HTTP error querying CIRCL for {cve_id}: {exc}"
        print(f"[Live CVE API] ✗ {cve_id} — request error")
        return _build_error_result(cve_id, msg)

    except (ValueError, KeyError, TypeError) as exc:
        msg = f"Failed to parse CIRCL response for {cve_id}: {exc}"
        print(f"[Live CVE API] ✗ {cve_id} — parse error")
        return _build_error_result(cve_id, msg)


# ---------------------------------------------------------------------------
# CLI quick-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    test_ids = sys.argv[1:] or ["CVE-2021-44228", "CVE-2017-0144", "INVALID-ID"]
    for cve in test_ids:
        print(f"\n{'='*60}")
        details = fetch_cve_details(cve)
        print(details["formatted"])
        if details["error"]:
            print(f"  ⚠  Error: {details['error']}")
        print(f"{'='*60}")
