"""
Incident I/O — Persist pipeline results to the filesystem
==========================================================
Every time the LangGraph pipeline completes a scan, this module creates
a structured folder under ``incidents/<thread_id>/`` containing:

* **recon_data.json**      — Raw Nmap output, web-tech fingerprinting,
                             and scan metadata.
* **analysis_report.md**   — Formatted Markdown with the threat-analysis
                             report, MITRE mapping, risk assessment, and
                             plain-English summary.
* **mitigation_log.txt**   — The final approved commands and the full
                             response plan (or a note that no action was
                             required / the plan was rejected).

The public entry point is :func:`save_incident`.  All three pipeline
front-ends (``main.py``, ``app.py``, ``monitor.py``) call it after
obtaining the final state.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from config import settings

# Base directory for incident artefacts — configured in settings
_INCIDENTS_DIR = settings.incidents_dir


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def save_incident(thread_id: str, state: dict[str, Any]) -> str:
    """
    Persist the pipeline results for a single run.

    Creates ``incidents/<thread_id>/`` (sanitised for filesystem safety)
    and writes three files inside it.

    Args:
        thread_id: The LangGraph thread ID used for this run.
        state:     The final ``AgentState`` dict produced by the pipeline.

    Returns:
        The absolute path to the created incident folder.
    """
    # Sanitise thread_id so it is a safe directory name
    safe_id = _sanitise(thread_id)
    folder = os.path.join(_INCIDENTS_DIR, safe_id)
    os.makedirs(folder, exist_ok=True)

    timestamp = datetime.now(timezone.utc).isoformat()
    target_ip = state.get("target_ip") or state.get("target", "unknown")

    _write_recon_data(folder, state, timestamp, target_ip, thread_id)
    _write_analysis_report(folder, state, timestamp, target_ip, thread_id)
    _write_mitigation_log(folder, state, timestamp, target_ip, thread_id)

    print(f"\n📁  [Incident I/O] Artefacts saved → {folder}")
    print(f"    ├── recon_data.json")
    print(f"    ├── analysis_report.md")
    print(f"    └── mitigation_log.txt")

    return folder


# ═══════════════════════════════════════════════════════════════════════════
# File writers
# ═══════════════════════════════════════════════════════════════════════════

def _write_recon_data(
    folder: str,
    state: dict,
    timestamp: str,
    target_ip: str,
    thread_id: str,
) -> None:
    """Write ``recon_data.json`` — raw Nmap output + web-tech results."""

    scan_results = state.get("scan_results", {}) or {}
    web_tech = state.get("web_tech_results", {}) or {}

    payload = {
        "meta": {
            "thread_id": thread_id,
            "target_ip": target_ip,
            "timestamp": timestamp,
            "agent": "recon",
        },
        "nmap_raw_output": scan_results.get("raw_output", ""),
        "scan_results": _json_safe(scan_results),
        "web_tech_results": _json_safe(web_tech),
    }

    path = os.path.join(folder, "recon_data.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)


def _write_analysis_report(
    folder: str,
    state: dict,
    timestamp: str,
    target_ip: str,
    thread_id: str,
) -> None:
    """Write ``analysis_report.md`` — formatted Markdown threat report."""

    risk_score = state.get("risk_score", "N/A")
    risk_level = state.get("risk_level", "N/A")
    category = state.get("category", "N/A")
    threat_detected = state.get("threat_detected", False)
    threat_report = state.get("threat_analysis_report", "")
    threat_summary = state.get("threat_summary", "")
    threat_intel = state.get("threat_intel_context", "")

    lines: list[str] = [
        f"# Threat Analysis Report",
        f"",
        f"| Field            | Value |",
        f"|------------------|-------|",
        f"| **Target IP**    | `{target_ip}` |",
        f"| **Thread ID**    | `{thread_id}` |",
        f"| **Timestamp**    | {timestamp} |",
        f"| **Risk Score**   | {risk_score}/10 |",
        f"| **Risk Level**   | {risk_level} |",
        f"| **Category**     | {category} |",
        f"| **Threat Found** | {'Yes' if threat_detected else 'No'} |",
        f"",
    ]

    if threat_summary:
        lines += [
            "## Executive Summary",
            "",
            threat_summary,
            "",
        ]

    if threat_report:
        lines += [
            "## Detailed Analysis",
            "",
            threat_report,
            "",
        ]

    if threat_intel:
        lines += [
            "## Threat Intelligence Context",
            "",
            threat_intel,
            "",
        ]

    # Append the full running incident report as an appendix
    incident_report = state.get("incident_report", "")
    if incident_report:
        lines += [
            "---",
            "",
            "## Appendix — Full Incident Report",
            "",
            "```",
            incident_report,
            "```",
            "",
        ]

    path = os.path.join(folder, "analysis_report.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def _write_mitigation_log(
    folder: str,
    state: dict,
    timestamp: str,
    target_ip: str,
    thread_id: str,
) -> None:
    """Write ``mitigation_log.txt`` — approved commands & response plan."""

    final_decision = state.get("final_decision", "")
    response_plan = state.get("response_plan", "")
    remediation = state.get("final_remediation_plan", "")
    risk_level = state.get("risk_level", "N/A")
    risk_score = state.get("risk_score", "N/A")

    lines: list[str] = [
        "=" * 60,
        "  MITIGATION LOG",
        "=" * 60,
        f"  Target IP  : {target_ip}",
        f"  Thread ID  : {thread_id}",
        f"  Timestamp  : {timestamp}",
        f"  Risk Level : {risk_level} ({risk_score}/10)",
        f"  Decision   : {final_decision or 'N/A'}",
        "=" * 60,
        "",
    ]

    if remediation:
        lines += [
            "-" * 60,
            "FINAL REMEDIATION PLAN (extracted commands)",
            "-" * 60,
            "",
            remediation,
            "",
        ]

    if response_plan:
        lines += [
            "-" * 60,
            "FULL RESPONSE PLAN (LLM output)",
            "-" * 60,
            "",
            response_plan,
            "",
        ]

    if not remediation and not response_plan:
        if "Rejected" in final_decision:
            lines.append(
                "Response plan was REJECTED by the human operator.\n"
                "No remediation commands were executed.\n"
            )
        else:
            lines.append(
                "No response plan was generated for this run.\n"
                "Risk level did not warrant active remediation.\n"
            )

    path = os.path.join(folder, "mitigation_log.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _sanitise(name: str) -> str:
    """
    Make a string safe for use as a directory name.

    Replaces filesystem-hostile characters with ``_`` and truncates
    to 128 characters.
    """
    safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in name)
    return safe[:128] or "unknown"


def _json_safe(obj: Any) -> Any:
    """
    Recursively convert an object so it is JSON-serialisable.

    LangChain message objects, sets, bytes, etc. are coerced to
    strings to avoid ``TypeError`` from ``json.dump``.
    """
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(item) for item in obj]
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    # Fallback: stringify anything exotic
    return str(obj)
