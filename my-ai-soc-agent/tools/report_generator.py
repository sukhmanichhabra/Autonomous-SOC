#!/usr/bin/env python3
"""
Report Generator Tool
=====================
Creates timestamped, professional incident-report artefacts from a
completed pipeline ``AgentState``.

Public API
----------
:func:`save_incident_bundle`  *(primary — call this at graph END)*
    Creates ``incidents/{thread_id}_{YYYYMMDD_HHMMSS}/`` and writes
    exactly three canonical post-mortem files:

    * **recon.json**              — Raw Nmap scan data, web-tech
                                    fingerprinting, CVE re-ranking telemetry,
                                    and full scan metadata.
    * **analysis.md**             — The AI's complete reasoning: MITRE ATT&CK
                                    mapping table, key findings, risk
                                    assessment, threat-intel context, and the
                                    full threat-analysis report.
    * **remediation_proof.txt**   — Actual terminal output from every executed
                                    command (stdout / stderr / exit-code /
                                    timing), plus the approved command list and
                                    the human-operator decision.  When no
                                    commands were executed the file explains
                                    why (dry-run, rejected, or low-risk).

    The ``{thread_id}_{timestamp}`` folder naming means repeated scans of
    the same target each produce a new, non-clobbering bundle.

:func:`generate_incident_report`  *(legacy — kept for backward compat)*
    Creates ``incidents/<thread_id>/`` and writes three timestamped files
    prefixed with ``YYYYMMDD_HHMMSS_``.

Usage
-----
::

    from tools.report_generator import save_incident_bundle

    # At the end of the LangGraph pipeline:
    folder = save_incident_bundle(final_state, thread_id="target-10.0.0.50")
    print(f"Post-mortem bundle saved to {folder}")
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

# Base directory — ``incidents/`` lives next to the project's main.py
_INCIDENTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "incidents",
)


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def generate_incident_report(state: dict[str, Any], thread_id: str = "") -> str:
    """
    Create a timestamped incident-report folder with three artefact files.

    Parameters
    ----------
    state : dict
        The final ``AgentState`` dictionary produced by the LangGraph
        pipeline.  At a minimum it should contain ``scan_results``,
        ``threat_analysis``, ``risk_level``, ``risk_score``, and
        ``response_plan``.
    thread_id : str, optional
        The LangGraph thread ID for the run.  Used as the folder name
        under ``incidents/``.  Falls back to
        ``target-<ip>`` when empty.

    Returns
    -------
    str
        Absolute path to the created incident folder.
    """
    # Derive a folder name
    target_ip = state.get("target_ip") or state.get("target", "unknown")
    if not thread_id:
        thread_id = f"target-{target_ip}"
    safe_id = _sanitise(thread_id)

    folder = os.path.join(_INCIDENTS_DIR, safe_id)
    os.makedirs(folder, exist_ok=True)

    # UTC timestamp used in every filename
    now = datetime.now(timezone.utc)
    ts_tag = now.strftime("%Y%m%d_%H%M%S")      # for filenames
    ts_iso = now.isoformat()                     # for metadata fields

    # Write the three artefact files
    evidence_path    = _write_evidence(folder, ts_tag, ts_iso, state, target_ip, thread_id)
    analysis_path    = _write_analysis(folder, ts_tag, ts_iso, state, target_ip, thread_id)
    remediation_path = _write_remediation(folder, ts_tag, ts_iso, state, target_ip, thread_id)

    # Console summary
    print(f"\n📁  [Report Generator] Incident artefacts saved → {folder}")
    print(f"    ├── {os.path.basename(evidence_path)}")
    print(f"    ├── {os.path.basename(analysis_path)}")
    print(f"    └── {os.path.basename(remediation_path)}")

    return folder


# ═══════════════════════════════════════════════════════════════════════════
# PRIMARY PUBLIC API  —  save_incident_bundle()
# ═══════════════════════════════════════════════════════════════════════════

def save_incident_bundle(state: dict[str, Any], thread_id: str = "") -> str:
    """
    Create a self-contained post-mortem bundle at graph END.

    This is the **canonical** entry point called once the LangGraph pipeline
    has finished (after the Response Agent returns, or after a human rejects
    the plan).  It replaces the need to call three separate artefact writers
    because every consumer — ``main.py``, ``app.py``, ``monitor.py`` — should
    call this single function to guarantee a consistent, auditable record.

    Folder layout
    -------------
    ``incidents/{thread_id}_{YYYYMMDD_HHMMSS}/``

    ├── ``recon.json``             raw scan data + CVE re-ranking telemetry
    ├── ``analysis.md``            AI reasoning, MITRE table, key findings
    └── ``remediation_proof.txt``  terminal output of every executed command

    Parameters
    ----------
    state : dict
        The final ``AgentState`` dictionary produced by the LangGraph pipeline.
    thread_id : str, optional
        LangGraph thread ID.  Defaults to ``target-<ip>`` when empty.

    Returns
    -------
    str
        Absolute path to the created bundle folder.
    """
    target_ip = state.get("target_ip") or state.get("target", "unknown")
    if not thread_id:
        thread_id = f"target-{target_ip}"

    now     = datetime.now(timezone.utc)
    ts_tag  = now.strftime("%Y%m%d_%H%M%S")   # filename / folder timestamp
    ts_iso  = now.isoformat()                  # human-readable metadata

    # Folder: incidents/{thread_id}_{timestamp}/
    safe_id = _sanitise(f"{thread_id}_{ts_tag}")
    folder  = os.path.join(_INCIDENTS_DIR, safe_id)
    os.makedirs(folder, exist_ok=True)

    recon_path  = _bundle_recon(folder, ts_iso, state, target_ip, thread_id)
    analysis_path = _bundle_analysis(folder, ts_iso, state, target_ip, thread_id)
    proof_path  = _bundle_remediation_proof(folder, ts_iso, state, target_ip, thread_id)

    print(f"\n📁  [Report Generator] Post-mortem bundle saved → {folder}")
    print(f"    ├── {os.path.basename(recon_path)}")
    print(f"    ├── {os.path.basename(analysis_path)}")
    print(f"    └── {os.path.basename(proof_path)}")

    return folder


# ───────────────────────────────────────────────────────────────────────────
# Bundle writer 1: recon.json
# ───────────────────────────────────────────────────────────────────────────

def _bundle_recon(
    folder: str,
    ts_iso: str,
    state: dict,
    target_ip: str,
    thread_id: str,
) -> str:
    """
    Write ``recon.json``.

    Contains every piece of raw evidence collected by the Recon Agent:
    the full Nmap raw output, web-tech fingerprinting results, CVE
    re-ranking telemetry from the Threat Analysis Agent (how many CVEs
    were retrieved vs. kept), and standard scan metadata.
    """
    scan_results: dict  = state.get("scan_results", {}) or {}
    web_tech: dict      = state.get("web_tech_results", {}) or {}
    threat_analysis: dict = state.get("threat_analysis", {}) or {}

    payload = {
        "meta": {
            "bundle_version": "2.0",
            "generator":  "tools.report_generator.save_incident_bundle",
            "thread_id":  thread_id,
            "target_ip":  target_ip,
            "generated_at": ts_iso,
        },
        # ── Nmap output ────────────────────────────────────────────────
        "nmap_scan": {
            "host":        scan_results.get("host", target_ip),
            "scan_type":   scan_results.get("scan_type", ""),
            "arguments":   scan_results.get("arguments", ""),
            "raw_output":  scan_results.get("raw_output", ""),
            "open_ports":  scan_results.get("open_ports", []),
            "services":    scan_results.get("services", {}),
        },
        # ── Web technology fingerprinting ─────────────────────────────
        "web_tech": {
            "raw_output":              web_tech.get("raw_output", ""),
            "technologies_found":      web_tech.get("technologies_found", []),
            "missing_security_headers": web_tech.get("missing_security_headers", []),
            "security_headers_present": web_tech.get("security_headers_present", []),
        },
        # ── CVE re-ranking telemetry (Stage 2 & 3 of threat analysis) ─
        "cve_reranking": {
            "high_confidence_kept":  threat_analysis.get("cve_high_confidence_kept", 0),
            "match_threshold_pct":   threat_analysis.get("cve_match_threshold", 90),
            "threat_intel_matches":  threat_analysis.get("threat_intel_matches", 0),
        },
        # ── Log data (if provided) ────────────────────────────────────
        "log_data": state.get("log_data", ""),
    }

    path = os.path.join(folder, "recon.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_json_safe(payload), fh, indent=2, default=str)
    return path


# ───────────────────────────────────────────────────────────────────────────
# Bundle writer 2: analysis.md
# ───────────────────────────────────────────────────────────────────────────

def _bundle_analysis(
    folder: str,
    ts_iso: str,
    state: dict,
    target_ip: str,
    thread_id: str,
) -> str:
    """
    Write ``analysis.md``.

    A professional Markdown document containing:
    * Metadata / risk-score table
    * Executive summary (plain-English threat paragraph)
    * MITRE ATT&CK mapping table (auto-extracted from the LLM output)
    * Key findings table
    * CVE re-ranking summary (how many CVEs were kept vs. filtered)
    * Detailed analysis (collapsible)
    * Threat-intel context (collapsible)
    * Full running incident report (collapsible appendix)
    """
    risk_score      = state.get("risk_score", "N/A")
    risk_level      = state.get("risk_level", "N/A")
    category        = state.get("category", "N/A")
    threat_detected = state.get("threat_detected", False)
    threat_summary  = state.get("threat_summary", "")
    threat_analysis: dict = state.get("threat_analysis", {}) or {}
    analysis_text   = threat_analysis.get("analysis", "")
    threat_intel    = state.get("threat_intel_context", "")
    incident_report = state.get("incident_report", "")
    final_decision  = state.get("final_decision", "")

    # CVE re-ranking telemetry
    cve_kept      = threat_analysis.get("cve_high_confidence_kept", 0)
    cve_threshold = threat_analysis.get("cve_match_threshold", 90)

    mitre_maps   = _extract_mitre_mappings(analysis_text)
    key_findings = _extract_findings(analysis_text)

    lines: list[str] = []

    # ── Title ──────────────────────────────────────────────────────────
    sev_badge = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢",
    }.get(str(risk_level).upper(), "⚪")

    lines += [
        f"# {sev_badge} Incident Analysis Report",
        "",
        f"> **Generated:** {ts_iso}  ",
        f"> **Generator:** `tools.report_generator.save_incident_bundle`",
        "",
    ]

    # ── Metadata table ─────────────────────────────────────────────────
    lines += [
        "## Metadata",
        "",
        "| Field                  | Value |",
        "|------------------------|-------|",
        f"| **Target IP**          | `{target_ip}` |",
        f"| **Thread ID**          | `{thread_id}` |",
        f"| **Timestamp (UTC)**    | {ts_iso} |",
        f"| **Risk Score**         | **{risk_score}/10** |",
        f"| **Risk Level**         | **{risk_level}** |",
        f"| **Category**           | {category} |",
        f"| **Threat Detected**    | {'✅ Yes' if threat_detected else '❌ No'} |",
        f"| **Human Decision**     | {final_decision or '—'} |",
        f"| **CVEs kept (≥{cve_threshold}%)**| {cve_kept} |",
        "",
    ]

    # ── Executive Summary ──────────────────────────────────────────────
    if threat_summary:
        lines += [
            "## Executive Summary",
            "",
            threat_summary,
            "",
        ]

    # ── CVE Re-ranking Summary ─────────────────────────────────────────
    lines += [
        "## CVE Re-ranking Summary",
        "",
        f"The Mini-LLM re-ranker (`llama-3.1-8b-instant`) evaluated the top-5 "
        f"CVE candidates retrieved from ChromaDB against the **exact service "
        f"versions** found during the Nmap scan.",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Match threshold | ≥{cve_threshold}% |",
        f"| High-confidence CVEs kept | **{cve_kept}** |",
        f"| Total threat-intel matches | "
        f"{threat_analysis.get('threat_intel_matches', 0)} |",
        "",
        f"> Only CVEs that scored **≥{cve_threshold}%** were forwarded to the "
        f"final analysis, minimising false positives that could cause legitimate "
        f"traffic to be blocked.",
        "",
    ]

    # ── MITRE ATT&CK Mapping Table ─────────────────────────────────────
    lines += [
        "## MITRE ATT&CK Mapping",
        "",
    ]
    if mitre_maps:
        lines += [
            "| # | Technique ID | Technique Name | Context |",
            "|---|-------------|----------------|---------|",
        ]
        for i, m in enumerate(mitre_maps, 1):
            tid  = m["technique_id"]
            name = _md_escape(m["name"][:60])
            ctx  = _md_escape(m["context"][:120])
            url  = (
                f"https://attack.mitre.org/techniques/"
                f"{tid.replace('.', '/')}/"
            )
            lines.append(f"| {i} | [{tid}]({url}) | {name} | {ctx} |")
        lines.append("")
    else:
        lines += [
            "_No MITRE ATT&CK techniques were identified in this scan._",
            "",
        ]

    # ── Key Findings ───────────────────────────────────────────────────
    if key_findings:
        lines += [
            "## Key Findings",
            "",
            "| # | Severity | Finding |",
            "|---|----------|---------|",
        ]
        for i, f in enumerate(key_findings, 1):
            sev     = f["severity"] or "—"
            finding = _md_escape(f["finding"][:200])
            lines.append(f"| {i} | {sev} | {finding} |")
        lines.append("")

    # ── Full Analysis (collapsible) ────────────────────────────────────
    if analysis_text:
        lines += [
            "## Detailed Analysis",
            "",
            "<details>",
            "<summary>Click to expand full AI analysis</summary>",
            "",
            analysis_text,
            "",
            "</details>",
            "",
        ]

    # ── Threat Intelligence Context (collapsible) ──────────────────────
    if threat_intel:
        lines += [
            "## Threat Intelligence Context",
            "",
            "<details>",
            "<summary>Click to expand high-confidence threat intel "
            f"(≥{cve_threshold}% CVE matches + relevant TTPs/IOCs)</summary>",
            "",
            threat_intel,
            "",
            "</details>",
            "",
        ]

    # ── Appendix: full running incident report ─────────────────────────
    if incident_report:
        lines += [
            "---",
            "",
            "## Appendix — Full Pipeline Incident Report",
            "",
            "<details>",
            "<summary>Click to expand raw incident report</summary>",
            "",
            "```",
            incident_report,
            "```",
            "",
            "</details>",
            "",
        ]

    lines += [
        "---",
        "",
        f"_Report generated by **AI SOC Agent** · "
        f"`tools.report_generator.save_incident_bundle` · {ts_iso}_",
        "",
    ]

    path = os.path.join(folder, "analysis.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


# ───────────────────────────────────────────────────────────────────────────
# Bundle writer 3: remediation_proof.txt
# ───────────────────────────────────────────────────────────────────────────

def _bundle_remediation_proof(
    folder: str,
    ts_iso: str,
    state: dict,
    target_ip: str,
    thread_id: str,
) -> str:
    """
    Write ``remediation_proof.txt``.

    This is the forensic record of **what actually ran on the system**.
    For each command in ``execution_results`` the file records:

    * The exact command string
    * Status: DRY_RUN | SUCCESS | FAILED | TIMEOUT | BLOCKED | ERROR
    * Exit code (for live runs)
    * stdout capture
    * stderr capture
    * Wall-clock duration in milliseconds

    When no commands were executed, the file explains why (dry-run
    mode, rejected by operator, or risk level too low to warrant action).
    """
    final_decision    = state.get("final_decision", "")
    response_plan     = state.get("response_plan", "")
    remediation_cmds  = state.get("final_remediation_plan", "")
    risk_level        = state.get("risk_level", "N/A")
    risk_score        = state.get("risk_score", "N/A")
    category          = state.get("category", "N/A")
    dry_run           = state.get("dry_run", True)
    execution_results = state.get("execution_results") or []

    SEP  = "=" * 66
    THIN = "-" * 66

    lines: list[str] = [
        SEP,
        "  REMEDIATION PROOF  —  AI SOC Agent",
        SEP,
        f"  Target IP       : {target_ip}",
        f"  Thread ID       : {thread_id}",
        f"  Timestamp (UTC) : {ts_iso}",
        f"  Risk Level      : {risk_level}  ({risk_score}/10)",
        f"  Category        : {category}",
        f"  Execution mode  : {'DRY-RUN (simulated)' if dry_run else '⚠️  LIVE EXECUTION'}",
        f"  Human decision  : {final_decision or 'N/A'}",
        SEP,
        "",
    ]

    # ── Section 1: Approved command list ──────────────────────────────
    if remediation_cmds:
        lines += [
            THIN,
            "  [1/3]  APPROVED REMEDIATION COMMANDS",
            THIN,
            "",
            remediation_cmds.strip(),
            "",
        ]
    else:
        _reason = (
            "Rejected by human operator — no commands approved."
            if final_decision and "Rejected" in final_decision
            else f"No remediation commands generated (risk level: {risk_level})."
        )
        lines += [
            THIN,
            "  [1/3]  APPROVED REMEDIATION COMMANDS",
            THIN,
            "",
            f"  {_reason}",
            "",
        ]

    # ── Section 2: Execution results (the actual proof) ───────────────
    lines += [
        THIN,
        "  [2/3]  COMMAND EXECUTION PROOF  (stdout / stderr / exit-code)",
        THIN,
        "",
    ]

    if execution_results:
        total   = len(execution_results)
        success = sum(1 for r in execution_results
                      if isinstance(r, dict) and r.get("status") == "SUCCESS")
        dry_n   = sum(1 for r in execution_results
                      if isinstance(r, dict) and r.get("status") == "DRY_RUN")
        failed  = sum(1 for r in execution_results
                      if isinstance(r, dict) and r.get("status") in ("FAILED", "TIMEOUT", "ERROR"))
        blocked = sum(1 for r in execution_results
                      if isinstance(r, dict) and r.get("status") == "BLOCKED")

        lines += [
            f"  Summary: {total} command(s) — "
            f"{dry_n} dry-run  |  {success} success  |  "
            f"{failed} failed  |  {blocked} blocked",
            "",
        ]

        for i, res in enumerate(execution_results, 1):
            if not isinstance(res, dict):
                lines.append(f"  [{i:02d}] {res}\n")
                continue

            cmd        = res.get("command", "N/A")
            status     = res.get("status", "N/A")
            returncode = res.get("returncode")
            stdout_raw = (res.get("stdout") or "").strip()
            stderr_raw = (res.get("stderr") or "").strip()
            duration   = res.get("duration_ms", 0)

            # Status icon
            icon = {
                "SUCCESS": "✅", "DRY_RUN": "🔵", "FAILED": "❌",
                "TIMEOUT": "⏱️", "BLOCKED": "🚫", "ERROR": "💥",
            }.get(status, "•")

            lines += [
                f"  ┌─ Command [{i:02d}/{total}] {icon}  {status}",
                f"  │  $ {cmd}",
                f"  │  Exit code  : {returncode if returncode is not None else '—  (simulated)'}",
                f"  │  Duration   : {duration} ms",
            ]

            if stdout_raw:
                lines.append("  │  stdout ↓")
                for ln in stdout_raw.splitlines():
                    lines.append(f"  │    {ln}")
            else:
                lines.append("  │  stdout : (none)")

            if stderr_raw:
                lines.append("  │  stderr ↓")
                for ln in stderr_raw.splitlines():
                    lines.append(f"  │    {ln}")

            lines += ["  └" + "─" * 60, ""]

    else:
        if dry_run:
            lines += [
                "  No commands were executed — pipeline ran in DRY-RUN mode.",
                "  All remediation actions were simulated (not applied to the system).",
                "  Re-run with --live (CLI) or enable 'Live Execution' in the UI",
                "  to apply commands to the host.",
                "",
            ]
        elif final_decision and "Rejected" in final_decision:
            lines += [
                "  No commands were executed — the human operator REJECTED the plan.",
                "  The Response Agent generated a plan but it was not approved.",
                "",
            ]
        else:
            lines += [
                "  No commands were generated or executed for this incident.",
                f"  Risk level ({risk_level}) did not produce actionable remediation.",
                "",
            ]

    # ── Section 3: Full response plan (LLM output for audit trail) ────
    lines += [
        THIN,
        "  [3/3]  FULL RESPONSE PLAN  (LLM output — for audit trail)",
        THIN,
        "",
    ]
    if response_plan:
        lines += [response_plan.strip(), ""]
    else:
        lines += ["  No response plan was generated for this run.", ""]

    lines += [
        SEP,
        f"  End of remediation proof  ·  {ts_iso}",
        SEP,
    ]

    path = os.path.join(folder, "remediation_proof.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


# ═══════════════════════════════════════════════════════════════════════════
# 1. evidence.json — raw Nmap results
# ═══════════════════════════════════════════════════════════════════════════

def _write_evidence(
    folder: str,
    ts_tag: str,
    ts_iso: str,
    state: dict,
    target_ip: str,
    thread_id: str,
) -> str:
    """
    Write ``<ts>_evidence.json`` containing the raw Nmap scan output,
    web-tech fingerprinting data, and scan metadata.
    """
    scan_results: dict = state.get("scan_results", {}) or {}
    web_tech: dict = state.get("web_tech_results", {}) or {}

    payload = {
        "meta": {
            "thread_id": thread_id,
            "target_ip": target_ip,
            "generated_at": ts_iso,
            "generator": "tools.report_generator",
        },
        "nmap_results": {
            "raw_output": scan_results.get("raw_output", ""),
            "scan_type": scan_results.get("scan_type", ""),
            "host": scan_results.get("host", target_ip),
            "arguments": scan_results.get("arguments", ""),
        },
        "web_tech_results": {
            "raw_output": web_tech.get("raw_output", ""),
            "technologies_found": web_tech.get("technologies_found", []),
            "missing_security_headers": web_tech.get("missing_security_headers", []),
        },
    }

    path = os.path.join(folder, f"{ts_tag}_evidence.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_json_safe(payload), fh, indent=2, default=str)
    return path


# ═══════════════════════════════════════════════════════════════════════════
# 2. analysis.md — professional Markdown report
# ═══════════════════════════════════════════════════════════════════════════

# Regex to find MITRE ATT&CK technique references in the analysis text
_MITRE_RE = re.compile(
    r"(T\d{4}(?:\.\d{3})?)"        # e.g. T1190, T1059.001
    r"\s*(?:[:\-–—]\s*|\()"        # separator — colon, dash, or opening paren
    r"(.+?)(?:\)|\.|$)",            # technique name — up to period, paren, or EOL
    re.MULTILINE,
)

# Fallback: lines that look like "- T1046: Network Service Discovery"
_MITRE_LINE_RE = re.compile(
    r"[-*]\s*(T\d{4}(?:\.\d{3})?)\s*[:\-–—]\s*(.+)",
    re.MULTILINE,
)


def _extract_mitre_mappings(analysis_text: str) -> list[dict[str, str]]:
    """
    Parse MITRE ATT&CK technique IDs and names from the LLM analysis.

    Returns a list of ``{"technique_id": "T1190", "name": "…", "context": "…"}``
    dicts.  Deduplicates by technique ID.
    """
    mappings: dict[str, dict[str, str]] = {}

    for rx in (_MITRE_RE, _MITRE_LINE_RE):
        for m in rx.finditer(analysis_text):
            tid = m.group(1).strip()
            name = m.group(2).strip().rstrip(".")
            if tid not in mappings:
                # Try to grab the surrounding sentence as context
                start = max(0, m.start() - 80)
                end = min(len(analysis_text), m.end() + 120)
                ctx = analysis_text[start:end].replace("\n", " ").strip()
                mappings[tid] = {
                    "technique_id": tid,
                    "name": name,
                    "context": ctx,
                }

    return list(mappings.values())


def _extract_findings(analysis_text: str) -> list[dict[str, str]]:
    """
    Extract key findings from the ``## Key Findings`` section or
    fall back to bullet-pointed items in the full analysis.
    """
    findings: list[dict[str, str]] = []

    # Try to find the Key Findings section
    kf_match = re.search(
        r"##\s*Key Findings\s*\n(.*?)(?=\n##|\nRISK_SCORE:|\Z)",
        analysis_text,
        re.DOTALL | re.IGNORECASE,
    )
    source = kf_match.group(1) if kf_match else analysis_text

    for line in source.splitlines():
        stripped = line.strip()
        if stripped and (stripped.startswith("-") or stripped.startswith("*")):
            # Remove leading bullet
            text = re.sub(r"^[-*]\s*", "", stripped)
            if len(text) > 10:
                # Try to split severity if it starts with **CRITICAL** etc.
                sev_match = re.match(
                    r"\*{0,2}(CRITICAL|HIGH|MEDIUM|LOW)\*{0,2}\s*[:\-–—]?\s*(.*)",
                    text, re.IGNORECASE,
                )
                if sev_match:
                    findings.append({
                        "severity": sev_match.group(1).upper(),
                        "finding": sev_match.group(2).strip(),
                    })
                else:
                    findings.append({
                        "severity": "",
                        "finding": text,
                    })
    return findings


def _write_analysis(
    folder: str,
    ts_tag: str,
    ts_iso: str,
    state: dict,
    target_ip: str,
    thread_id: str,
) -> str:
    """
    Write ``<ts>_analysis.md`` — a professional Markdown report
    containing metadata, risk assessment, MITRE ATT&CK mapping table,
    key findings, and the full analysis text.
    """
    risk_score = state.get("risk_score", "N/A")
    risk_level = state.get("risk_level", "N/A")
    category = state.get("category", "N/A")
    threat_detected = state.get("threat_detected", False)
    threat_summary = state.get("threat_summary", "")
    threat_analysis: dict = state.get("threat_analysis", {}) or {}
    analysis_text = threat_analysis.get("analysis", "")
    threat_intel = state.get("threat_intel_context", "")

    # ── Parse MITRE mappings from the analysis ─────────────────────
    mitre_maps = _extract_mitre_mappings(analysis_text)
    key_findings = _extract_findings(analysis_text)

    lines: list[str] = []

    # Title
    lines += [
        f"# 🛡️ Incident Analysis Report",
        "",
        f"> **Generated:** {ts_iso}  ",
        f"> **Generator:** `tools.report_generator`",
        "",
    ]

    # ── Metadata table ─────────────────────────────────────────────
    lines += [
        "## Metadata",
        "",
        "| Field              | Value |",
        "|--------------------|-------|",
        f"| **Target IP**      | `{target_ip}` |",
        f"| **Thread ID**      | `{thread_id}` |",
        f"| **Timestamp (UTC)**| {ts_iso} |",
        f"| **Risk Score**     | **{risk_score}/10** |",
        f"| **Risk Level**     | **{risk_level}** |",
        f"| **Category**       | {category} |",
        f"| **Threat Detected**| {'✅ Yes' if threat_detected else '❌ No'} |",
        "",
    ]

    # ── Executive Summary ──────────────────────────────────────────
    if threat_summary:
        lines += [
            "## Executive Summary",
            "",
            threat_summary,
            "",
        ]

    # ── MITRE ATT&CK Mapping Table ────────────────────────────────
    lines += [
        "## MITRE ATT&CK Mapping",
        "",
    ]
    if mitre_maps:
        lines += [
            "| # | Technique ID | Technique Name | Context |",
            "|---|-------------|----------------|---------|",
        ]
        for i, m in enumerate(mitre_maps, 1):
            tid = m["technique_id"]
            name = _md_escape(m["name"][:60])
            ctx = _md_escape(m["context"][:120])
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            lines.append(
                f"| {i} | [{tid}]({url}) | {name} | {ctx} |"
            )
        lines.append("")
    else:
        lines += [
            "_No MITRE ATT&CK techniques were identified in this scan._",
            "",
        ]

    # ── Key Findings ──────────────────────────────────────────────
    if key_findings:
        lines += [
            "## Key Findings",
            "",
            "| # | Severity | Finding |",
            "|---|----------|---------|",
        ]
        for i, f in enumerate(key_findings, 1):
            sev = f["severity"] or "—"
            finding = _md_escape(f["finding"][:200])
            lines.append(f"| {i} | {sev} | {finding} |")
        lines.append("")

    # ── Full Analysis (collapsible) ────────────────────────────────
    if analysis_text:
        lines += [
            "## Detailed Analysis",
            "",
            "<details>",
            "<summary>Click to expand full analysis</summary>",
            "",
            analysis_text,
            "",
            "</details>",
            "",
        ]

    # ── Threat Intelligence Context ────────────────────────────────
    if threat_intel:
        lines += [
            "## Threat Intelligence Context",
            "",
            "<details>",
            "<summary>Click to expand threat intel</summary>",
            "",
            threat_intel,
            "",
            "</details>",
            "",
        ]

    # ── Footer ─────────────────────────────────────────────────────
    lines += [
        "---",
        "",
        f"_Report generated by **AI SOC Agent** on {ts_iso}._",
        "",
    ]

    path = os.path.join(folder, f"{ts_tag}_analysis.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


# ═══════════════════════════════════════════════════════════════════════════
# 3. remediation.txt — approved commands & execution results
# ═══════════════════════════════════════════════════════════════════════════

def _write_remediation(
    folder: str,
    ts_tag: str,
    ts_iso: str,
    state: dict,
    target_ip: str,
    thread_id: str,
) -> str:
    """
    Write ``<ts>_remediation.txt`` containing:

    * The human-approval decision.
    * The extracted executable commands (from ``final_remediation_plan``).
    * The full response / monitoring plan (from ``response_plan``).
    * Any execution results recorded in the state.
    """
    final_decision = state.get("final_decision", "")
    response_plan = state.get("response_plan", "")
    remediation = state.get("final_remediation_plan", "")
    risk_level = state.get("risk_level", "N/A")
    risk_score = state.get("risk_score", "N/A")
    category = state.get("category", "N/A")

    # Some pipeline variants may stash execution results here
    execution_results = state.get("execution_results", "")

    sep = "=" * 64
    thin = "-" * 64

    lines: list[str] = [
        sep,
        "  REMEDIATION LOG",
        sep,
        f"  Target IP      : {target_ip}",
        f"  Thread ID      : {thread_id}",
        f"  Timestamp (UTC): {ts_iso}",
        f"  Risk Level     : {risk_level} ({risk_score}/10)",
        f"  Category       : {category}",
        f"  Decision       : {final_decision or 'N/A'}",
        sep,
        "",
    ]

    # ── Approved / extracted commands ──────────────────────────────
    if remediation:
        lines += [
            thin,
            "APPROVED REMEDIATION COMMANDS",
            thin,
            "",
            remediation,
            "",
        ]
    else:
        if final_decision and "Rejected" in final_decision:
            lines += [
                thin,
                "REMEDIATION STATUS: REJECTED",
                thin,
                "",
                "The response plan was REJECTED by the human operator.",
                "No remediation commands were approved for execution.",
                "",
            ]
        else:
            lines += [
                thin,
                "REMEDIATION STATUS: NONE REQUIRED",
                thin,
                "",
                "No remediation commands were generated for this run.",
                f"Risk level ({risk_level}) did not warrant active remediation.",
                "",
            ]

    # ── Execution results (if available) ──────────────────────────
    if execution_results:
        lines += [
            thin,
            "EXECUTION RESULTS",
            thin,
            "",
        ]
        if isinstance(execution_results, dict):
            lines.append(json.dumps(execution_results, indent=2, default=str))
        elif isinstance(execution_results, list):
            for i, res in enumerate(execution_results, 1):
                if isinstance(res, dict):
                    cmd = res.get("command", "N/A")
                    status = res.get("status", "N/A")
                    output = res.get("output", "")
                    lines.append(f"  [{i:02d}] Command : {cmd}")
                    lines.append(f"       Status  : {status}")
                    if output:
                        lines.append(f"       Output  : {output}")
                    lines.append("")
                else:
                    lines.append(f"  [{i:02d}] {res}")
                    lines.append("")
        else:
            lines.append(str(execution_results))
        lines.append("")
    else:
        lines += [
            thin,
            "EXECUTION RESULTS",
            thin,
            "",
            "No commands were executed in this session.",
            "(Commands are logged here when run via the auto-approve pipeline",
            " or when an operator manually executes them.)",
            "",
        ]

    # ── Full response plan (LLM output) ──────────────────────────
    if response_plan:
        lines += [
            thin,
            "FULL RESPONSE PLAN (LLM output)",
            thin,
            "",
            response_plan,
            "",
        ]

    path = os.path.join(folder, f"{ts_tag}_remediation.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _sanitise(name: str) -> str:
    """Make a string safe for use as a directory name."""
    safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in name)
    return safe[:128] or "unknown"


def _json_safe(obj: Any) -> Any:
    """Recursively convert an object to be JSON-serialisable."""
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(item) for item in obj]
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    return str(obj)


def _md_escape(text: str) -> str:
    """Escape pipe characters so they don't break Markdown tables."""
    return text.replace("|", "\\|").replace("\n", " ")
