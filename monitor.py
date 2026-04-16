#!/usr/bin/env python3
"""
Autonomous Security-Alert File Monitor
=======================================
Watches a log file (``logs/auth.log``, ``logs/security_alerts.txt``, or
any custom path) for lines that match known attack patterns and
**automatically** triggers the full LangGraph cybersecurity pipeline
(Recon → Threat Analysis → Response) for each detected IP — no human
intervention required in the detection/investigation phase.

This directly addresses the **alert-fatigue** problem: instead of a
human analyst triaging every syslog line, the monitor classifies the
event, attaches a threat category, and hands off to the AI pipeline
immediately.  The human gate is preserved only at the *remediation*
step (the Response Agent ``interrupt_before``).

Threat patterns detected
------------------------
The monitor uses a prioritised, named-pattern table rather than a simple
IP regex.  Each pattern carries a **severity** and a **category** that
is injected directly into the pipeline's ``AgentState``:

+---------------------------+----------+-------------------------------+
| Pattern name              | Severity | Category injected             |
+===========================+==========+===============================+
| Failed password (SSH)     | HIGH     | Brute Force — SSH             |
| Invalid user (SSH)        | HIGH     | Brute Force — SSH             |
| Connection reset (SSH)    | MEDIUM   | Connection Anomaly            |
| Too many auth failures    | HIGH     | Brute Force — SSH             |
| Possible break-in attempt | CRITICAL | Intrusion Attempt             |
| Accepted publickey (SSH)  | LOW      | Successful Auth — SSH         |
| sudo: auth failure        | HIGH     | Privilege Escalation Attempt  |
| su: auth failure          | HIGH     | Privilege Escalation Attempt  |
| kernel: UFW BLOCK         | MEDIUM   | Firewall Block Event          |
| kernel: UFW ALLOW         | LOW      | Firewall Allow Event          |
| Nmap scan detected        | HIGH     | Port Scan                     |
| SYN flood                 | CRITICAL | DoS / SYN Flood               |
| Port scan (Suricata/Snort)| HIGH     | Port Scan — IDS               |
| Generic ALERT line        | MEDIUM   | Security Alert (Generic)      |
| Bare IP (catch-all)       | LOW      | Network Activity              |
+---------------------------+----------+-------------------------------+

Patterns are evaluated in priority order — the **first** matching
pattern wins for a given line, so a "Possible break-in attempt" line
will never be downgraded to the catch-all.

Two delivery modes (``--mode``)
--------------------------------
* **direct** *(default)* — ``graph.invoke()`` in-process.  No server needed.
* **streamlit** — POSTs to the Streamlit dashboard ``/api/trigger_scan``.

File-watch strategy
-------------------
Uses **watchdog** for efficient filesystem event notifications.
Falls back to a 0.5 s polling loop if watchdog is not installed.

Usage examples
--------------
::

    # Watch auth.log (SSH brute-force, sudo failures, etc.)
    python monitor.py --auth-log

    # Watch a custom file
    python monitor.py --file /var/log/ids_alerts.txt

    # Dry-run — print matched patterns, don't invoke pipeline
    python monitor.py --auth-log --dry-run

    # Test your patterns against a sample line without watching
    python monitor.py --pattern-test "Mar  1 12:00:01 srv sshd[1234]: Failed password for root from 10.0.0.50 port 55123 ssh2"

    # Auto-approve Response Agent (fully autonomous SOAR mode)
    python monitor.py --auth-log --auto-approve

    # Streamlit mode
    python monitor.py --auth-log --mode streamlit --streamlit-url http://localhost:8501

    # Custom cooldown (re-investigate same IP after 60 s)
    python monitor.py --auth-log --cooldown 60
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Project path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.join(_SCRIPT_DIR, "my-ai-soc-agent")

# Ensure both the workspace root and project dir are importable
for _p in (_SCRIPT_DIR, _PROJECT_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dotenv import load_dotenv
load_dotenv(os.path.join(_PROJECT_DIR, ".env"))


# ---------------------------------------------------------------------------
# Constants & regex
# ---------------------------------------------------------------------------
DEFAULT_LOG      = os.path.join(_SCRIPT_DIR, "logs", "security_alerts.txt")
DEFAULT_AUTH_LOG = os.path.join(_SCRIPT_DIR, "logs", "auth.log")

# Bare IP extractor — used as the catch-all and for Streamlit payloads
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPs to silently ignore (loopback, link-local zeros, broadcast)
_IGNORE_PREFIXES = ("127.", "0.", "255.")


# ---------------------------------------------------------------------------
# Threat pattern engine
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ThreatPattern:
    """
    A named, prioritised pattern that matches a log line and extracts
    the offending IP together with threat metadata.

    Attributes
    ----------
    name:
        Human-readable label shown in alerts and the incident report.
    severity:
        CRITICAL | HIGH | MEDIUM | LOW — fed into the pipeline's
        initial ``risk_level`` hint so the Threat Analysis Agent has
        context before it even runs Nmap.
    category:
        Pre-classified threat category injected into ``AgentState``.
        The Threat Analysis Agent can refine this further.
    regex:
        Compiled pattern.  Must contain a named group ``(?P<ip>…)``
        that captures the offending IP address.
    min_risk_score:
        Minimum ``risk_score`` hinted to the pipeline for this pattern
        (0-10).  The Threat Analysis Agent will adjust upward based on
        CVE findings.
    """
    name: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    category: str
    regex: re.Pattern
    min_risk_score: int    # 0-10


# ---------------------------------------------------------------------------
# Named pattern table — evaluated in order, first match wins
# ---------------------------------------------------------------------------
# Each regex MUST contain (?P<ip>...) capturing the offending host.
# Patterns are written to match standard Linux syslog / auth.log / IDS
# log formats but also plain-text alert files.
# ---------------------------------------------------------------------------
THREAT_PATTERNS: list[ThreatPattern] = [

    # ── CRITICAL ────────────────────────────────────────────────────────
    ThreatPattern(
        name="Possible break-in attempt",
        severity="CRITICAL",
        category="Intrusion Attempt",
        min_risk_score=9,
        regex=re.compile(
            r"POSSIBLE BREAK-IN ATTEMPT.*?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="SYN flood / DoS",
        severity="CRITICAL",
        category="DoS — SYN Flood",
        min_risk_score=9,
        regex=re.compile(
            r"(?:SYN[_ ]flood|DOS[_ ]attack|possible SYN flooding)"
            r".*?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),

    # ── HIGH ─────────────────────────────────────────────────────────────
    ThreatPattern(
        name="Failed password (SSH)",
        severity="HIGH",
        category="Brute Force — SSH",
        min_risk_score=7,
        regex=re.compile(
            r"Failed password for (?:invalid user )?(?:\S+) from "
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="Invalid user (SSH)",
        severity="HIGH",
        category="Brute Force — SSH",
        min_risk_score=7,
        regex=re.compile(
            r"Invalid user \S+ from "
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="Too many authentication failures",
        severity="HIGH",
        category="Brute Force — SSH",
        min_risk_score=8,
        regex=re.compile(
            r"(?:Too many authentication failures|maximum authentication attempts exceeded)"
            r".*?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="sudo authentication failure",
        severity="HIGH",
        category="Privilege Escalation Attempt",
        min_risk_score=7,
        regex=re.compile(
            r"sudo.*?auth(?:entication)? failure.*?rhost=(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="su authentication failure",
        severity="HIGH",
        category="Privilege Escalation Attempt",
        min_risk_score=7,
        regex=re.compile(
            r"\bsu\b.*?auth(?:entication)? failure.*?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="Port scan detected (IDS/IPS)",
        severity="HIGH",
        category="Port Scan — IDS Alert",
        min_risk_score=7,
        regex=re.compile(
            r"(?:port.?scan|ET SCAN|NMAP|masscan|Nmap scan)"
            r".*?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="Repeated login failures (PAM)",
        severity="HIGH",
        category="Brute Force — PAM",
        min_risk_score=7,
        regex=re.compile(
            r"pam_unix.*?authentication failure.*?rhost=(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),

    # ── MEDIUM ───────────────────────────────────────────────────────────
    ThreatPattern(
        name="Connection reset (SSH)",
        severity="MEDIUM",
        category="Connection Anomaly — SSH",
        min_risk_score=4,
        regex=re.compile(
            r"Connection (?:reset|closed) by (?:authenticating user \S+ )?(?:invalid user \S+ )?"
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="UFW BLOCK",
        severity="MEDIUM",
        category="Firewall Block Event",
        min_risk_score=4,
        regex=re.compile(
            r"UFW BLOCK.*?SRC=(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="Disconnected (preauth)",
        severity="MEDIUM",
        category="Connection Anomaly — SSH",
        min_risk_score=3,
        regex=re.compile(
            r"Disconnected from (?:invalid user \S+ )?(?:authenticating user \S+ )?"
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}).*?preauth",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="Generic ALERT line",
        severity="MEDIUM",
        category="Security Alert (Generic)",
        min_risk_score=4,
        regex=re.compile(
            r"(?:ALERT|WARNING|INTRUSION|MALICIOUS|SUSPICIOUS|ATTACK)"
            r".*?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),

    # ── LOW ──────────────────────────────────────────────────────────────
    ThreatPattern(
        name="Accepted publickey (SSH)",
        severity="LOW",
        category="Successful Auth — SSH",
        min_risk_score=1,
        regex=re.compile(
            r"Accepted (?:publickey|password|keyboard-interactive) for \S+ from "
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    ThreatPattern(
        name="UFW ALLOW",
        severity="LOW",
        category="Firewall Allow Event",
        min_risk_score=1,
        regex=re.compile(
            r"UFW ALLOW.*?SRC=(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE,
        ),
    ),

    # ── CATCH-ALL — must be LAST ──────────────────────────────────────────
    ThreatPattern(
        name="Bare IP (catch-all)",
        severity="LOW",
        category="Network Activity",
        min_risk_score=1,
        regex=re.compile(
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        ),
    ),
]

# Severity → initial risk_level hint for the pipeline
_SEVERITY_TO_RISK_LEVEL: dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
}

# RAG query hints — give ChromaDB more semantic context than the raw line.
_THREAT_QUERY_HINTS: dict[str, str] = {
    "Possible break-in attempt": "intrusion attempt break-in brute force login abuse",
    "SYN flood / DoS": "syn flood denial of service network reconnaissance",
    "Failed password (SSH)": "ssh brute force failed password invalid user credential stuffing",
    "Invalid user (SSH)": "ssh brute force invalid user password spraying",
    "Too many authentication failures": "ssh brute force authentication failures password spraying",
    "sudo authentication failure": "privilege escalation sudo auth failure unauthorized root access",
    "su authentication failure": "privilege escalation su auth failure unauthorized root access",
    "Port scan detected (IDS/IPS)": "port scan nmap masscan network reconnaissance",
    "Repeated login failures (PAM)": "pam authentication failure brute force",
    "Connection reset (SSH)": "ssh connection anomaly probing unusual auth behaviour",
    "UFW BLOCK": "firewall block hostile source repeated denied connection",
    "Disconnected (preauth)": "ssh preauth disconnect brute force scanning",
    "Generic ALERT line": "generic security alert suspicious activity",
    "Accepted publickey (SSH)": "ssh successful authentication baseline activity",
    "UFW ALLOW": "firewall allow event benign network activity",
    "Bare IP (catch-all)": "network activity ip indicator",
}


def _confidence_from_distance(distance: object) -> float:
    """Convert a ChromaDB distance to a rough 0-1 confidence score."""
    try:
        return max(0.0, min(1.0, 1.0 - float(distance)))
    except (TypeError, ValueError):
        return 0.0


def _summarize_text(text: str, limit: int = 140) -> str:
    """Return a compact one-line summary for console output."""
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "…"

# Match result — what _match_line() returns per IP found
class _Match(NamedTuple):
    ip: str
    pattern: ThreatPattern


def _match_line(line: str) -> list[_Match]:
    """
    Run all ThreatPatterns against *line* in priority order.

    Returns a de-duplicated list of ``_Match`` named-tuples — one per
    unique, non-ignored IP — where each match carries the **first**
    (highest-priority) pattern that captured that IP.

    The catch-all pattern at the end of ``THREAT_PATTERNS`` ensures
    that any line containing a bare IP is never silently dropped.
    """
    seen_ips: set[str] = set()
    results: list[_Match] = []

    for pattern in THREAT_PATTERNS:
        for m in pattern.regex.finditer(line):
            ip = m.group("ip")
            # Validate octets
            if not _valid_ip(ip):
                continue
            # Skip ignored prefixes
            if any(ip.startswith(p) for p in _IGNORE_PREFIXES):
                continue
            # De-duplicate — keep only the first (highest-priority) match
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            results.append(_Match(ip=ip, pattern=pattern))

    return results


def _valid_ip(ip: str) -> bool:
    """Return True if all four octets are 0-255."""
    try:
        return all(0 <= int(o) <= 255 for o in ip.split("."))
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# ANSI colour helpers (for terminal readability)
# ---------------------------------------------------------------------------
_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _ts() -> str:
    """UTC timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ═══════════════════════════════════════════════════════════════════════════
# Core Monitor Class
# ═══════════════════════════════════════════════════════════════════════════
class SecurityAlertMonitor:
    """
    Watch a text file for new lines containing IP addresses and trigger
    the LangGraph cybersecurity pipeline for each one.

    Parameters
    ----------
    log_path : str
        Path to the alert log file (default: ``logs/security_alerts.txt``).
    mode : str
        ``"direct"`` to invoke the pipeline in-process, or
        ``"streamlit"`` to POST the IP to the Streamlit dashboard.
    streamlit_url : str
        Base URL for the Streamlit dashboard (only used when *mode* is
        ``"streamlit"``).
    model_name : str
        Groq model passed to the LangGraph pipeline.
    auto_approve : bool
        If ``True`` the Response Agent runs without human approval.
    cooldown : int
        Seconds to wait before re-investigating the same IP.
    dry_run : bool
        If ``True`` alerts are printed but nothing is invoked.
    """

    def __init__(
        self,
        log_path: str = DEFAULT_LOG,
        mode: str = "direct",
        streamlit_url: str = "http://localhost:8501",
        model_name: str = "llama-3.3-70b-versatile",
        auto_approve: bool = False,
        cooldown: int = 300,
        dry_run: bool = False,
    ):
        self.log_path = os.path.abspath(log_path)
        self.mode = mode
        self.streamlit_url = streamlit_url.rstrip("/")
        self.model_name = model_name
        self.auto_approve = auto_approve
        self.cooldown = cooldown
        self.dry_run = dry_run

        # Tracking state
        self._last_trigger: dict[str, float] = {}   # ip → epoch timestamp
        self._trigger_count: int = 0

        # Pipeline objects (lazy-init for direct mode)
        self._graph = None
        self._checkpointer = None
        self._checkpointer_cm = None
        self._threat_store = None
        self._threat_store_ready = False

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------
    def _print_banner(self) -> None:
        print(f"\n{_BOLD}{'=' * 65}{_RESET}")
        print(f"  {_CYAN}🔍  AUTONOMOUS SOAR — SECURITY ALERT FILE MONITOR{_RESET}")
        print(f"{'=' * 65}")
        print(f"  Log file     : {self.log_path}")
        print(f"  Mode         : {self.mode}")
        if self.mode == "streamlit":
            print(f"  Streamlit URL: {self.streamlit_url}")
        print(f"  Model        : {self.model_name}")
        print(f"  Auto-approve : {self.auto_approve}")
        print(f"  Cooldown     : {self.cooldown}s")
        print(f"  Dry run      : {self.dry_run}")
        print(f"  Patterns     : {len(THREAT_PATTERNS)} active "
              f"(auth.log / syslog / IDS alert formats)")
        print(f"  RAG intel    : pgvector threat matching enabled")
        print(f"{'=' * 65}")
        print(f"  Watching for new lines … press {_BOLD}Ctrl-C{_RESET} to stop.\n")

    # ------------------------------------------------------------------
    # Threat intel helpers
    # ------------------------------------------------------------------
    def _ensure_threat_store(self):
        """Return a pgvector threat store instance if available."""
        if self._threat_store_ready:
            return self._threat_store

        try:
            from vector_db.threat_intel_store import ThreatIntelStore
            self._threat_store = ThreatIntelStore()
            self._threat_store_ready = True
        except Exception as exc:
            print(
                f"  {_YELLOW}⚠️  pgvector threat store unavailable — "
                f"continuing without vector-DB intel ({exc}).{_RESET}"
            )
            self._threat_store = None
            self._threat_store_ready = True

        return self._threat_store

    def _build_threat_query(self, line: str, match: _Match) -> str:
        """Construct a retrieval query with behavior and IOC context."""
        hint = _THREAT_QUERY_HINTS.get(match.pattern.name, match.pattern.category)
        ips = ", ".join(_IP_RE.findall(line))
        parts = [hint, match.pattern.name, match.pattern.category, line.strip()]
        if ips:
            parts.append(f"observed IPs: {ips}")
        return " | ".join(part for part in parts if part)

    def _query_threat_intel(self, line: str, match: _Match) -> tuple[str, list[dict]]:
        """Run a semantic search against the threat-intel vector store."""
        threat_store = self._ensure_threat_store()
        if threat_store is None:
            return "", []

        query = self._build_threat_query(line, match)
        try:
            results = threat_store.query_threats(query, n_results=3)
        except Exception as exc:
            print(f"  {_YELLOW}⚠️  Threat-intel lookup failed: {exc}{_RESET}")
            return "", []

        documents = results.get("documents", [[]])
        metadatas = results.get("metadatas", [[]])
        distances = results.get("distances", [[]])

        docs = documents[0] if documents else []
        metas = metadatas[0] if metadatas else []
        dists = distances[0] if distances else []

        hits: list[dict] = []
        for doc, meta, distance in zip(docs, metas, dists):
            hits.append({
                "document": doc,
                "metadata": meta or {},
                "distance": distance,
                "confidence": _confidence_from_distance(distance),
            })

        if not hits:
            return query, []

        summary_lines = [
            f"Historical threat-intel match query: {_summarize_text(query, 180)}",
        ]
        for index, hit in enumerate(hits, 1):
            metadata = hit["metadata"]
            label = (
                metadata.get("type")
                or metadata.get("mitre_id")
                or metadata.get("category")
                or "intel"
            )
            confidence = int(hit["confidence"] * 100)
            distance = hit["distance"]
            summary_lines.append(
                f"{index}. [{label}] {_summarize_text(hit['document'], 170)} "
                f"(confidence ~{confidence}%, distance={distance})"
            )

        return "\n".join(summary_lines), hits

    # ------------------------------------------------------------------
    # Pipeline — direct invocation
    # ------------------------------------------------------------------
    def _ensure_pipeline(self) -> None:
        """Lazy-build the LangGraph pipeline (once, on first trigger)."""
        if self._graph is not None:
            return

        from checkpointer import create_postgres_checkpointer
        from main import build_graph

        self._checkpointer = create_postgres_checkpointer()
        self._graph = build_graph(model_name=self.model_name, checkpointer=self._checkpointer)

    def _build_initial_state(
        self,
        ip: str,
        line: str,
        match: _Match,
        threat_intel_context: str = "",
    ) -> dict:
        """Build the full ``AgentState`` dict for a pipeline invocation."""
        pat = match.pattern
        rag_line = f"RAG intel : {threat_intel_context}\n" if threat_intel_context else ""
        return {
            "messages": [],
            "target": ip,
            "target_ip": ip,
            "scan_results": {},
            "web_tech_results": {},
            "incident_report": (
                f"[Autonomous Monitor — {pat.name}]\n"
                f"Timestamp  : {_ts()}\n"
                f"Severity   : {pat.severity}\n"
                f"Category   : {pat.category}\n"
                f"Source IP  : {ip}\n"
                f"Trigger    : {line.strip()}\n"
                f"{rag_line}"
            ),
            "log_data": line.strip(),
            "threat_analysis": {},
            "threat_analysis_report": "",
            "threat_summary": "",
            "threat_detected": False,
            "threat_intel_context": threat_intel_context,
            "response_plan": "",
            "risk_level": _SEVERITY_TO_RISK_LEVEL[pat.severity],
            "risk_score": pat.min_risk_score,
            "category": pat.category,
            "final_decision": "",
            "final_remediation_plan": "",
            "stealth_mode": False,
            "dry_run": True,
            "execution_results": [],
            "current_agent": "",
        }

    def _invoke_direct(
        self,
        ip: str,
        line: str,
        match: _Match,
        threat_intel_context: str = "",
    ) -> None:
        """Invoke the LangGraph pipeline directly in-process."""
        self._ensure_pipeline()

        thread_id = f"file-monitor-{ip}-{int(time.time())}"
        config = {"configurable": {"thread_id": thread_id}}
        initial_state = self._build_initial_state(
            ip,
            line,
            match,
            threat_intel_context=threat_intel_context,
        )

        print(f"\n  {'🚀' * 3}  Launching pipeline for {_BOLD}{ip}{_RESET}")
        print(f"    Thread ID : {thread_id}")

        try:
            final_state = self._graph.invoke(initial_state, config)

            # Handle human-in-the-loop pause
            if not self.auto_approve:
                graph_state = self._graph.get_state(config)
                while graph_state.next and "human_review" in graph_state.next:
                    paused = graph_state.values
                    risk  = paused.get("risk_score", 0)
                    level = paused.get("risk_level", "UNKNOWN")
                    print(f"\n  ⏸️   Pipeline paused — risk {risk}/10 ({level})")
                    answer = input("  👤  Approve Response Agent? (y/n): ").strip().lower()
                    if answer in ("y", "yes"):
                        print(f"  {_GREEN}✅  Approved — resuming …{_RESET}")
                        final_state = self._graph.invoke(None, config)
                    else:
                        print(f"  {_RED}❌  Rejected — skipping Response Agent.{_RESET}")
                        self._graph.update_state(
                            config,
                            {
                                "final_decision": "Rejected by Human Operator",
                                "response_plan": "",
                                "final_remediation_plan": "",
                                "current_agent": "human_review",
                            },
                            as_node="human_review",
                        )
                        final_state = self._graph.get_state(config).values
                    graph_state = self._graph.get_state(config)

            # Print the report
            from main import print_report
            print_report(final_state)

            # Persist incident artefacts
            try:
                from incident_io import save_incident
                save_incident(thread_id, final_state)
                from tools.report_generator import save_incident_bundle
                save_incident_bundle(final_state, thread_id)
            except Exception as exc:
                print(f"  {_YELLOW}⚠️  Could not save incident: {exc}{_RESET}")

        except Exception as exc:
            print(f"  {_RED}❌  Pipeline error for {ip}: {exc}{_RESET}")

    # ------------------------------------------------------------------
    # Pipeline — Streamlit HTTP trigger
    # ------------------------------------------------------------------
    def _invoke_streamlit(
        self,
        ip: str,
        line: str,
        match: _Match,
        threat_intel_context: str = "",
        threat_intel_hits: list[dict] | None = None,
    ) -> None:
        """
        POST the IP to the Streamlit dashboard.

        This sends a simple JSON payload to a lightweight webhook
        endpoint.  If Streamlit is not running or doesn't expose an
        API route, the request will fail gracefully.
        """
        import requests

        payload = {
            "target_ip": ip,
            "trigger_line": line.strip(),
            "timestamp": _ts(),
            "source": "file_monitor",
            "pattern_name": match.pattern.name,
            "severity": match.pattern.severity,
            "category": match.pattern.category,
            "threat_intel_context": threat_intel_context,
            "threat_intel_hits": threat_intel_hits or [],
        }

        # Try the Streamlit webhook endpoint
        url = f"{self.streamlit_url}/api/trigger_scan"
        print(f"\n  📡  POSTing to Streamlit: {url}")
        print(f"    Payload: {json.dumps(payload, indent=2)}")

        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                print(f"  {_GREEN}✅  Streamlit accepted the scan request.{_RESET}")
                try:
                    body = resp.json()
                    print(f"    Response: {json.dumps(body, indent=2)}")
                except Exception:
                    print(f"    Response: {resp.text[:200]}")
            else:
                print(f"  {_YELLOW}⚠️  Streamlit returned HTTP {resp.status_code}.{_RESET}")
                print(f"    Body: {resp.text[:300]}")
                # Fall back to direct invocation
                print(f"  {_CYAN}↩️  Falling back to direct pipeline invocation …{_RESET}")
                self._invoke_direct(
                    ip,
                    line,
                    match,
                    threat_intel_context=threat_intel_context,
                )
        except requests.ConnectionError:
            print(f"  {_YELLOW}⚠️  Cannot reach Streamlit at {self.streamlit_url}.{_RESET}")
            print(f"  {_CYAN}↩️  Falling back to direct pipeline invocation …{_RESET}")
            self._invoke_direct(
                ip,
                line,
                match,
                threat_intel_context=threat_intel_context,
            )
        except Exception as exc:
            print(f"  {_RED}❌  HTTP request failed: {exc}{_RESET}")
            print(f"  {_CYAN}↩️  Falling back to direct pipeline invocation …{_RESET}")
            self._invoke_direct(
                ip,
                line,
                match,
                threat_intel_context=threat_intel_context,
            )

    # ------------------------------------------------------------------
    # IP extraction + cooldown
    # ------------------------------------------------------------------
    def _extract_ips(self, line: str) -> list[str]:
        """Backward-compat wrapper — returns plain IPs via _match_line()."""
        return [m.ip for m in _match_line(line)]

    def _is_on_cooldown(self, ip: str) -> bool:
        last = self._last_trigger.get(ip)
        if last is None:
            return False
        return (time.time() - last) < self.cooldown

    def _record_trigger(self, ip: str) -> None:
        self._last_trigger[ip] = time.time()
        self._trigger_count += 1

    # ------------------------------------------------------------------
    # Process a single new line
    # ------------------------------------------------------------------
    def _process_line(self, line: str) -> None:
        """Check a new line for threat patterns and trigger the appropriate action."""
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return  # skip blanks and comments

        matches = _match_line(stripped)
        if not matches:
            return  # no actionable IP in this line

        for match in matches:
            ip = match.ip
            if self._is_on_cooldown(ip):
                print(f"  {_YELLOW}⏳  {ip} is on cooldown — skipping.{_RESET}")
                continue

            self._record_trigger(ip)

            threat_intel_context, threat_intel_hits = self._query_threat_intel(stripped, match)
            if threat_intel_hits:
                top_hit = threat_intel_hits[0]
                top_meta = top_hit["metadata"]
                top_label = (
                    top_meta.get("type")
                    or top_meta.get("mitre_id")
                    or top_meta.get("category")
                    or "historical attack"
                )
                top_confidence = int(top_hit["confidence"] * 100)
                intel_line = f"RAG-confirmed against {top_label} (~{top_confidence}% confidence)"
            elif match.pattern.name != "Bare IP (catch-all)":
                intel_line = "No strong historical intel hit; regex signal still elevated the alert"
            else:
                print(
                    f"  {_YELLOW}ℹ️  Bare IP matched, but no historical IOC or behavior match was found."
                    f"{_RESET}"
                )
                continue

            # Severity-based colour
            sev = match.pattern.severity
            sev_colour = (
                _RED    if sev == "CRITICAL" else
                _YELLOW if sev == "HIGH"     else
                _CYAN   if sev == "MEDIUM"   else
                _GREEN
            )

            print(f"\n  {_RED}🚨  ALERT #{self._trigger_count}{_RESET}  "
                  f"[{_ts()}]")
            print(f"    IP       : {_BOLD}{ip}{_RESET}")
            print(f"    Pattern  : {match.pattern.name}  "
                  f"[{sev_colour}{sev}{_RESET}]")
            print(f"    Category : {match.pattern.category}")
            print(f"    Risk hint: {match.pattern.min_risk_score}/10")
            print(f"    Intel    : {intel_line}")
            print(f"    Line     : {stripped[:120]}")
            if threat_intel_context:
                print(f"    RAG      : {_summarize_text(threat_intel_context, 120)}")

            if self.dry_run:
                print(f"    {_YELLOW}(dry-run mode — pipeline NOT invoked){_RESET}")
                continue

            if self.mode == "streamlit":
                self._invoke_streamlit(
                    ip,
                    stripped,
                    match,
                    threat_intel_context=threat_intel_context,
                    threat_intel_hits=threat_intel_hits,
                )
            else:
                self._invoke_direct(
                    ip,
                    stripped,
                    match,
                    threat_intel_context=threat_intel_context,
                )

    # ------------------------------------------------------------------
    # File-watching strategies
    # ------------------------------------------------------------------
    def _tail_polling(self) -> None:
        """
        Simple ``while True`` polling loop — works everywhere, no
        dependencies beyond the standard library.
        """
        print(f"  {_CYAN}📂  Using polling mode (0.5 s interval).{_RESET}\n")

        # Wait for the file to appear
        while not os.path.exists(self.log_path):
            print(f"  Waiting for {self.log_path} to appear …")
            time.sleep(2)

        inode = os.stat(self.log_path).st_ino
        fh = open(self.log_path, "r")
        # Seek to end — only process NEW lines appended after start
        fh.seek(0, 2)

        try:
            while True:
                line = fh.readline()
                if line:
                    self._process_line(line)
                else:
                    # Check for log rotation / truncation
                    try:
                        current_inode = os.stat(self.log_path).st_ino
                    except FileNotFoundError:
                        time.sleep(1)
                        continue
                    if current_inode != inode:
                        print(f"  {_CYAN}🔄  File rotated — reopening.{_RESET}")
                        fh.close()
                        fh = open(self.log_path, "r")
                        inode = current_inode
                    else:
                        time.sleep(0.5)
        finally:
            fh.close()

    def _tail_watchdog(self) -> None:
        """
        Use the ``watchdog`` library for efficient filesystem event
        notifications.  Falls back to polling if watchdog is unavailable.
        """
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            print(f"  {_YELLOW}⚠️  watchdog not installed — "
                  f"falling back to polling.{_RESET}")
            return self._tail_polling()

        print(f"  {_GREEN}📂  Using watchdog file-system notifications.{_RESET}\n")

        # Ensure the file exists before starting
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        if not os.path.exists(self.log_path):
            with open(self.log_path, "w") as f:
                f.write("")

        monitor = self  # reference for the inner class

        class _Handler(FileSystemEventHandler):
            """React to modifications of the watched file."""

            def __init__(self):
                super().__init__()
                self._fh = open(monitor.log_path, "r")
                # Start at the end so we only see new content
                self._fh.seek(0, 2)

            def on_modified(self, event):
                if event.is_directory:
                    return
                # Only react to changes to our specific file
                if os.path.abspath(event.src_path) != monitor.log_path:
                    return
                # Read all new lines
                while True:
                    line = self._fh.readline()
                    if not line:
                        break
                    monitor._process_line(line)

            def close(self):
                self._fh.close()

        handler = _Handler()
        observer = Observer()
        # Watch the directory containing the file
        watch_dir = os.path.dirname(self.log_path)
        observer.schedule(handler, watch_dir, recursive=False)
        observer.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            observer.stop()
            observer.join()
            handler.close()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def watch(self) -> None:
        """
        Start watching the log file.  Uses watchdog if available,
        otherwise falls back to polling.
        """
        self._print_banner()

        try:
            self._tail_watchdog()
        except KeyboardInterrupt:
            pass
        finally:
            print(f"\n\n  {_BOLD}[Monitor] Stopped. "
                  f"Processed {self._trigger_count} alert(s). Goodbye 👋{_RESET}\n")
            # PostgreSQL checkpointer does not require context-manager teardown here.


# ═══════════════════════════════════════════════════════════════════════════
# Pattern self-test helper
# ═══════════════════════════════════════════════════════════════════════════
def _run_pattern_test(line: str) -> None:
    """
    Run the ThreatPattern engine against *line* and print every match.
    Exits without starting any file watcher or pipeline.

    Usage::

        python monitor.py --pattern-test "Failed password for root from 10.0.0.50 port 22"
    """
    print(f"\n{_BOLD}{'─' * 65}{_RESET}")
    print(f"  {_CYAN}🧪  PATTERN TEST MODE{_RESET}")
    print(f"{'─' * 65}")
    print(f"  Input : {line}")
    print(f"{'─' * 65}")

    matches = _match_line(line)
    if not matches:
        print(f"  {_YELLOW}⚠️  No patterns matched — no actionable IP found.{_RESET}\n")
        return

    for i, match in enumerate(matches, 1):
        sev = match.pattern.severity
        sev_colour = (
            _RED    if sev == "CRITICAL" else
            _YELLOW if sev == "HIGH"     else
            _CYAN   if sev == "MEDIUM"   else
            _GREEN
        )
        print(f"\n  Match #{i}")
        print(f"    IP           : {_BOLD}{match.ip}{_RESET}")
        print(f"    Pattern      : {match.pattern.name}")
        print(f"    Severity     : {sev_colour}{sev}{_RESET}")
        print(f"    Category     : {match.pattern.category}")
        print(f"    Min risk     : {match.pattern.min_risk_score}/10")
        print(f"    Risk level   : {_SEVERITY_TO_RISK_LEVEL[sev]}")

    print(f"\n{'─' * 65}")
    print(f"  Total matches: {len(matches)}\n")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Autonomous SOAR file monitor — watches auth.log / syslog / "
            "alert files for known attack patterns and triggers the "
            "LangGraph cybersecurity pipeline (Recon → Threat Analysis → Response)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python monitor.py --auth-log                          # watch logs/auth.log\n"
            "  python monitor.py --auth-log --dry-run                # print alerts only\n"
            "  python monitor.py --file /var/log/syslog              # custom file\n"
            "  python monitor.py --mode streamlit                    # POST to Streamlit\n"
            "  python monitor.py --auto-approve                      # skip human gate\n"
            "  python monitor.py --cooldown 60                       # 60-s re-trigger window\n"
            "  python monitor.py --pattern-test 'Failed password for root from 10.0.0.50 port 22'\n"
        ),
    )

    # ── File selection ──────────────────────────────────────────────────
    file_group = parser.add_mutually_exclusive_group()
    file_group.add_argument(
        "--file", "-f",
        default=None,
        help=(
            "Path to the alert log file to watch "
            f"(default: {DEFAULT_LOG})"
        ),
    )
    file_group.add_argument(
        "--auth-log",
        action="store_true",
        help=f"Convenience flag — watch {DEFAULT_AUTH_LOG} (auth.log / SSH brute-force, sudo, PAM).",
    )

    # ── Self-test mode ──────────────────────────────────────────────────
    parser.add_argument(
        "--pattern-test",
        metavar="LINE",
        default=None,
        help=(
            "Test mode: run the pattern engine against a single log line "
            "and print all matches, then exit (no file watching, no pipeline)."
        ),
    )

    # ── Pipeline options ────────────────────────────────────────────────
    parser.add_argument(
        "--mode",
        choices=["direct", "streamlit"],
        default="direct",
        help=(
            "How to trigger the pipeline: 'direct' invokes graph.invoke() "
            "in-process; 'streamlit' POSTs to the dashboard (default: direct)."
        ),
    )
    parser.add_argument(
        "--streamlit-url",
        default="http://localhost:8501",
        help="Base URL for the Streamlit dashboard (default: http://localhost:8501).",
    )
    parser.add_argument(
        "--model", "-m",
        default=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        help="Groq model name (default: llama-3.3-70b-versatile).",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Skip human-in-the-loop; let the Response Agent run automatically.",
    )
    parser.add_argument(
        "--cooldown", "-c",
        type=int,
        default=300,
        help="Seconds before re-investigating the same IP (default: 300).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print alerts but do NOT invoke the pipeline.",
    )

    args = parser.parse_args()

    # ── --pattern-test self-test mode ───────────────────────────────────
    if args.pattern_test is not None:
        _run_pattern_test(args.pattern_test)
        return

    # ── Resolve log file path ───────────────────────────────────────────
    if args.auth_log:
        log_path = DEFAULT_AUTH_LOG
    elif args.file:
        log_path = args.file
    else:
        log_path = DEFAULT_LOG

    monitor = SecurityAlertMonitor(
        log_path=log_path,
        mode=args.mode,
        streamlit_url=args.streamlit_url,
        model_name=args.model,
        auto_approve=args.auto_approve,
        cooldown=args.cooldown,
        dry_run=args.dry_run,
    )
    monitor.watch()


if __name__ == "__main__":
    main()
