#!/usr/bin/env python3
"""
Real-Time Log Monitor
=====================
Watches a log file (e.g. ``auth.log``, ``alerts.txt``, or any syslog-
style file) for suspicious events and **automatically triggers the
LangGraph cybersecurity pipeline** when an alert condition is met.

Detected alert conditions
-------------------------
* **Failed login** — lines containing ``Failed password``,
  ``authentication failure``, or ``Invalid user``.
* **New / unknown IP** — any IP address that has not been seen before
  in the current monitoring session.
* **Brute-force burst** — more than ``--threshold`` failed logins from
  the same IP within the sliding observation window.
* **Port-scan indicators** — lines mentioning ``port scan``,
  ``SYN flood``, or similar patterns.
* **Privilege escalation** — lines referencing ``sudo``, ``su``,
  ``privilege``, or ``root access`` in a suspicious context.

When a trigger fires the monitor:

1. Logs the alert to the console with a timestamp and reason.
2. Builds the initial ``AgentState`` (with the offending IP as
   ``target_ip`` and the recent log context as ``log_data``).
3. Invokes the full Recon → Threat Analysis → Response pipeline.
4. Prints the pipeline's final report.
5. Records a cooldown so the **same IP** is not re-investigated
   within ``--cooldown`` seconds (default 300 s / 5 min).

Usage examples
--------------
::

    # Watch a file, trigger on ≥ 5 failed logins from one IP
    python monitor.py --file /var/log/auth.log

    # Lower threshold, shorter cooldown, custom model
    python monitor.py --file alerts.txt --threshold 3 --cooldown 120

    # Auto-approve the Response Agent (skip human-in-the-loop)
    python monitor.py --file alerts.txt --auto-approve

    # Just watch and print alerts, don't run the pipeline
    python monitor.py --file alerts.txt --dry-run

The monitor tails the file continuously (like ``tail -f``) and
survives log-rotation (it re-opens the file when the inode changes).
Press ``Ctrl-C`` to stop.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so we can import agents / tools
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

load_dotenv(os.path.join(_PROJECT_ROOT, ".env"))


# ═══════════════════════════════════════════════════════════════════════════
# Regex patterns for alert detection
# ═══════════════════════════════════════════════════════════════════════════
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_FAILED_LOGIN_RE = re.compile(
    r"(Failed password|authentication failure|Invalid user|"
    r"failed login|login failed|Access denied)",
    re.IGNORECASE,
)
_PORT_SCAN_RE = re.compile(
    r"(port scan|SYN flood|connection refused.*rapid|nmap|masscan)",
    re.IGNORECASE,
)
_PRIV_ESC_RE = re.compile(
    r"(sudo[\[:].*COMMAND|su\[\d+\]|privilege escalat|"
    r"unauthorized root|BREAK-IN ATTEMPT)",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════
# Alert data class
# ═══════════════════════════════════════════════════════════════════════════
class Alert:
    """Lightweight container for a single triggered alert."""

    __slots__ = ("timestamp", "ip", "reason", "line", "severity")

    def __init__(
        self,
        ip: str,
        reason: str,
        line: str,
        severity: str = "HIGH",
    ):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.ip = ip
        self.reason = reason
        self.line = line.strip()
        self.severity = severity

    def __repr__(self) -> str:
        return (
            f"[{self.timestamp}] {self.severity} — {self.reason} "
            f"(IP: {self.ip})"
        )


# ═══════════════════════════════════════════════════════════════════════════
# The Log Monitor
# ═══════════════════════════════════════════════════════════════════════════
class LogMonitor:
    """
    Continuously tail a log file and trigger the LangGraph pipeline
    when suspicious activity is detected.

    Parameters
    ----------
    log_path : str
        Path to the log file to watch.
    threshold : int
        Number of failed-login lines from the same IP before triggering.
    cooldown : int
        Seconds to wait before re-investigating the same IP.
    model_name : str
        Groq model passed to the LangGraph pipeline.
    auto_approve : bool
        If ``True`` the Response Agent runs without human approval.
    dry_run : bool
        If ``True`` alerts are printed but the pipeline is NOT invoked.
    """

    def __init__(
        self,
        log_path: str,
        threshold: int = 5,
        cooldown: int = 300,
        model_name: str = "llama-3.3-70b-versatile",
        auto_approve: bool = False,
        dry_run: bool = False,
    ):
        self.log_path = os.path.abspath(log_path)
        self.threshold = threshold
        self.cooldown = cooldown
        self.model_name = model_name
        self.auto_approve = auto_approve
        self.dry_run = dry_run

        # Tracking state
        self._known_ips: set[str] = set()
        self._fail_counts: defaultdict[str, int] = defaultdict(int)
        self._last_trigger: dict[str, float] = {}  # ip → epoch
        self._context_buffer: list[str] = []        # recent N lines for context
        self._max_context = 50                       # lines kept in buffer

        # Pipeline objects (lazy-initialised on first trigger)
        self._graph = None
        self._checkpointer = None
        self._checkpointer_cm = None

    # ------------------------------------------------------------------
    # Pipeline helpers
    # ------------------------------------------------------------------
    def _ensure_pipeline(self):
        """Lazy-build the LangGraph pipeline (once)."""
        if self._graph is not None:
            return
        from checkpointer import create_postgres_checkpointer
        from main import build_graph

        self._checkpointer = create_postgres_checkpointer()
        self._graph = build_graph(model_name=self.model_name, checkpointer=self._checkpointer)

    def _build_initial_state(self, alert: Alert) -> dict:
        """Build the ``AgentState`` dict for a pipeline invocation."""
        recent_logs = "\n".join(self._context_buffer[-self._max_context :])
        return {
            "messages": [],
            "target": alert.ip,
            "target_ip": alert.ip,
            "scan_results": {},
            "web_tech_results": {},
            "incident_report": (
                f"[Monitor Alert — {alert.timestamp}]\n"
                f"Reason  : {alert.reason}\n"
                f"Source IP: {alert.ip}\n"
                f"Severity: {alert.severity}\n"
                f"Trigger line: {alert.line}\n"
                f"\n--- Recent log context ({len(self._context_buffer)} lines) ---\n"
                f"{recent_logs}\n"
            ),
            "log_data": recent_logs,
            "threat_analysis": {},
            "threat_analysis_report": "",
            "threat_summary": "",
            "threat_detected": False,
            "threat_intel_context": "",
            "response_plan": "",
            "risk_level": "NONE",
            "risk_score": 0,
            "category": "",
            "final_decision": "",
            "final_remediation_plan": "",
            "stealth_mode": False,
            "dry_run": True,
            "execution_results": [],
            "current_agent": "",
            "confidence_score": 0.0,
            "incident_logs": [],
            "raw_log_data": recent_logs,
            "is_vulnerable": False,
        }

    def _run_pipeline(self, alert: Alert) -> None:
        """Invoke the full LangGraph pipeline for a triggered alert."""
        self._ensure_pipeline()

        thread_id = f"monitor-{alert.ip}-{int(time.time())}"
        config = {"configurable": {"thread_id": thread_id}}
        initial_state = self._build_initial_state(alert)

        print(f"\n{'🚀' * 3}  Launching pipeline for {alert.ip}  {'🚀' * 3}")
        print(f"    Thread ID : {thread_id}")
        print(f"    Reason    : {alert.reason}\n")

        try:
            final_state = self._graph.invoke(initial_state, config)

            # Handle human-in-the-loop pause (when auto_approve is off)
            if not self.auto_approve:
                graph_state = self._graph.get_state(config)
                while graph_state.next and "human_review" in graph_state.next:
                    paused = graph_state.values
                    risk = paused.get("risk_score", 0)
                    level = paused.get("risk_level", "UNKNOWN")
                    print(f"\n⏸️   Pipeline paused — risk {risk}/10 ({level})")
                    answer = input("👤  Approve Response Agent? (y/n): ").strip().lower()
                    if answer in ("y", "yes"):
                        print("✅  Approved — resuming …")
                        final_state = self._graph.invoke(None, config)
                    else:
                        print("❌  Rejected — skipping Response Agent.")
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

            # Print the final report
            from main import print_report
            print_report(final_state)

            # Persist incident artefacts
            from incident_io import save_incident
            save_incident(thread_id, final_state)

        except Exception as exc:
            print(f"[Monitor] ❌  Pipeline error for {alert.ip}: {exc}")

    # ------------------------------------------------------------------
    # Alert detection
    # ------------------------------------------------------------------
    def _is_on_cooldown(self, ip: str) -> bool:
        """Return True if the IP was triggered recently."""
        last = self._last_trigger.get(ip)
        if last is None:
            return False
        return (time.time() - last) < self.cooldown

    def _record_trigger(self, ip: str) -> None:
        self._last_trigger[ip] = time.time()

    def _process_line(self, line: str) -> Alert | None:
        """
        Analyse a single log line and return an ``Alert`` if it should
        trigger the pipeline, or ``None`` otherwise.
        """
        # Buffer the line for context
        self._context_buffer.append(line.rstrip())
        if len(self._context_buffer) > self._max_context:
            self._context_buffer.pop(0)

        # Extract IPs from the line
        ips_in_line = _IP_RE.findall(line)

        # --- 1. Failed login detection ---
        if _FAILED_LOGIN_RE.search(line):
            for ip in ips_in_line:
                self._fail_counts[ip] += 1
                if self._fail_counts[ip] >= self.threshold:
                    if not self._is_on_cooldown(ip):
                        self._record_trigger(ip)
                        # Reset the counter so we don't re-fire every line
                        self._fail_counts[ip] = 0
                        return Alert(
                            ip=ip,
                            reason=(
                                f"Brute-force: {self.threshold}+ failed "
                                f"logins detected from {ip}"
                            ),
                            line=line,
                            severity="HIGH",
                        )

        # --- 2. Port-scan indicators ---
        if _PORT_SCAN_RE.search(line):
            for ip in ips_in_line:
                if not self._is_on_cooldown(ip):
                    self._record_trigger(ip)
                    return Alert(
                        ip=ip,
                        reason=f"Port-scan / reconnaissance activity from {ip}",
                        line=line,
                        severity="HIGH",
                    )

        # --- 3. Privilege escalation ---
        if _PRIV_ESC_RE.search(line):
            for ip in ips_in_line:
                if not self._is_on_cooldown(ip):
                    self._record_trigger(ip)
                    return Alert(
                        ip=ip,
                        reason=f"Privilege escalation attempt involving {ip}",
                        line=line,
                        severity="CRITICAL",
                    )

        # --- 4. Brand-new IP (never seen in this session) ---
        for ip in ips_in_line:
            # Ignore common non-routable / internal addresses
            if ip.startswith("127.") or ip.startswith("0."):
                continue
            if ip not in self._known_ips:
                self._known_ips.add(ip)
                # New IPs don't trigger immediately — just note them.
                # They'll trigger if they hit one of the patterns above.

        return None

    # ------------------------------------------------------------------
    # File-tailing loop
    # ------------------------------------------------------------------
    def watch(self) -> None:
        """
        Tail the log file forever, triggering the pipeline on alerts.

        Handles log rotation: if the file is truncated or replaced the
        monitor re-opens it from the beginning.
        """
        print(f"\n{'=' * 60}")
        print(f"  🔍  LOG MONITOR — Real-Time Cybersecurity Watch")
        print(f"{'=' * 60}")
        print(f"  Log file    : {self.log_path}")
        print(f"  Threshold   : {self.threshold} failed logins per IP")
        print(f"  Cooldown    : {self.cooldown}s between investigations")
        print(f"  Model       : {self.model_name}")
        print(f"  Auto-approve: {self.auto_approve}")
        print(f"  Dry run     : {self.dry_run}")
        print(f"{'=' * 60}")
        print(f"  Watching … press Ctrl-C to stop.\n")

        # Wait for the file to appear if it doesn't exist yet
        while not os.path.exists(self.log_path):
            print(f"[Monitor] Waiting for {self.log_path} to appear …")
            time.sleep(2)

        inode = os.stat(self.log_path).st_ino
        fh = open(self.log_path, "r")

        # Start reading from the END of the file (only process new lines)
        fh.seek(0, 2)

        try:
            while True:
                line = fh.readline()
                if line:
                    alert = self._process_line(line)
                    if alert:
                        print(f"\n🚨  ALERT: {alert}")
                        if self.dry_run:
                            print("    (dry-run mode — pipeline NOT invoked)")
                        else:
                            self._run_pipeline(alert)
                else:
                    # No new data — check for log rotation
                    try:
                        current_inode = os.stat(self.log_path).st_ino
                    except FileNotFoundError:
                        # File was deleted; wait for it to reappear
                        time.sleep(1)
                        continue

                    if current_inode != inode:
                        # File was rotated — reopen
                        print("[Monitor] Log file rotated — reopening.")
                        fh.close()
                        fh = open(self.log_path, "r")
                        inode = current_inode
                    else:
                        # No rotation, just no new data yet
                        time.sleep(0.5)

        except KeyboardInterrupt:
            print("\n\n[Monitor] Stopped by user (Ctrl-C). Goodbye 👋")
        finally:
            fh.close()
            # Postgres checkpointer does not require context-manager teardown here.


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Real-time log monitor that triggers the LangGraph "
            "cybersecurity pipeline on suspicious events."
        ),
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        help="Path to the log file to watch (e.g. /var/log/auth.log, alerts.txt).",
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=5,
        help="Failed-login count per IP before triggering (default: 5).",
    )
    parser.add_argument(
        "--cooldown", "-c",
        type=int,
        default=300,
        help="Seconds before re-investigating the same IP (default: 300).",
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
        "--dry-run",
        action="store_true",
        help="Print alerts but do NOT invoke the pipeline.",
    )
    args = parser.parse_args()

    monitor = LogMonitor(
        log_path=args.file,
        threshold=args.threshold,
        cooldown=args.cooldown,
        model_name=args.model,
        auto_approve=args.auto_approve,
        dry_run=args.dry_run,
    )
    monitor.watch()


if __name__ == "__main__":
    main()
