"""
Investigate Node — Vulnerability Assessment
=============================================
The second node in the 4-step specialist pipeline.  Only runs when
the Monitor node detects an anomaly (``threat_detected = True``).

Composes the existing **Recon Agent** (Nmap tool-calling) and
**Threat Analysis Agent** (CVE correlation, MITRE mapping) into a
single sequential operation, then sets the ``is_vulnerable`` flag.

Responsibilities:
    1. Run the Recon Agent to do Nmap scanning + web-tech fingerprinting.
    2. Feed results to the Threat Analysis Agent for CVE correlation.
    3. Set ``is_vulnerable = True`` when ``risk_score >= 7`` (HIGH/CRITICAL).
    4. Append investigation reasoning to ``incident_logs``.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage
from agents.state import AgentState
from agents.recon_agent import create_recon_agent
from agents.threat_analysis_agent import create_threat_analysis_agent
from config import settings

if TYPE_CHECKING:
    from vector_db.threat_intel_store import ThreatIntelStore

# Risk score threshold at or above which we consider the target vulnerable
_VULNERABLE_THRESHOLD = 7


def create_investigate_node(
    model_name: str | None = None,
    threat_store: "ThreatIntelStore | None" = None,
):
    """
    Create the Investigate node function.

    Internally composes the existing Recon and Threat Analysis agents
    into a single LangGraph node that runs them sequentially.

    Args:
        model_name: Groq model for both agents.
        threat_store: ChromaDB threat intel store for the Threat Analyzer.

    Returns:
        A function usable as a LangGraph node.
    """
    # Create the two internal agent functions
    resolved_model = model_name or os.getenv("GROQ_MODEL_MAIN", settings.groq_model_main)
    recon_fn = create_recon_agent(resolved_model)
    threat_fn = create_threat_analysis_agent(resolved_model, threat_store)

    def investigate_node(state: AgentState) -> dict:
        """
        Composite investigation: Recon scan → Threat Analysis → is_vulnerable.

        1. Run Nmap via the Recon Agent.
        2. Merge recon results into state.
        3. Run the Threat Analysis Agent on the merged state.
        4. Determine ``is_vulnerable`` from the risk score.
        5. Append reasoning to ``incident_logs``.
        """
        target_ip = state.get("target_ip") or state.get("target", "127.0.0.1")
        incident_logs: list[str] = list(state.get("incident_logs", []) or [])

        print(f"\n{'='*60}")
        print(f"[Investigate Node] Starting vulnerability assessment")
        print(f"[Investigate Node] Target: {target_ip}")
        print(f"{'='*60}")

        incident_logs.append(
            f"[Investigate] Starting Nmap scan and threat analysis on {target_ip}."
        )

        # ── Step 1: Run the Recon Agent ──────────────────────────────
        print("\n[Investigate Node] Phase 1: Running Recon Agent…")
        recon_result = recon_fn(state)

        # Merge recon results into a working copy of state for the
        # Threat Analysis Agent.  We build a new dict that overlays
        # the recon output on top of the current state.
        merged_state = dict(state)
        merged_state.update(recon_result)

        incident_logs.append(
            f"[Investigate] Recon complete — "
            f"scan output: {len(recon_result.get('scan_results', {}).get('raw_output', ''))} chars."
        )

        # ── Step 2: Run the Threat Analysis Agent ────────────────────
        print("\n[Investigate Node] Phase 2: Running Threat Analysis Agent…")
        threat_result = threat_fn(merged_state)

        # Extract the key outputs from threat analysis
        risk_score = threat_result.get("risk_score", 0)
        risk_level = threat_result.get("risk_level", "LOW")
        category = threat_result.get("category", "")
        threat_detected = threat_result.get("threat_detected", False)

        # ── Step 3: Set is_vulnerable flag ───────────────────────────
        is_vulnerable = risk_score >= _VULNERABLE_THRESHOLD

        incident_logs.append(
            f"[Investigate] Threat analysis complete — "
            f"risk_score={risk_score}/10, risk_level={risk_level}, "
            f"category={category}, is_vulnerable={is_vulnerable}."
        )

        print(f"\n[Investigate Node] Risk score: {risk_score}/10 ({risk_level})")
        print(f"[Investigate Node] Category: {category}")
        print(f"[Investigate Node] is_vulnerable: {is_vulnerable}")
        print(f"[Investigate Node] threat_detected (analysis): {threat_detected}")

        # ── Step 4: Merge all results ────────────────────────────────
        # Combine messages from both agents
        combined_messages = []
        if recon_result.get("messages"):
            combined_messages.extend(recon_result["messages"])
        if threat_result.get("messages"):
            combined_messages.extend(threat_result["messages"])

        return {
            # From recon
            "target_ip": recon_result.get("target_ip", target_ip),
            "scan_results": recon_result.get("scan_results", {}),
            "web_tech_results": recon_result.get("web_tech_results", {}),
            # From threat analysis
            "threat_analysis": threat_result.get("threat_analysis", {}),
            "threat_analysis_report": threat_result.get("threat_analysis_report", ""),
            "threat_summary": threat_result.get("threat_summary", ""),
            "threat_detected": threat_detected,
            "threat_intel_context": threat_result.get("threat_intel_context", ""),
            "risk_level": risk_level,
            "risk_score": risk_score,
            "category": category,
            # This node's outputs
            "is_vulnerable": is_vulnerable,
            "incident_logs": incident_logs,
            "incident_report": threat_result.get("incident_report", ""),
            "messages": combined_messages,
            "current_agent": "investigate",
        }

    return investigate_node
