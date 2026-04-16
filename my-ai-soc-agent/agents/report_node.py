"""
Report Node — Structured Post-Mortem
======================================
The final node in the 4-step specialist pipeline.  Always runs,
regardless of whether a threat was found.

Responsibilities:
    1. Collect all ``incident_logs`` entries accumulated by previous nodes.
    2. Ask the LLM to generate a structured post-mortem summary.
    3. Store the result in ``incident_report``.
    4. Call ``save_incident_bundle()`` to persist artefacts to disk.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agents.state import AgentState
from config import settings


REPORT_SYSTEM_PROMPT = """\
You are a cybersecurity incident report writer.

You are given:
- The target IP address.
- Risk score, risk level, and threat category from the analysis.
- A chronological log of all agent reasoning steps (incident_logs).
- The full incident report accumulated during the pipeline.

Your job is to produce a **structured post-mortem report** with these exact sections:

### EXECUTIVE SUMMARY
2-3 sentences summarising the incident for management.

### TIMELINE OF EVENTS
A numbered, chronological list of key events derived from the incident logs.

### FINDINGS
- Vulnerabilities discovered (if any)
- Threat intelligence correlations (if any)
- Risk assessment and categorization

### ACTIONS TAKEN
- Remediation commands executed (or simulated)
- API-based defensive controls triggered
- Human approval decisions

### RECOMMENDATIONS
- Short-term improvements (next 24 hours)
- Long-term hardening (next 7 days)

### STATUS
Final status of the incident (Resolved / Mitigated / Monitoring / No Action Required).

End your response with:
POST_MORTEM_COMPLETE
"""


def create_report_node(model_name: str | None = None):
    """
    Create the Report node function.

    Args:
        model_name: Groq model for report generation.

    Returns:
        A function usable as a LangGraph node.
    """
    resolved_model = model_name or os.getenv("GROQ_MODEL_MAIN", settings.groq_model_main)
    groq_api_key = os.getenv("GROQ_API_KEY", settings.groq_api_key)
    llm = ChatGroq(model=resolved_model, temperature=0.1, api_key=groq_api_key)

    def report_node(state: AgentState) -> dict:
        """
        Generate a structured post-mortem from all incident_logs.

        1. Collate incident_logs into a timeline.
        2. Build context from state (risk, scan results, decisions).
        3. Ask LLM to produce the post-mortem.
        4. Prepend to the running incident_report.
        """
        target_ip = state.get("target_ip") or state.get("target", "127.0.0.1")
        risk_score = state.get("risk_score", 0)
        risk_level = state.get("risk_level", "NONE")
        category = state.get("category", "N/A")
        is_vulnerable = state.get("is_vulnerable", False)
        confidence = state.get("confidence_score", 0.0)
        threat_detected = state.get("threat_detected", False)
        final_decision = state.get("final_decision", "")
        incident_logs: list[str] = list(state.get("incident_logs", []) or [])
        existing_report = state.get("incident_report", "") or ""

        print(f"\n{'='*60}")
        print(f"[Report Node] Generating structured post-mortem")
        print(f"{'='*60}")

        incident_logs.append(
            f"[Report] Generating post-mortem report at "
            f"{datetime.now(timezone.utc).isoformat()}."
        )

        # ── Build the timeline from incident_logs ────────────────────
        if incident_logs:
            timeline = "\n".join(
                f"  {i+1}. {entry}" for i, entry in enumerate(incident_logs)
            )
        else:
            timeline = "  No incident logs recorded."

        # ── Build context ────────────────────────────────────────────
        context_parts = [
            f"## Target\n{target_ip}",
            f"## Risk Assessment\n"
            f"Score: {risk_score}/10 | Level: {risk_level} | "
            f"Category: {category}",
            f"## Flags\n"
            f"confidence_score: {confidence:.2f} | "
            f"is_vulnerable: {is_vulnerable} | "
            f"threat_detected: {threat_detected}",
            f"## Final Decision\n{final_decision or 'N/A'}",
            f"## Agent Reasoning Log (chronological)\n{timeline}",
        ]

        # Include the accumulated incident report as additional context
        if existing_report:
            # Truncate to avoid exceeding context limits
            context_parts.append(
                f"## Accumulated Incident Data\n"
                f"```\n{existing_report[:4000]}\n```"
            )

        full_context = "\n\n".join(context_parts)

        messages = [
            SystemMessage(content=REPORT_SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Generate a post-mortem report for the security audit "
                    f"of {target_ip}:\n\n{full_context}"
                )
            ),
        ]

        response = llm.invoke(messages)
        post_mortem = response.content

        # ── Build the final combined report ──────────────────────────
        separator = f"\n{'='*60}\n"
        header = (
            f"POST-MORTEM REPORT — {target_ip}\n"
            f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
            f"Risk: {risk_score}/10 ({risk_level}) | "
            f"Category: {category}\n"
            f"{'='*60}\n"
        )
        final_report = (
            separator + header + post_mortem + separator + existing_report
        )

        print(f"[Report Node] Post-mortem generated "
              f"({len(post_mortem)} chars)")

        return {
            "incident_report": final_report,
            "incident_logs": incident_logs,
            "messages": [
                HumanMessage(
                    content=f"[Report Node]\n{post_mortem}"
                )
            ],
            "current_agent": "report",
        }

    return report_node
