"""
Monitor Node — RAG-Based Anomaly Detection
============================================
The first node in the 4-step specialist pipeline.  Compares
``raw_log_data`` (the initial trigger from the Monitor component)
against the ChromaDB threat-intelligence vector store using
semantic similarity search.

Responsibilities:
    1. Query ChromaDB with the raw log data for matching threats.
    2. Calculate an initial ``confidence_score`` (0.0–1.0) based on
       the top match distances returned by the vector DB.
    3. Set ``threat_detected = True`` when there is a meaningful match.
    4. Append reasoning steps to ``incident_logs`` for the final report.

Fallback:
    When ``raw_log_data`` is empty (e.g. a direct IP scan without a
    monitor trigger), the node auto-passes with ``threat_detected = True``
    and ``confidence_score = 0.5`` so the Investigate node still runs.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agents.state import AgentState
from config import settings

if TYPE_CHECKING:
    from vector_db.threat_intel_store import ThreatIntelStore


# Distance threshold — ChromaDB L2 distance below which we consider a match
# "strong".  Typical embedding L2 distances range ~0.3 (very close) to
# ~1.8 (unrelated).  0.8 is a reasonable cut-off for "likely relevant".
_STRONG_MATCH_DISTANCE = 0.8
_MODERATE_MATCH_DISTANCE = 1.2

# Number of vector-DB results to retrieve
_N_RESULTS = 5


MONITOR_SYSTEM_PROMPT = """\
You are a Security Operations Center (SOC) log triage specialist.

You are given raw log data from a monitoring system and threat intelligence
context retrieved from a vector database.

Your job is to:
1. Determine whether the log data indicates a genuine security anomaly.
2. Explain your reasoning concisely (2-4 sentences).
3. Assign a confidence score between 0.0 and 1.0:
   - 0.0–0.3: Normal activity, no anomaly.
   - 0.4–0.6: Suspicious but uncertain — warrants investigation.
   - 0.7–0.9: Likely threat — strong correlation with known TTPs/IOCs.
   - 0.95–1.0: High-confidence match with known critical vulnerability.

End your response with exactly this line:
CONFIDENCE: <float between 0.0 and 1.0>
"""


def create_monitor_node(
    model_name: str | None = None,
    threat_store: "ThreatIntelStore | None" = None,
):
    """
    Create the Monitor node function for the LangGraph pipeline.

    Args:
        model_name: Groq model used for log triage.
        threat_store: ChromaDB threat intel store for RAG lookups.

    Returns:
        A function usable as a LangGraph node.
    """
    resolved_model = model_name or os.getenv("GROQ_MODEL_MAIN", settings.groq_model_main)
    groq_api_key = os.getenv("GROQ_API_KEY", settings.groq_api_key)
    llm = ChatGroq(model=resolved_model, temperature=0, api_key=groq_api_key)

    def monitor_node(state: AgentState) -> dict:
        """
        RAG-based anomaly detection.

        1. Read ``raw_log_data`` from state.
        2. Query ChromaDB for similar threat intel.
        3. Ask the LLM to triage and assign confidence.
        4. Return updated state with ``confidence_score`` and
           ``threat_detected``.
        """
        raw_log_data: str = state.get("raw_log_data", "") or ""
        target_ip = state.get("target_ip") or state.get("target", "127.0.0.1")
        incident_logs: list[str] = list(state.get("incident_logs", []) or [])

        print(f"\n{'='*60}")
        print(f"[Monitor Node] Starting RAG-based anomaly detection")
        print(f"[Monitor Node] Target: {target_ip}")
        print(f"[Monitor Node] Raw log data length: {len(raw_log_data)} chars")
        print(f"{'='*60}")

        # ── Fallback: no raw_log_data → auto-pass-through ────────────
        if not raw_log_data.strip():
            incident_logs.append(
                "[Monitor] No raw_log_data provided (direct scan). "
                "Auto-passing to Investigate with confidence=0.5."
            )
            print("[Monitor Node] No raw_log_data — auto-pass-through")
            return {
                "confidence_score": 0.5,
                "threat_detected": True,
                "incident_logs": incident_logs,
                "current_agent": "monitor",
                "messages": [
                    HumanMessage(
                        content=(
                            "[Monitor Node] No log data provided — "
                            "treating as direct scan request. "
                            "Passing through to investigation."
                        )
                    )
                ],
            }

        # ── Stage 1: Query ChromaDB for threat intel matches ──────────
        threat_context = ""
        match_distances: list[float] = []

        if threat_store:
            print("[Monitor Node] Querying ChromaDB threat intel store…")
            try:
                results = threat_store.query_threats(
                    raw_log_data[:2000], n_results=_N_RESULTS
                )
                docs = (
                    results.get("documents", [[]])[0]
                    if results.get("documents")
                    else []
                )
                distances = (
                    results.get("distances", [[]])[0]
                    if results.get("distances")
                    else []
                )
                match_distances = distances

                if docs:
                    threat_context = "\n\n".join(
                        f"[Match {i+1}] (distance={d:.3f})\n{doc}"
                        for i, (doc, d) in enumerate(zip(docs, distances))
                    )
                    strong = sum(
                        1 for d in distances if d < _STRONG_MATCH_DISTANCE
                    )
                    moderate = sum(
                        1 for d in distances if d < _MODERATE_MATCH_DISTANCE
                    )
                    print(
                        f"[Monitor Node] Retrieved {len(docs)} matches — "
                        f"{strong} strong (<{_STRONG_MATCH_DISTANCE}), "
                        f"{moderate} moderate (<{_MODERATE_MATCH_DISTANCE})"
                    )
                    incident_logs.append(
                        f"[Monitor] ChromaDB returned {len(docs)} matches: "
                        f"{strong} strong, {moderate} moderate."
                    )
                else:
                    print("[Monitor Node] ChromaDB returned no matches.")
                    incident_logs.append(
                        "[Monitor] ChromaDB returned no matches."
                    )
            except Exception as exc:
                print(f"[Monitor Node] ⚠️  ChromaDB query failed: {exc}")
                incident_logs.append(
                    f"[Monitor] ChromaDB query failed: {exc}"
                )
        else:
            print("[Monitor Node] No threat store available — skipping RAG.")
            incident_logs.append(
                "[Monitor] No ChromaDB threat store configured."
            )

        # ── Stage 2: LLM triage ──────────────────────────────────────
        context_parts = [
            f"## Raw Log Data\n```\n{raw_log_data[:3000]}\n```",
        ]
        if threat_context:
            context_parts.append(
                f"## Threat Intelligence Matches (from vector DB)\n"
                f"{threat_context}"
            )
        else:
            context_parts.append(
                "## Threat Intelligence Matches\nNo matches found in "
                "the vector database."
            )

        full_context = "\n\n".join(context_parts)

        messages = [
            SystemMessage(content=MONITOR_SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Triage the following log data for target {target_ip}. "
                    f"Determine if this is a genuine security anomaly:\n\n"
                    f"{full_context}"
                )
            ),
        ]

        response = llm.invoke(messages)
        llm_output = response.content

        # ── Stage 3: Parse confidence score from LLM output ──────────
        import re

        confidence = 0.3  # cautious default
        match = re.search(
            r"CONFIDENCE:\s*([\d.]+)", llm_output, re.IGNORECASE
        )
        if match:
            try:
                confidence = float(match.group(1))
                confidence = max(0.0, min(1.0, confidence))
            except ValueError:
                pass

        # Boost confidence if ChromaDB returned strong matches
        if match_distances:
            best_distance = min(match_distances)
            if best_distance < _STRONG_MATCH_DISTANCE and confidence < 0.7:
                confidence = max(confidence, 0.7)
                incident_logs.append(
                    f"[Monitor] Confidence boosted to {confidence:.2f} "
                    f"due to strong ChromaDB match (distance={best_distance:.3f})."
                )

        threat_detected = confidence >= 0.4
        incident_logs.append(
            f"[Monitor] LLM triage complete — confidence={confidence:.2f}, "
            f"threat_detected={threat_detected}."
        )

        print(f"\n[Monitor Node] Confidence score: {confidence:.2f}")
        print(f"[Monitor Node] Threat detected: {threat_detected}")

        return {
            "confidence_score": confidence,
            "threat_detected": threat_detected,
            "incident_logs": incident_logs,
            "current_agent": "monitor",
            "messages": [
                HumanMessage(
                    content=f"[Monitor Node]\n{llm_output}"
                )
            ],
        }

    return monitor_node
