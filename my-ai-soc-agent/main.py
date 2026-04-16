"""
Autonomous Cybersecurity Defense Agent
======================================
Main orchestrator that uses LangGraph to wire four specialized nodes
into a stateful pipeline:

    1. Monitor Node       →  RAG-based anomaly detection (pgvector)
    2. Investigate Node   →  Nmap scanning + CVE threat analysis
    3. Action Node        →  Remediation execution (auto or human-approved)
    4. Report Node        →  Structured post-mortem generation

State is persisted across runs via a **PostgreSQL** checkpointer.
Provide a ``thread_id`` (defaults to the target IP) so the AI recalls
previous findings when you re-scan the same target.

Usage:
    python main.py                                    # scan localhost
    python main.py --target 192.168.1.1               # scan a specific target
    python main.py --target 192.168.1.1 --thread-id mythread  # custom thread
    python main.py --seed-db                          # seed threat intel DB
"""

import argparse
import os

from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.postgres import PostgresSaver

from config import settings, getenv_bool
from checkpointer import create_postgres_checkpointer, validate_database_connection
from agents.state import AgentState
from agents.monitor_node import create_monitor_node
from agents.investigate_node import create_investigate_node
from agents.action_node import create_action_node
from agents.report_node import create_report_node
from incident_io import save_incident
from tools.report_generator import save_incident_bundle


# ---------------------------------------------------------------------------
# Load environment variables
# ---------------------------------------------------------------------------
load_dotenv()

# Database URL for PostgreSQL checkpointer
DATABASE_URL = os.getenv("DB_URL", os.getenv("DATABASE_URL", settings.database_url))


# ---------------------------------------------------------------------------
# Conditional edge: Monitor → Investigate or Report
# ---------------------------------------------------------------------------
def should_investigate(state: AgentState) -> str:
    """Decide whether to investigate based on Monitor's findings."""
    threat_detected = state.get("threat_detected", False)

    if threat_detected:
        confidence = state.get("confidence_score", 0.0)
        print(f"\n[Router] Anomaly detected (confidence={confidence:.2f}) "
              f"— routing to Investigate Node.")
        return "investigate"

    print(f"\n[Router] No anomaly detected — generating clean report.")
    return "report"


# ---------------------------------------------------------------------------
# Conditional edge: Investigate → Action (Auto-Pilot) / Human Review
# ---------------------------------------------------------------------------
def should_authenticate(state: AgentState) -> str:
    """
    Confidence-based routing after investigation:
      - confidence_score >= 0.9 → auto-pilot directly to Action Node
      - confidence_score <  0.9 → route to human_review for approval

    After either path completes, the graph always routes to Report.
    """
    confidence = state.get("confidence_score", 0.0)
    risk_score = state.get("risk_score", 0)
    is_vulnerable = state.get("is_vulnerable", False)

    if confidence >= 0.9:
        print(f"\n[Router] ✅ High confidence ({confidence:.2f}) "
              f"— AUTO-PILOT: routing directly to Action Node.")
        print(f"[Router]    risk_score={risk_score}/10, "
              f"is_vulnerable={is_vulnerable}")
        return "action"

    print(f"\n[Router] ⏸️  Confidence ({confidence:.2f}) < 0.9 "
          f"— routing to Human Review for approval.")
    print(f"[Router]    risk_score={risk_score}/10, "
          f"is_vulnerable={is_vulnerable}")
    return "human_review"


# ---------------------------------------------------------------------------
# Build the LangGraph workflow — 4-node specialist model
# ---------------------------------------------------------------------------
def build_graph(model_name: str = "llama-3.3-70b-versatile", checkpointer=None):
    """
    Construct the LangGraph state graph for the cybersecurity defense pipeline.

    Args:
        model_name:   Groq model to use for all agents.
        checkpointer: A LangGraph checkpointer (e.g. ``PostgresSaver``).
                      When provided the compiled graph will persist state
                      between invocations keyed by ``thread_id``.

    Graph structure::

        monitor → (conditional) → investigate → (conditional) → action  → report → END
                        │                              │            ↑
                        └→ report                      │            │
                                                       └→ human_review ─┘
    """
    # Initialise shared resources
    threat_store = None
    try:
        from vector_db.pgvector_store import ThreatIntelStore
        threat_store = ThreatIntelStore()
    except Exception as exc:
        print(f"[Main] ⚠️  Could not initialise pgvector threat store: {exc}")
        print("[Main]    Continuing without vector DB threat intelligence.")

    # Create node functions
    monitor_node = create_monitor_node(model_name, threat_store)
    investigate_node = create_investigate_node(model_name, threat_store)
    action_auto_node = create_action_node(model_name, approval_required=False)
    action_approved_node = create_action_node(model_name, approval_required=True)
    report_node = create_report_node(model_name)

    # Build the graph
    workflow = StateGraph(AgentState)

    # Add nodes
    workflow.add_node("monitor", monitor_node)
    workflow.add_node("investigate", investigate_node)
    workflow.add_node("action", action_auto_node)
    workflow.add_node("human_review", action_approved_node)
    workflow.add_node("report", report_node)

    # Define edges
    workflow.set_entry_point("monitor")

    # Monitor → Investigate (anomaly) or Report (clean)
    workflow.add_conditional_edges(
        "monitor",
        should_investigate,
        {
            "investigate": "investigate",
            "report": "report",
        },
    )

    # Investigate → Action (auto-pilot) or Human Review
    # confidence_score >= 0.9 → action (auto-pilot)
    # confidence_score <  0.9 → human_review (interrupt gate)
    workflow.add_conditional_edges(
        "investigate",
        should_authenticate,
        {
            "action": "action",
            "human_review": "human_review",
        },
    )

    # Action (auto-executed) → Report (close the loop)
    workflow.add_edge("action", "report")

    # Human Review (after interrupt) → Report (close the loop)
    workflow.add_edge("human_review", "report")

    # Report → END
    workflow.add_edge("report", END)

    return workflow.compile(
        checkpointer=checkpointer,
        interrupt_before=["human_review"],
    )


# ---------------------------------------------------------------------------
# Helper: derive a deterministic thread_id from the target IP
# ---------------------------------------------------------------------------
def make_thread_id(target: str, custom_id: str | None = None) -> str:
    """
    Return a thread_id for the checkpointer.

    If *custom_id* is supplied it is used directly; otherwise a
    deterministic id is derived from the target IP so that repeated
    scans of the same target automatically share history.
    """
    if custom_id:
        return custom_id
    return f"target-{target}"


# ---------------------------------------------------------------------------
# Pretty-print the final report
# ---------------------------------------------------------------------------
def print_report(final_state: dict) -> None:
    """Print a formatted summary of the pipeline run."""
    print("\n" + "=" * 70)
    print("   AUTONOMOUS CYBERSECURITY DEFENSE AGENT — FINAL REPORT")
    print("=" * 70)

    target = final_state.get("target_ip") or final_state.get("target", "N/A")
    print(f"\n🎯  Target          : {target}")
    print(f"📊  Risk Score      : {final_state.get('risk_score', 'N/A')}/10")
    print(f"⚠️   Risk Level      : {final_state.get('risk_level', 'N/A')}")
    print(f"🏷️   Category        : {final_state.get('category', 'N/A')}")
    print(f"🚨  Threat Detected : {final_state.get('threat_detected', False)}")
    print(f"🔍  Confidence      : {final_state.get('confidence_score', 0.0):.2f}")
    print(f"🛡️   Vulnerable      : {final_state.get('is_vulnerable', False)}")

    final_decision = final_state.get("final_decision", "")
    if final_decision:
        print(f"📌  Final Decision  : {final_decision}")

    # Threat analysis summary
    threat = final_state.get("threat_analysis", {})
    if threat:
        print(f"🔍  Threat Matches : {threat.get('threat_intel_matches', 0)}")

    # Plain-English threat summary
    threat_summary = final_state.get("threat_summary", "")
    if threat_summary:
        print(f"\n{'─'*70}")
        print("🗒️   THREAT SUMMARY")
        print(f"{'─'*70}")
        print(threat_summary)

    # Structured Threat Analysis Report
    threat_analysis_report = final_state.get("threat_analysis_report", "")
    if threat_analysis_report:
        print(f"\n{'─'*70}")
        print("🔎  THREAT ANALYSIS REPORT")
        print(f"{'─'*70}")
        print(threat_analysis_report)

    # Agent reasoning log (incident_logs)
    incident_logs = final_state.get("incident_logs", [])
    if incident_logs:
        print(f"\n{'─'*70}")
        print("📋  AGENT REASONING LOG")
        print(f"{'─'*70}")
        for i, entry in enumerate(incident_logs, 1):
            print(f"  {i:02d}. {entry}")

    # Incident report (cumulative raw data from every agent)
    incident_report = final_state.get("incident_report", "")
    if incident_report:
        print(f"\n{'─'*70}")
        print("📄  INCIDENT REPORT")
        print(f"{'─'*70}")
        print(incident_report)

    # Response plan
    response_plan = final_state.get("response_plan", "")
    if response_plan:
        print(f"\n{'─'*70}")
        print("📋  INCIDENT RESPONSE PLAN")
        print(f"{'─'*70}")
        print(response_plan)
    else:
        print("\n✅  No incident response required — risk level is acceptable.")

    # Final remediation plan (extracted executable commands)
    remediation = final_state.get("final_remediation_plan", "")
    if remediation:
        print(f"\n{'─'*70}")
        print("🛠️   FINAL REMEDIATION PLAN")
        print(f"{'─'*70}")
        print(remediation)

    print("\n" + "=" * 70)
    print("   END OF REPORT")
    print("=" * 70)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Cybersecurity Defense Agent"
    )
    parser.add_argument(
        "--target",
        default=os.getenv("SCAN_TARGET", "127.0.0.1"),
        help="Target IP or hostname to scan (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("GROQ_MODEL", settings.groq_model_main),
        help="Groq model name (default: llama-3.3-70b-versatile)",
    )
    parser.add_argument(
        "--seed-db",
        action="store_true",
        help="Seed the threat intelligence vector DB with sample data",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Optional path to a log file to include in the analysis",
    )
    parser.add_argument(
        "--thread-id",
        default=None,
        help=(
            "Thread ID for the checkpointer. Allows the AI to recall "
            "previous findings for the same conversation. "
            "Defaults to 'target-<IP>' so re-scanning the same IP "
            "automatically resumes the previous session."
        ),
    )
    parser.add_argument(
        "--stealth",
        action="store_true",
        help=(
            "Enable stealth scanning mode. Uses -sS -T2 -f (SYN Stealth, "
            "polite timing, fragmented packets) instead of -sV to evade "
            "firewalls and IDS/IPS at the cost of less version detail."
        ),
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help=(
            "Enable LIVE execution of remediation commands (iptables, ufw, "
            "systemctl, etc.).  By default all commands are dry-run only. "
            "Only use this flag when you have reviewed the threat report "
            "and explicitly intend to modify the host's firewall/services."
        ),
    )
    args = parser.parse_args()

    # Ensure key runtime settings are available for all modules.
    os.environ.setdefault("GROQ_API_KEY", os.getenv("GROQ_API_KEY", settings.groq_api_key))
    os.environ.setdefault("NMAP_PATH", os.getenv("NMAP_PATH", settings.nmap_path))
    os.environ.setdefault("DB_URL", DATABASE_URL)

    default_dry_run = getenv_bool("DRY_RUN", settings.dry_run)

    # Optionally seed the threat intel DB
    if args.seed_db:
        try:
            from vector_db.threat_intel_store import ThreatIntelStore
            store = ThreatIntelStore()
            store.seed_sample_data()
            print("\n✅  Threat intelligence database seeded successfully.")
        except Exception as exc:
            print(f"\n⚠️  Could not seed threat intel DB: {exc}")
        if not args.target:
            return

    # Read log data if provided
    log_data = ""
    if args.log_file:
        try:
            with open(args.log_file, "r") as f:
                log_data = f.read()
            print(f"[Main] Loaded log file: {args.log_file}")
        except Exception as e:
            print(f"[Main] Warning: Could not read log file: {e}")

    # Derive the thread_id
    thread_id = make_thread_id(args.target, args.thread_id)

    # Build and run the graph with PostgreSQL persistence
    print("\n🚀  Starting Autonomous Cybersecurity Defense Agent")
    print(f"    Target   : {args.target}")
    print(f"    Model    : {args.model}")
    print(f"    Stealth  : {'ON 🥷' if args.stealth else 'OFF'}")
    print(f"    Execution: {'⚠️  LIVE' if args.live else 'DRY-RUN 🔵'}")
    print(f"    Pipeline : Monitor → Investigate → Action → Report")
    print(f"    Thread ID: {thread_id}")
    print(f"    Database : PostgreSQL\n")

    # Validate database connection
    if not validate_database_connection():
        print("[Main] ❌ PostgreSQL connection failed!")
        print("[Main] Run: python init_db.py")
        return 1

    # Create PostgreSQL checkpointer
    checkpointer = create_postgres_checkpointer()
    graph = build_graph(model_name=args.model, checkpointer=checkpointer)

    # The config that tells LangGraph which thread to use
    config = {"configurable": {"thread_id": thread_id}}

    # Initial state
    initial_state: AgentState = {
        "messages": [],
        "target": args.target,
        "target_ip": args.target,
        "scan_results": {},
        "web_tech_results": {},
        "incident_report": "",
        "log_data": log_data,
        "threat_analysis": {},
        "threat_analysis_report": "",
        "threat_summary":         "",
        "threat_detected": False,
        "threat_intel_context": "",
        "response_plan": "",
        "risk_level": "NONE",
        "risk_score": 0,
        "category": "",
        "final_decision": "",
        "final_remediation_plan": "",
        "stealth_mode": args.stealth,
        "dry_run": (not args.live) if args.live else default_dry_run,
        "execution_results": [],
        "current_agent": "",
        "confidence_score": 0.0,
        "incident_logs": [],
        "raw_log_data": log_data,
        "is_vulnerable": False,
    }

    # The graph will pause BEFORE entering the "human_review" node
    # thanks to interrupt_before=["human_review"] in compile().
    final_state = graph.invoke(initial_state, config)

    # ----- Human-in-the-loop: interrupt_before the human_review node ------
    # When the graph pauses before "human_review", get_state().next
    # will contain ("human_review",).  We show the threat analysis to
    # the operator and ask for approval before letting the action
    # node run.
    graph_state = graph.get_state(config)
    while graph_state.next and "human_review" in graph_state.next:
        # Show the operator what was found so far
        paused_state = graph_state.values
        risk_score = paused_state.get("risk_score", 0)
        risk_level = paused_state.get("risk_level", "UNKNOWN")
        category = paused_state.get("category", "Unknown")
        target = paused_state.get("target_ip", "N/A")
        confidence = paused_state.get("confidence_score", 0.0)
        is_vuln = paused_state.get("is_vulnerable", False)
        threat_report = paused_state.get(
            "threat_analysis_report", ""
        )

        print(f"\n{'='*60}")
        print("⏸️   GRAPH PAUSED — interrupt_before=['human_review']")
        print(f"{'='*60}")
        print(f"    Target     : {target}")
        print(f"    Risk       : {risk_score}/10 ({risk_level})")
        print(f"    Category   : {category}")
        print(f"    Confidence : {confidence:.2f} (< 0.9 → requires review)")
        print(f"    Vulnerable : {is_vuln}")
        if threat_report:
            print(f"\n{'─'*60}")
            print("  THREAT ANALYSIS SUMMARY (review before approving)")
            print(f"{'─'*60}")
            # Show a condensed preview (first 1500 chars)
            preview = threat_report[:1500]
            if len(threat_report) > 1500:
                preview += "\n  … (truncated — full report in final output)"
            print(preview)
            print(f"{'─'*60}")

        print("\n  The Action Node will execute Firewall block-IP and")
        print("  EDR host isolation API calls, plus remediation commands.")

        answer = input(
            "\n👤  Approve running the Action Node? (y/n): "
        ).strip().lower()
        if answer not in ("y", "yes", "n", "no"):
            print("   ⚠️  Invalid input — defaulting to 'n' (reject).")
            answer = "n"

        if answer in ("y", "yes"):
            # Resume: let the human_review node execute
            print("\n✅  Approved — resuming graph into Action Node…")
            final_state = graph.invoke(None, config)
        else:
            # Rejected: update state directly, do NOT run action node
            print("\n❌  Rejected — skipping Action Node.")
            final_state = graph.update_state(
                config,
                {
                    "final_decision": "Rejected by Human Operator",
                    "response_plan": "",
                    "final_remediation_plan": "",
                    "current_agent": "human_review",
                },
                as_node="human_review",
            )
            # After update_state the graph moves to report; invoke to
            # let the report node run.
            final_state = graph.invoke(None, config)

        # Check if there are more pending nodes
        graph_state = graph.get_state(config)

    # Print results
    print_report(final_state)

    # Persist incident artefacts to incidents/<thread_id>/
    save_incident(thread_id, final_state)
    save_incident_bundle(final_state, thread_id)


if __name__ == "__main__":
    main()
