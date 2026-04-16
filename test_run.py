#!/usr/bin/env python3
"""
Test Run Script
===============
Quick integration test for the Autonomous Cybersecurity Defense Agent.

Imports build_graph from main.py, constructs a minimal initial state
targeting 192.168.1.1, invokes the LangGraph pipeline with a SqliteSaver
checkpointer and thread_id, and prints the final state showing Nmap
results and AI threat analysis.

Prerequisites:
    - OPENAI_API_KEY set in .env (or environment)
    - pip dependencies installed  (pip install -r requirements.txt)
    - (optional) nmap binary installed for real scans
"""

import sys
import os
import json

# Ensure the project package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "my-ai-soc-agent"))

from dotenv import load_dotenv

# Load environment variables from the project .env
load_dotenv(os.path.join(os.path.dirname(__file__), "my-ai-soc-agent", ".env"))

from langgraph.checkpoint.sqlite import SqliteSaver
from main import build_graph, print_report, make_thread_id
from agents.state import AgentState

# SQLite checkpoint DB lives next to this script
DB_PATH = os.path.join(os.path.dirname(__file__), "test_checkpoints.sqlite")


def run_test(target_ip: str = "192.168.1.1", model: str = None,
             thread_id: str = None) -> dict:
    """
    Build the graph, invoke it with a test initial state, and return the
    final state dictionary.
    """
    model = model or os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    thread_id = thread_id or make_thread_id(target_ip)

    print("=" * 60)
    print("  TEST RUN — Autonomous Cybersecurity Defense Agent")
    print("=" * 60)
    print(f"  Target IP  : {target_ip}")
    print(f"  Model      : {model}")
    print(f"  Thread ID  : {thread_id}")
    print(f"  DB Path    : {DB_PATH}")
    print("=" * 60, "\n")

    # Define the initial state with all required AgentState fields
    initial_state: AgentState = {
        "messages": [],
        "target": target_ip,
        "target_ip": target_ip,
        "scan_results": {},
        "web_tech_results": {},
        "incident_report": "",
        "log_data": "",
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
        "stealth_mode": False,
        "dry_run": True,
        "execution_results": [],
        "current_agent": "",
    }

    config = {"configurable": {"thread_id": thread_id}}

    with SqliteSaver.from_conn_string(DB_PATH) as checkpointer:
        # Build the compiled LangGraph pipeline with persistence
        graph = build_graph(model_name=model, checkpointer=checkpointer)

        # Execute the pipeline
        print("🚀  Invoking the agent pipeline …\n")
        final_state = graph.invoke(initial_state, config)

        # ----- Human-in-the-loop: handle interrupt_before response review node -----
        graph_state = graph.get_state(config)
        while graph_state.next and "response_review" in graph_state.next:
            # Display the paused state info
            paused_state = graph_state.values
            risk_score = paused_state.get("risk_score", 0)
            risk_level = paused_state.get("risk_level", "UNKNOWN")
            category = paused_state.get("category", "Unknown")
            target = paused_state.get("target_ip", "N/A")
            threat_report = paused_state.get("threat_analysis_report", "")

            print(f"\n{'='*60}")
            print("⏸️   GRAPH PAUSED — interrupt_before=['response_review']")
            print(f"{'='*60}")
            print(f"    Target   : {target}")
            print(f"    Risk     : {risk_score}/10 ({risk_level})")
            print(f"    Category : {category}")
            if threat_report:
                print(f"\n{'─'*60}")
                print("  THREAT ANALYSIS SUMMARY")
                print(f"{'─'*60}")
                preview = threat_report[:1500]
                if len(threat_report) > 1500:
                    preview += "\n  … (truncated)"
                print(preview)
                print(f"{'─'*60}")

            # Prompt the human operator
            answer = input("\n👤  Approve running the Response Agent? (y/n): ").strip().lower()
            if answer not in ("y", "yes", "n", "no"):
                print("   ⚠️  Invalid input — defaulting to 'n' (reject).")
                answer = "n"

            if answer in ("y", "yes"):
                # Resume: let the response node execute
                print("\n✅  Approved — resuming graph into Response Agent…")
                final_state = graph.invoke(None, config)
            else:
                # Rejected: update state directly, skip response node
                print("\n❌  Rejected — skipping Response Agent.")
                graph.update_state(
                    config,
                    {
                        "final_decision": "Rejected by Human Operator",
                        "response_plan": "",
                        "final_remediation_plan": "",
                        "current_agent": "response_review",
                    },
                    as_node="response_review",
                )
                final_state = graph.get_state(config).values

            # Check if there are more pending nodes
            graph_state = graph.get_state(config)

    return final_state


def dump_state(state: dict) -> None:
    """Pretty-print key fields of the final state for inspection."""

    print("\n" + "=" * 60)
    print("  RAW STATE DUMP (key fields)")
    print("=" * 60)

    fields = [
        "target_ip",
        "risk_score",
        "risk_level",
        "category",
        "threat_detected",
        "final_decision",
        "current_agent",
    ]
    for field in fields:
        print(f"  {field:25s}: {state.get(field, 'N/A')}")

    # Threat analysis dict
    threat = state.get("threat_analysis", {})
    if threat:
        print(f"\n  {'threat_analysis':25s}:")
        print(json.dumps(threat, indent=4, default=str))

    # Scan results dict
    scan = state.get("scan_results", {})
    if scan:
        print(f"\n  {'scan_results':25s}:")
        print(json.dumps(scan, indent=4, default=str))

    # Incident report (may be long — show first 2000 chars)
    report = state.get("incident_report", "")
    if report:
        preview = report[:2000] + ("…" if len(report) > 2000 else "")
        print(f"\n  {'incident_report (preview)':25s}:\n{preview}")

    # Response plan
    plan = state.get("response_plan", "")
    if plan:
        print(f"\n  {'response_plan':25s}:\n{plan}")

    # Final remediation plan (extracted commands)
    remediation = state.get("final_remediation_plan", "")
    if remediation:
        print(f"\n  {'final_remediation_plan':25s}:\n{remediation}")

    print("\n" + "=" * 60)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
    custom_thread = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        final_state = run_test(target_ip=target, thread_id=custom_thread)
    except Exception as exc:
        print(f"\n❌  Pipeline failed: {exc}")
        raise

    # Formatted report (same as main.py)
    print_report(final_state)

    # Raw state dump for debugging
    dump_state(final_state)

    print("\n✅  Test run complete.")

# Example usage:
# python test_run.py                               # scan 192.168.1.1 (thread = target-192.168.1.1)
# python test_run.py 10.0.0.1                      # scan 10.0.0.1   (thread = target-10.0.0.1)
# python test_run.py 10.0.0.1 my-custom-thread     # custom thread_id
