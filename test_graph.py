#!/usr/bin/env python3
"""
test_graph.py — Mock State Test for LangGraph
==============================================
Validates    # 1. All 22 AgentState keys are present
    expected_keys = set(AgentState.__annotations__.keys())
    actual_keys = set(final_state.keys())
    missing = expected_keys - actual_keys
    checks.append((
        "All 22 AgentState keys present",
        len(missing) == 0,
        f"missing: {missing}" if missing else f"{len(expected_keys)} keys ✓",
    )) AgentState TypedDict is formatted correctly for
LangGraph by injecting a **fake incident report** (no real Nmap scan)
and invoking the graph starting from the ``threat_analysis`` node.

What this test proves:
    1. The 22-field AgentState dict is accepted by LangGraph without errors.
    2. The threat_analysis → conditional → response/END flow works.
    3. The graph reaches the END node and returns a complete final state.
    4. The interrupt_before=["response_review"] human-approval gate is
       correctly handled by checking graph.get_state().next and
       resuming with graph.invoke(None, config).
    5. threat_summary is populated by the Threat Analysis Agent.

Usage:
    python test_graph.py
"""

import sys
import os
import json
import textwrap

# Force unbuffered output (Python 3.14 terminal buffering workaround)
_print = print
def print(*args, **kwargs):
    kwargs.setdefault("flush", True)
    _print(*args, **kwargs)

# ---------------------------------------------------------------------------
# Make the project package importable
# ---------------------------------------------------------------------------
PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "my-ai-soc-agent")
sys.path.insert(0, PROJECT_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_DIR, ".env"))

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite import SqliteSaver
from agents.state import AgentState
from agents.threat_analysis_agent import create_threat_analysis_agent
from agents.response_agent import create_response_agent

# SQLite checkpoint DB for this test (next to this script)
TEST_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_graph_checkpoints.sqlite")

# ANSI helpers
_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

# ---------------------------------------------------------------------------
# Fake incident report — simulates what the Recon Agent would produce
# ---------------------------------------------------------------------------
FAKE_INCIDENT_REPORT = textwrap.dedent("""\
    ============================================================
    RECONNAISSANCE SCAN — 10.0.0.50
    ============================================================
    Nmap scan report for 10.0.0.50
    Host is up (0.0032s latency).

    PORT      STATE  SERVICE       VERSION
    22/tcp    open   ssh           OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
    80/tcp    open   http          Apache httpd 2.2.22 ((Ubuntu))
    443/tcp   open   ssl/http      Apache httpd 2.2.22 ((Ubuntu))
    3306/tcp  open   mysql         MySQL 5.1.73-0ubuntu0.10.04.1
    8080/tcp  open   http-proxy    Squid http proxy 3.1.19

    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    Service detection performed. 5 services scanned.
""")


# ---------------------------------------------------------------------------
# Build a test graph: threat_analysis → (conditional) → response / END
# ---------------------------------------------------------------------------
def build_mock_graph(model_name: str = "llama-3.3-70b-versatile", checkpointer=None):
    """
    Construct a 2-node graph that skips the Recon Agent entirely.
    Entry point is ``threat_analysis``.
    """
    threat_node  = create_threat_analysis_agent(model_name, threat_store=None)
    response_auto_node = create_response_agent(
        model_name,
        approval_required=False,
    )
    response_review_node = create_response_agent(
        model_name,
        approval_required=True,
    )

    def should_respond(state: AgentState) -> str:
        risk_score = state.get("risk_score", 0)
        if risk_score >= 9:
            return "respond_auto"
        if risk_score >= 1:
            return "respond_review"
        return "end"

    workflow = StateGraph(AgentState)

    workflow.add_node("threat_analysis", threat_node)
    workflow.add_node("response_auto", response_auto_node)
    workflow.add_node("response_review", response_review_node)

    workflow.set_entry_point("threat_analysis")
    workflow.add_conditional_edges(
        "threat_analysis",
        should_respond,
        {
            "respond_auto": "response_auto",
            "respond_review": "response_review",
            "end": END,
        },
    )
    workflow.add_edge("response_auto", END)
    workflow.add_edge("response_review", END)

    return workflow.compile(
        checkpointer=checkpointer,
        interrupt_before=["response_review"],
    )


# ---------------------------------------------------------------------------
# Validation checks
# ---------------------------------------------------------------------------
def validate_state(final_state: dict) -> list[tuple[str, bool, str]]:
    """
    Run a series of checks against the final state and return a list
    of (name, passed, detail) tuples.
    """
    checks: list[tuple[str, bool, str]] = []

    # 1. All 20 AgentState keys are present
    expected_keys = set(AgentState.__annotations__.keys())
    actual_keys = set(final_state.keys())
    missing = expected_keys - actual_keys
    checks.append((
        "All 20 AgentState keys present",
        len(missing) == 0,
        f"missing: {missing}" if missing else f"{len(expected_keys)} keys ✓",
    ))

    # 2. risk_score is an int in 0-10
    rs = final_state.get("risk_score")
    checks.append((
        "risk_score is int 0-10",
        isinstance(rs, int) and 0 <= rs <= 10,
        f"risk_score={rs}",
    ))

    # 3. risk_level is one of the expected labels
    rl = final_state.get("risk_level", "")
    checks.append((
        "risk_level in {CRITICAL, HIGH, MEDIUM, LOW}",
        rl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
        f"risk_level={rl}",
    ))

    # 4. category is a non-empty string
    cat = final_state.get("category", "")
    checks.append((
        "category is non-empty",
        isinstance(cat, str) and len(cat) > 0,
        f"category={cat}",
    ))

    # 5. threat_detected is a bool
    td = final_state.get("threat_detected")
    checks.append((
        "threat_detected is bool",
        isinstance(td, bool),
        f"threat_detected={td}",
    ))

    # 6. incident_report was appended to (longer than the fake input)
    ir = final_state.get("incident_report", "")
    checks.append((
        "incident_report grew (agent appended)",
        len(ir) > len(FAKE_INCIDENT_REPORT),
        f"{len(ir)} chars (original {len(FAKE_INCIDENT_REPORT)})",
    ))

    # 7. current_agent was set
    ca = final_state.get("current_agent", "")
    checks.append((
        "current_agent is set",
        ca in ("threat_analysis", "response"),
        f"current_agent={ca}",
    ))

    # 8. final_decision reflects human approval or monitoring
    fd = final_state.get("final_decision", "")
    valid_decisions = {
        "No Action Required",
        "No Action Required — Monitoring Recommended",
        "Approved by Human Operator",
        "Rejected by Human Operator",
    }
    checks.append((
        "final_decision is a valid value",
        fd in valid_decisions,
        f"final_decision={fd}",
    ))

    # 9. messages list is non-empty
    msgs = final_state.get("messages", [])
    checks.append((
        "messages list is non-empty",
        isinstance(msgs, list) and len(msgs) > 0,
        f"{len(msgs)} message(s)",
    ))

    # 10. threat_analysis_report is a non-empty string
    tar = final_state.get("threat_analysis_report", "")
    checks.append((
        "threat_analysis_report is non-empty",
        isinstance(tar, str) and len(tar) > 0,
        f"{len(tar)} chars",
    ))

    # 11. threat_summary is a non-empty string
    ts = final_state.get("threat_summary", "")
    checks.append((
        "threat_summary is non-empty",
        isinstance(ts, str) and len(ts) > 0,
        f"{len(ts)} chars",
    ))

    # 12. If threat detected, response_plan should exist
    if final_state.get("threat_detected"):
        rp = final_state.get("response_plan", "")
        checks.append((
            "response_plan generated (threat detected)",
            isinstance(rp, str) and len(rp) > 0,
            f"{len(rp)} chars",
        ))
        rem = final_state.get("final_remediation_plan", "")
        checks.append((
            "final_remediation_plan generated",
            isinstance(rem, str) and len(rem) > 0,
            f"{len(rem)} chars",
        ))

    return checks


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    print(f"\n{_BOLD}{'=' * 60}")
    print("  TEST GRAPH — Mock State Validation")
    print(f"{'=' * 60}{_RESET}")
    print(f"  Purpose    : Verify AgentState dict is LangGraph-compatible")
    print(f"  Graph      : threat_analysis → (conditional) → response / END")
    print(f"  Target IP  : 10.0.0.50 (mock — no real scan)")
    print(f"  Model      : {model}")
    print(f"  DB Path    : {TEST_DB_PATH}")
    print(f"{'=' * 60}\n")

    # ── Build the mock initial state (all 18 fields) ─────────────────
    if graph_state.next and "response_review" in graph_state.next:
        "messages":               [],
        "target":                 "10.0.0.50",
        "target_ip":              "10.0.0.50",
        "scan_results":           {},
        "web_tech_results":       {},
        "incident_report":        FAKE_INCIDENT_REPORT,
        "log_data":               "",
        "threat_analysis":        {},
        "threat_analysis_report": "",
        "threat_summary":         "",
        "threat_detected":        False,
        "threat_intel_context":   "",
        "response_plan":          "",
        "risk_level":             "NONE",
        "risk_score":             0,
        "category":               "",
        "final_decision":         "",
        "final_remediation_plan": "",
        "stealth_mode":           False,
        "dry_run":                True,
        "execution_results":      [],
        "current_agent":          "",
    }

    thread_id = "test-graph-mock-state"

    # ── Run ───────────────────────────────────────────────────────────
    with SqliteSaver.from_conn_string(TEST_DB_PATH) as checkpointer:
        graph = build_mock_graph(model_name=model, checkpointer=checkpointer)
        config = {"configurable": {"thread_id": thread_id}}

        print(f"{_CYAN}🚀  Invoking graph (threat_analysis → …) …{_RESET}\n")
        try:
            final_state = graph.invoke(initial_state, config)
        except Exception as exc:
            print(f"\n{_RED}{_BOLD}❌  Graph invocation failed: {exc}{_RESET}")
            raise

        # ── Handle interrupt (human-in-the-loop approval) ────────────
        graph_state = graph.get_state(config)
        if graph_state.next and "response_review" in graph_state.next:
            print(f"{_YELLOW}⏸️   Interrupt detected (interrupt_before=['response_review']) — auto-approving for test …{_RESET}")
            final_state = graph.invoke(None, config)

    # ── Print final state snapshot ────────────────────────────────────
    print(f"\n{_CYAN}{_BOLD}{'─' * 60}")
    print("  FINAL STATE SNAPSHOT")
    print(f"{'─' * 60}{_RESET}")
    snapshot_keys = [
        "target_ip", "risk_score", "risk_level", "category",
        "threat_detected", "final_decision", "current_agent",
    ]
    for key in snapshot_keys:
        print(f"  {key:25s}: {final_state.get(key, 'N/A')}")

    threat = final_state.get("threat_analysis", {})
    if threat:
        print(f"\n  {'threat_analysis.analysis':25s}:")
        analysis = threat.get("analysis", "N/A")
        # Show first 500 chars
        preview = analysis[:500] + ("…" if len(analysis) > 500 else "")
        for line in preview.splitlines():
            print(f"    {line}")

    remediation = final_state.get("final_remediation_plan", "")
    if remediation:
        print(f"\n  {'final_remediation_plan':25s}:")
        for line in remediation.splitlines()[:15]:
            print(f"    {line}")
        if len(remediation.splitlines()) > 15:
            print(f"    … ({len(remediation.splitlines())} lines total)")

    # ── Validation checks ─────────────────────────────────────────────
    print(f"\n{_BOLD}{'=' * 60}")
    print("  VALIDATION CHECKS")
    print(f"{'=' * 60}{_RESET}")

    checks = validate_state(final_state)
    passed_count = 0
    for name, passed, detail in checks:
        icon = f"{_GREEN}✅" if passed else f"{_RED}❌"
        print(f"  {icon}  {name:42s}  {detail}{_RESET}")
        if passed:
            passed_count += 1

    total = len(checks)
    print(f"\n{'=' * 60}")
    if passed_count == total:
        print(f"  {_GREEN}{_BOLD}🎉  ALL {total} CHECKS PASSED — AgentState is LangGraph-compatible{_RESET}")
    else:
        print(f"  {_YELLOW}{_BOLD}⚠️   {passed_count}/{total} checks passed — review failures above{_RESET}")
    print(f"{'=' * 60}\n")

    return passed_count == total


if __name__ == "__main__":
    try:
        success = main()
    except Exception as exc:
        print(f"\n{_RED}{_BOLD}❌  Test failed with exception: {exc}{_RESET}")
        sys.exit(1)

    sys.exit(0 if success else 1)
