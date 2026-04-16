#!/usr/bin/env python3
"""
test_agent.py — Targeted Agent Test
====================================
Tests ONLY the threat_analysis_node and response_node by:

1. Initialising AgentState with a mock IP (8.8.8.8).
2. Injecting a fake Nmap result that looks like a vulnerable MySQL 5.5
   database exposed on port 3306.
3. Building a small 2-node LangGraph (threat_analysis → response)
   that skips the Recon Agent entirely.
4. Running the graph and printing the output to verify the AI correctly
   identifies the MySQL port as high risk (risk_score > 7).

Usage:
    python test_agent.py
"""

import sys
import os
import json
import textwrap

# ---------------------------------------------------------------------------
# Make the project package importable
# ---------------------------------------------------------------------------
PROJECT_DIR = os.path.join(os.path.dirname(__file__), "my-ai-soc-agent")
sys.path.insert(0, PROJECT_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_DIR, ".env"))

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite import SqliteSaver
from agents.state import AgentState
from agents.threat_analysis_agent import create_threat_analysis_agent
from agents.response_agent import create_response_agent

# SQLite checkpoint DB for test runs (next to this script)
TEST_DB_PATH = os.path.join(os.path.dirname(__file__), "test_agent_checkpoints.sqlite")

# ---------------------------------------------------------------------------
# ANSI helpers for the verdict banner
# ---------------------------------------------------------------------------
_GREEN = "\033[92m"
_RED = "\033[91m"
_BOLD = "\033[1m"
_CYAN = "\033[96m"
_YELLOW = "\033[93m"
_RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Fake Nmap scan result — a deliberately vulnerable MySQL 5.5 instance
# ---------------------------------------------------------------------------
FAKE_NMAP_RESULT = textwrap.dedent("""\
    Nmap scan report for 8.8.8.8
    Host is up (0.015s latency).

    PORT      STATE  SERVICE       VERSION
    22/tcp    open   ssh           OpenSSH 7.2p2 Ubuntu 4ubuntu2.10
    80/tcp    open   http          Apache httpd 2.4.18
    3306/tcp  open   mysql         MySQL 5.5.62-0ubuntu0.14.04.1
    6379/tcp  open   redis         Redis key-value store 3.0.6

    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Service detection performed. 4 services scanned.
""")


# ---------------------------------------------------------------------------
# Build a 2-node test graph: threat_analysis → (conditional) → response/END
# ---------------------------------------------------------------------------
def build_test_graph(model_name: str = "llama-3.3-70b-versatile", checkpointer=None):
    """
    Build a minimal LangGraph that wires only the Threat Analysis and
    Response agents — no Recon Agent, no real Nmap scan.

    Args:
        model_name:   Groq model to use.
        checkpointer: Optional LangGraph checkpointer for persistence.
    """
    # Create the agent node functions (no threat_store — keeps it isolated)
    threat_node = create_threat_analysis_agent(model_name, threat_store=None)
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
# Pretty-print helpers
# ---------------------------------------------------------------------------
def print_section(title: str, content: str, color: str = _CYAN) -> None:
                while graph_state.next and "response_review" in graph_state.next:
    print(f"  {title}")
    print(f"{'─'*60}{_RESET}")
    print(content)


def print_verdict(final_state: dict) -> None:
    """Evaluate and display a PASS / FAIL verdict."""
    risk_score = final_state.get("risk_score", 0)
    category = final_state.get("category", "")
    threat_detected = final_state.get("threat_detected", False)
    risk_level = final_state.get("risk_level", "NONE")
    remediation = final_state.get("final_remediation_plan", "")

    print(f"\n{'='*60}")
    print(f"{_BOLD}  TEST VERDICT{_RESET}")
    print(f"{'='*60}")

    checks = []

    # Check 1: risk_score > 7
    passed = risk_score > 7
    checks.append(passed)
    icon = f"{_GREEN}✅" if passed else f"{_RED}❌"
    print(f"  {icon}  risk_score > 7          : {risk_score}/10{_RESET}")

    # Check 2: threat_detected is True
    passed = threat_detected is True
    checks.append(passed)
    icon = f"{_GREEN}✅" if passed else f"{_RED}❌"
    print(f"  {icon}  threat_detected = True  : {threat_detected}{_RESET}")

    # Check 3: risk_level is CRITICAL or HIGH
    passed = risk_level in ("CRITICAL", "HIGH")
    checks.append(passed)
    icon = f"{_GREEN}✅" if passed else f"{_RED}❌"
    print(f"  {icon}  risk_level CRITICAL/HIGH: {risk_level}{_RESET}")

    # Check 4: category is reasonable (not 'No Threat')
    passed = category != "" and category.lower() != "no threat"
    checks.append(passed)
    icon = f"{_GREEN}✅" if passed else f"{_RED}❌"
    print(f"  {icon}  category ≠ 'No Threat'  : {category}{_RESET}")

    # Check 5: remediation plan was generated
    passed = len(remediation) > 0
    checks.append(passed)
    icon = f"{_GREEN}✅" if passed else f"{_RED}❌"
    print(f"  {icon}  remediation plan exists  : {len(remediation)} chars{_RESET}")

    # Check 6: remediation mentions port 3306 or MySQL
    passed = "3306" in remediation or "mysql" in remediation.lower()
    checks.append(passed)
    icon = f"{_GREEN}✅" if passed else f"{_RED}❌"
    print(f"  {icon}  remediation refs MySQL   : {'yes' if passed else 'no'}{_RESET}")

    all_passed = all(checks)
    print(f"\n{'='*60}")
    if all_passed:
        print(f"  {_GREEN}{_BOLD}🎉  ALL CHECKS PASSED — AI correctly flagged MySQL 5.5 as high risk{_RESET}")
    else:
        count = sum(checks)
        print(f"  {_YELLOW}{_BOLD}⚠️   {count}/{len(checks)} checks passed — review output above{_RESET}")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    print(f"\n{_BOLD}{'='*60}")
    print("  TEST AGENT — Threat Analysis + Response (mock data)")
    print(f"{'='*60}{_RESET}")
    print(f"  Target IP    : 8.8.8.8  (mock)")
    print(f"  Model        : {model}")
    print(f"  Injected scan: MySQL 5.5 on port 3306, Redis 3.0.6 on 6379,")
    print(f"                 OpenSSH 7.2 on 22, Apache 2.4.18 on 80")
    print(f"{'='*60}\n")

    # -- Build the 2-node graph with SqliteSaver checkpointer ----------------
    thread_id = "test-agent-8.8.8.8"

    with SqliteSaver.from_conn_string(TEST_DB_PATH) as checkpointer:
        graph = build_test_graph(model_name=model, checkpointer=checkpointer)
        config = {"configurable": {"thread_id": thread_id}}

        # -- Assemble initial state with fake Nmap injected into incident_report --
        initial_state: AgentState = {
            "messages": [],
            "target": "8.8.8.8",
            "target_ip": "8.8.8.8",
            "scan_results": {},
            "web_tech_results": {},
            "incident_report": (
                f"{'='*60}\n"
                f"RECONNAISSANCE — Nmap Scan Results for 8.8.8.8\n"
                f"{'='*60}\n"
                f"{FAKE_NMAP_RESULT}\n"
            ),
            "log_data": "",
            "threat_analysis": {},
            "threat_analysis_report": "",
            "threat_summary":         "",
            "threat_detected": False,
            "stealth_mode": False,
            "dry_run": True,
            "execution_results": [],
        }

        # -- Run the pipeline -------------------------------------------------
        print(f"{_CYAN}🚀  Running threat_analysis → response pipeline …")
        print(f"    Thread ID: {thread_id}")
        print(f"    DB Path  : {TEST_DB_PATH}{_RESET}\n")
        try:
            final_state = graph.invoke(initial_state, config)
        except Exception as exc:
            print(f"\n{_RED}{_BOLD}❌  Pipeline failed: {exc}{_RESET}")
            raise

        # -- Human-in-the-loop: handle interrupt_before response review node --
        graph_state = graph.get_state(config)
        while graph_state.next and "response_review" in graph_state.next:
            # Display the paused state info
            paused_state = graph_state.values
            risk_score = paused_state.get("risk_score", 0)
            risk_level = paused_state.get("risk_level", "UNKNOWN")
            category = paused_state.get("category", "Unknown")
            target = paused_state.get("target_ip", "N/A")

            print(f"\n{_YELLOW}⏸️   GRAPH PAUSED — interrupt_before=['response_review']")
            print(f"    Target : {target}")
            print(f"    Risk   : {risk_score}/10 ({risk_level})")
            print(f"    Category: {category}{_RESET}")

            # Prompt the human operator
            answer = input(f"\n{_BOLD}👤  Approve running the Response Agent? (y/n): {_RESET}").strip().lower()
            if answer not in ("y", "yes", "n", "no"):
                print(f"   {_YELLOW}⚠️  Invalid input — defaulting to 'n' (reject).{_RESET}")
                answer = "n"

            if answer in ("y", "yes"):
                # Resume: let the response node execute
                print(f"\n✅  Approved — resuming graph into Response Agent…")
                final_state = graph.invoke(None, config)
            else:
                # Rejected: update state directly, skip response node
                print(f"\n❌  Rejected — skipping Response Agent.")
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

    # -- Display results ------------------------------------------------------
    print_section(
        "THREAT ANALYSIS (from LLM)",
        final_state.get("threat_analysis", {}).get("analysis", "N/A"),
    )

    print_section(
        "STATE SNAPSHOT",
        json.dumps(
            {
                "target_ip": final_state.get("target_ip"),
                "risk_score": final_state.get("risk_score"),
                "risk_level": final_state.get("risk_level"),
                "category": final_state.get("category"),
                "threat_detected": final_state.get("threat_detected"),
                "final_decision": final_state.get("final_decision"),
            },
            indent=4,
        ),
        color=_YELLOW,
    )

    remediation = final_state.get("final_remediation_plan", "")
    if remediation:
        print_section("FINAL REMEDIATION PLAN", remediation, color=_RED)

    # -- Verdict --------------------------------------------------------------
    print_verdict(final_state)


if __name__ == "__main__":
    main()
