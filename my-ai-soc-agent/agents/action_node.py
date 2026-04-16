"""
Action Node — Remediation Execution with Firewall & EDR APIs
==============================================================
The third node in the 4-step specialist pipeline.  Integrates the
existing **Response Agent** and explicitly calls the real API clients
from ``response_automation.py``:

    • **Firewall API** — ``execute_firewall_block_api()`` to block-IP.
    • **EDR API** — ``execute_edr_isolation_api()`` to isolate the host.
    • **Optional SSH** — ``execute_ssh_isolation()`` fallback.

Routing:
    • ``confidence_score >= 0.9`` → auto-pilot (no human gate).
    • ``confidence_score <  0.9`` → ``human_review`` interrupt gate,
      then resumes into this same function after approval.

After execution, the graph **always** routes to the Report Node.
"""

from __future__ import annotations

import os

from langchain_core.messages import HumanMessage
from agents.state import AgentState
from agents.response_agent import create_response_agent
from tools.response_automation import (
    execute_firewall_block_api,
    execute_edr_isolation_api,
    execute_api_response_actions,
)
from tools.action_executor import ExecutionResult, format_execution_results
from config import settings


def create_action_node(
    model_name: str | None = None,
    approval_required: bool = False,
):
    """
    Create the Action node function.

    Wraps the existing Response Agent AND explicitly invokes the
    Firewall and EDR isolation API clients.

    Args:
        model_name: Groq model for the Response Agent.
        approval_required: If True, the decision label reflects human
            approval; if False, it reflects auto-execution by policy.

    Returns:
        A function usable as a LangGraph node.
    """
    resolved_model = model_name or os.getenv("GROQ_MODEL_MAIN", settings.groq_model_main)
    response_fn = create_response_agent(
        resolved_model, approval_required=approval_required
    )

    def action_node(state: AgentState) -> dict:
        """
        Generate and execute the full remediation plan.

        Phase 1 — Response Agent:
            Generate the LLM-driven remediation plan and execute
            shell-level commands (iptables, ufw, systemctl, etc.)

        Phase 2 — API-Driven Controls:
            Explicitly call the real Firewall block-IP and EDR
            host-isolation API clients built in response_automation.py.

        Always appends full execution telemetry to ``incident_logs``.
        """
        target_ip = state.get("target_ip") or state.get("target", "127.0.0.1")
        confidence = state.get("confidence_score", 0.0)
        is_vuln = state.get("is_vulnerable", False)
        default_dry_run = os.getenv("DRY_RUN", str(settings.dry_run)).strip().lower() in (
            "1", "true", "yes", "on"
        )
        dry_run = bool(state.get("dry_run", default_dry_run))
        incident_logs: list[str] = list(state.get("incident_logs", []) or [])

        auto = confidence >= 0.9
        mode = "AUTO-PILOT" if auto else "HUMAN-APPROVED"
        exec_mode = "DRY-RUN 🔵" if dry_run else "⚠️  LIVE EXECUTION"

        print(f"\n{'='*60}")
        print(f"[Action Node] Starting remediation — mode: {mode}")
        print(f"[Action Node] confidence={confidence:.2f}, "
              f"is_vulnerable={is_vuln}")
        print(f"[Action Node] Execution mode: {exec_mode}")
        print(f"{'='*60}")

        incident_logs.append(
            f"[Action] Remediation started — mode={mode}, "
            f"execution={exec_mode}, "
            f"confidence={confidence:.2f}, is_vulnerable={is_vuln}."
        )

        # ── Phase 1: Delegate to the Response Agent ──────────────────
        # This generates the LLM remediation plan and executes commands
        # (iptables/ufw/systemctl) + already calls execute_api_response_actions
        # internally for the high-risk path.
        print("\n[Action Node] Phase 1: Response Agent — generating "
              "remediation plan + shell commands…")
        result = response_fn(state)

        shell_results: list[ExecutionResult] = result.get("execution_results", [])
        incident_logs.append(
            f"[Action] Phase 1 complete — Response Agent produced "
            f"{len(shell_results)} command result(s)."
        )

        # ── Phase 2: Explicit Firewall + EDR API calls ───────────────
        # We call these directly to ensure they are always invoked and
        # their results are clearly logged in the incident trail.
        print("\n[Action Node] Phase 2: Firewall & EDR API controls…")

        # 2a. Firewall block-IP
        print(f"[Action Node]   🔥 Firewall API — block IP {target_ip}")
        fw_result = execute_firewall_block_api(
            target_ip=target_ip,
            dry_run=dry_run,
        )
        incident_logs.append(
            f"[Action] Firewall block-IP: status={fw_result['status']}, "
            f"dry_run={fw_result['dry_run']}. "
            f"{fw_result.get('stdout', '') or fw_result.get('stderr', '')}"
        )
        print(f"[Action Node]   → Firewall: {fw_result['status']}")

        # 2b. EDR host isolation
        print(f"[Action Node]   🛡️  EDR API — isolate host {target_ip}")
        edr_result = execute_edr_isolation_api(
            target_ip=target_ip,
            dry_run=dry_run,
        )
        incident_logs.append(
            f"[Action] EDR host isolation: status={edr_result['status']}, "
            f"dry_run={edr_result['dry_run']}. "
            f"{edr_result.get('stdout', '') or edr_result.get('stderr', '')}"
        )
        print(f"[Action Node]   → EDR: {edr_result['status']}")

        # Merge API results into the execution results
        api_results = [fw_result, edr_result]
        all_results = shell_results + api_results

        # ── Summary ──────────────────────────────────────────────────
        n_total = len(all_results)
        n_ok = sum(
            1 for r in all_results
            if r.get("status") in ("SUCCESS", "DRY_RUN")
        )
        n_err = n_total - n_ok

        decision = result.get("final_decision", "")
        incident_logs.append(
            f"[Action] All phases complete — {n_total} total action(s), "
            f"{n_ok} ok, {n_err} error(s). Decision: {decision}."
        )

        print(f"\n[Action Node] ✅ Complete — {n_total} total actions, "
              f"{n_ok} ok, {n_err} errors")
        print(f"[Action Node] Decision: {decision}")

        # ── Return merged state ──────────────────────────────────────
        result["execution_results"] = all_results
        result["incident_logs"] = incident_logs
        result["current_agent"] = "action"
        return result

    return action_node
