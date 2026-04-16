"""
Incident Response Agent
=======================
The third and final agent in the pipeline.

Behaviour depends on the ``risk_level`` and the confidence policy set by
the Threat Analysis Agent and orchestration layer:

    • **CRITICAL / HIGH** — Generate a full technical remediation plan
      with executable commands (iptables, ufw, AWS SG, service patches)
    to close vulnerable ports.  Normally requires human approval, but
    incidents with ``risk_score >= 9`` may be auto-executed by the
    graph without a human gate.
        • **LOW / MEDIUM** — Suggest monitoring and passive hardening steps.
            No human approval is required.
        • **CONFIDENCE-AWARE** — Approval mode can be auto-executed based on
            confidence levels set by the orchestration layer.

In every case the agent prints a bold
**"SECURITY ACTION PLAN GENERATED"** banner to the console.
"""

import re
import json
import os

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agents.state import AgentState
from tools.action_executor import (
    execute_remediation_plan,
    format_execution_results,
    ExecutionResult,
)
from tools.response_automation import execute_api_response_actions
from config import settings


# ---------------------------------------------------------------------------
# ANSI colour codes for console output
# ---------------------------------------------------------------------------
_RED = "\033[91m"
_GREEN = "\033[92m"
_BOLD = "\033[1m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_RESET = "\033[0m"


# ---------------------------------------------------------------------------
# System prompt — CRITICAL / HIGH: full technical remediation
# ---------------------------------------------------------------------------
RESPONSE_PROMPT_HIGH = """You are an expert cybersecurity incident responder and SOC team lead.

You are given:
- The target IP address.
- The risk score (0-10) and threat category.
- The full incident report (containing raw Nmap scan results).
- The threat analysis produced by the previous agent.
- Optionally, relevant threat intelligence context.

Your job is to produce a **concise, actionable mitigation plan** with
ready-to-execute technical commands that a network administrator can
run immediately.

Structure your response with EXACTLY these sections:

### EXECUTIVE SUMMARY
2-3 sentences for management.

### TECHNICAL REMEDIATION COMMANDS
For every dangerous port or service found, emit the exact commands.
Include ALL of the following where applicable:
- **iptables rules** (Linux firewall — use the exact target IP):
    iptables -A INPUT -s <IP> -p tcp --dport <PORT> -j DROP
- **ufw rules** (simplified firewall):
    ufw deny from <IP> to any port <PORT>
- **AWS Security Group CLI** (cloud environments):
    aws ec2 revoke-security-group-ingress --group-id sg-XXXXXXXX --protocol tcp --port <PORT> --cidr <IP>/32
- **Service-specific patches / restarts**:
    systemctl stop <service> && apt-get update && apt-get upgrade <package>

### SHORT-TERM REMEDIATION (1-24 hrs)
Patches, config hardening, version upgrades.

### LONG-TERM HARDENING (1-7 days)
Monitoring, IDS/IPS rules, policy updates, network segmentation.

Rules:
1. Reference the exact target IP in EVERY command.
2. Each command must be copy-paste ready — no placeholders except sg-XXXXXXXX for the AWS SG ID which the admin must fill in.
3. Be specific — include exact shell commands.
4. End your response with a single line:
   SUGGESTED_ACTIONS_COMPLETE"""

# ---------------------------------------------------------------------------
# System prompt — LOW / MEDIUM: monitoring-only recommendations
# ---------------------------------------------------------------------------
RESPONSE_PROMPT_LOW = """You are an expert cybersecurity incident responder and SOC team lead.

You are given:
- The target IP address.
- The risk score (0-10) and threat category.
- The full incident report (containing raw Nmap scan results).
- The threat analysis produced by the previous agent.

The risk level is LOW or MEDIUM.  No immediate blocking action is
required, but the team should monitor the target and apply passive
hardening.

Structure your response with EXACTLY these sections:

### EXECUTIVE SUMMARY
2-3 sentences explaining why the risk is low.

### MONITORING RECOMMENDATIONS
List specific monitoring actions, including:
- Network traffic monitoring (tcpdump, Zeek, Suricata rules)
- Log-based alerting (journalctl, SIEM correlation rules)
- Periodic re-scan schedule (e.g. weekly Nmap service scans)

### PASSIVE HARDENING
Non-disruptive improvements:
- Configuration audits (SSH hardening, TLS version enforcement)
- Service version upgrades (apt-get / yum)
- Firewall rule reviews (ufw status, iptables -L)

### NEXT REVIEW DATE
Suggest a follow-up date and criteria for escalation.

Rules:
1. Do NOT issue any blocking/drop commands.
2. Focus on visibility and detection, not active response.
3. End your response with a single line:
   MONITORING_PLAN_COMPLETE"""


def create_response_agent(
    model_name: str | None = None,
    approval_required: bool = True,
):
    """
    Create the Incident Response Agent node function.

    Args:
        model_name: Groq model to use.
            approval_required: When False, the high-risk remediation path
                runs without a human approval banner.

    Returns:
        A function that can be used as a LangGraph node.
    """
    resolved_model = model_name or os.getenv("GROQ_MODEL_MAIN", settings.groq_model_main)
    groq_api_key = os.getenv("GROQ_API_KEY", settings.groq_api_key)
    llm = ChatGroq(model=resolved_model, temperature=0.1, api_key=groq_api_key)

    def response_node(state: AgentState) -> dict:
        """
        Generate a response plan whose depth depends on ``risk_level``.

        • **CRITICAL / HIGH** → full technical remediation with
          iptables/ufw/AWS SG block commands + human approval via
          ``interrupt()``.
        • **LOW / MEDIUM** → monitoring & passive hardening suggestions
          (no human approval needed).

        In both paths the bold **SECURITY ACTION PLAN GENERATED**
        banner is printed to the console.
        """
        target_ip = state.get("target_ip") or state.get("target", "UNKNOWN")
        risk_level = state.get("risk_level", "LOW")
        risk_score = state.get("risk_score", 0)
        category = state.get("category", "Unknown")
        incident_report = state.get("incident_report", "")
        threat_analysis = state.get("threat_analysis", {})
        threat_intel_context = state.get("threat_intel_context", "")
        # dry_run=True by default — only set to False when the operator
        # has explicitly toggled "Live Execution" in the UI or CLI.
        default_dry_run = os.getenv("DRY_RUN", str(settings.dry_run)).strip().lower() in (
            "1", "true", "yes", "on"
        )
        dry_run = bool(state.get("dry_run", default_dry_run))

        print(f"\n{'='*60}")
        print(f"[Response Agent] Starting — risk_level={risk_level}, "
              f"risk_score={risk_score}/10")
        mode_str = "DRY-RUN 🔵" if dry_run else "⚠️  LIVE EXECUTION"
        print(f"[Response Agent] Execution mode: {mode_str}")
        print(f"{'='*60}")

        # ── Decide which path to take based on risk_level ────────────
        is_high_risk = risk_level in ("CRITICAL", "HIGH")

        if is_high_risk:
            return _handle_high_risk(
                llm, target_ip, risk_level, risk_score, category,
                incident_report, threat_analysis, threat_intel_context,
                dry_run,
            )
        else:
            return _handle_low_risk(
                llm, target_ip, risk_level, risk_score, category,
                incident_report, threat_analysis, threat_intel_context,
            )

    # ------------------------------------------------------------------
    # Path A — CRITICAL / HIGH: full remediation + human approval
    # ------------------------------------------------------------------
    def _handle_high_risk(
        llm,
        target_ip: str,
        risk_level: str,
        risk_score: int,
        category: str,
        incident_report: str,
        threat_analysis: dict,
        threat_intel_context: str,
        dry_run: bool,
    ) -> dict:
        """Generate technical remediation commands and request approval."""

        # ── Build context for the LLM ────────────────────────────────
        context_parts = [
            f"## Target IP\n{target_ip}",
            f"## Risk Score\n{risk_score}/10 ({risk_level})",
            f"## Threat Category\n{category}",
            f"## Incident Report (Nmap Scan Results)\n"
            f"```\n{incident_report[:4000]}\n```",
            f"## Threat Analysis\n{threat_analysis.get('analysis', 'N/A')}",
        ]
        if threat_intel_context:
            context_parts.append(
                f"## Relevant Threat Intelligence\n"
                f"{threat_intel_context[:1500]}"
            )
        full_context = "\n\n".join(context_parts)

        messages = [
            SystemMessage(content=RESPONSE_PROMPT_HIGH),
            HumanMessage(
                content=(
                    f"A threat (risk_score={risk_score}/10, "
                    f"category={category}) has been detected on "
                    f"{target_ip}. Generate a technical mitigation plan "
                    f"with executable commands:\n\n{full_context}"
                )
            ),
        ]

        response = llm.invoke(messages)
        mitigation_plan = response.content

        # ── Extract technical commands ────────────────────────────────
        final_remediation_plan = _extract_remediation_plan(
            mitigation_plan, target_ip, risk_score, category,
        )

        # ── Parse the individual command strings for execution ────────
        raw_commands = _parse_commands_from_plan(final_remediation_plan)

        # ── Execute (or dry-run) local shell commands via Action Executor ────
        mode_label = "DRY-RUN" if dry_run else "LIVE"
        print(f"\n[Response Agent] 🚀 Executing remediation plan "
              f"({mode_label}, {len(raw_commands)} command(s))…")
        command_results: list[ExecutionResult] = execute_remediation_plan(
            raw_commands, dry_run=dry_run
        )

        # ── Execute API-driven controls (firewall + EDR, optional SSH) ───
        print("[Response Agent] 🔌 Executing API-based response actions...")
        api_results: list[ExecutionResult] = execute_api_response_actions(
            target_ip=target_ip,
            dry_run=dry_run,
        )

        execution_results: list[ExecutionResult] = command_results + api_results
        execution_text = format_execution_results(execution_results)

        # ── Print the SECURITY ALERT banner ───────────────────────────
        _print_security_alert(
            target_ip, risk_score, risk_level, category,
            final_remediation_plan,
        )

        # ── Bold SECURITY ACTION PLAN GENERATED banner ────────────────
        _print_action_plan_banner(risk_level)

        # ── Append to the running incident report ─────────────────────
        report_section = (
            f"\n{'='*60}\n"
            f"INCIDENT RESPONSE — Mitigation Plan for {target_ip}\n"
            f"{'='*60}\n"
            f"{mitigation_plan}\n"
            f"\n{'─'*60}\n"
            f"FINAL REMEDIATION PLAN (extracted commands)\n"
            f"{'─'*60}\n"
            f"{final_remediation_plan}\n"
            f"\n{'─'*60}\n"
            f"EXECUTION RESULTS\n"
            f"{'─'*60}\n"
            f"{execution_text}\n"
        )
        updated_report = incident_report + report_section

        print(f"\n[Response Agent] Mitigation plan generated for "
              f"{target_ip}.")

        if approval_required:
            # Human approval already granted via interrupt_before in the
            # graph — this node only executes if the operator approved.
            decision = "Approved by Human Operator"
            print(f"\n{_CYAN}[Response Agent] ✅ Remediation plan "
                  f"APPROVED (via interrupt_before).{_RESET}")
        else:
            decision = "Approved by Policy — Auto-executed"
            print(f"\n{_GREEN}[Response Agent] ✅ Remediation plan "
                  f"AUTO-APPROVED (risk_score >= 9).{_RESET}")

        return {
            "response_plan":          mitigation_plan,
            "final_remediation_plan": final_remediation_plan,
            "execution_results":      execution_results,
            "incident_report":        updated_report,
            "final_decision":         decision,
            "messages": [
                HumanMessage(
                    content=f"[Response Agent]\n{mitigation_plan}"
                )
            ],
            "current_agent": "response",
        }

    # ------------------------------------------------------------------
    # Path B — LOW / MEDIUM: monitoring recommendations (no approval)
    # ------------------------------------------------------------------
    def _handle_low_risk(
        llm,
        target_ip: str,
        risk_level: str,
        risk_score: int,
        category: str,
        incident_report: str,
        threat_analysis: dict,
        threat_intel_context: str,
    ) -> dict:
        """Suggest monitoring — no blocking commands, no interrupt."""

        context_parts = [
            f"## Target IP\n{target_ip}",
            f"## Risk Score\n{risk_score}/10 ({risk_level})",
            f"## Threat Category\n{category}",
            f"## Incident Report (Nmap Scan Results)\n"
            f"```\n{incident_report[:4000]}\n```",
            f"## Threat Analysis\n{threat_analysis.get('analysis', 'N/A')}",
        ]
        if threat_intel_context:
            context_parts.append(
                f"## Relevant Threat Intelligence\n"
                f"{threat_intel_context[:1500]}"
            )
        full_context = "\n\n".join(context_parts)

        messages = [
            SystemMessage(content=RESPONSE_PROMPT_LOW),
            HumanMessage(
                content=(
                    f"The target {target_ip} has a {risk_level} risk "
                    f"(score={risk_score}/10, category={category}). "
                    f"Provide monitoring recommendations:\n\n"
                    f"{full_context}"
                )
            ),
        ]

        response = llm.invoke(messages)
        monitoring_plan = response.content

        # ── Bold SECURITY ACTION PLAN GENERATED banner ────────────────
        _print_action_plan_banner(risk_level)

        # ── Pretty-print the monitoring advice ────────────────────────
        _print_monitoring_summary(target_ip, risk_score, risk_level,
                                  category, monitoring_plan)

        # ── Append to the running incident report ─────────────────────
        report_section = (
            f"\n{'='*60}\n"
            f"INCIDENT RESPONSE — Monitoring Plan for {target_ip}\n"
            f"{'='*60}\n"
            f"{monitoring_plan}\n"
        )
        updated_report = incident_report + report_section

        print(f"\n[Response Agent] Monitoring plan generated for "
              f"{target_ip}.")

        return {
            "response_plan": monitoring_plan,
            "final_remediation_plan": "",
            "execution_results": [],
            "incident_report": updated_report,
            "final_decision": "No Action Required — Monitoring Recommended",
            "messages": [
                HumanMessage(
                    content=f"[Response Agent]\n{monitoring_plan}"
                )
            ],
            "current_agent": "response",
        }

    return response_node


# ---------------------------------------------------------------------------
# Parse individual command strings out of a formatted remediation plan
# ---------------------------------------------------------------------------
def _parse_commands_from_plan(plan_text: str) -> list[str]:
    """
    Extract the executable command strings from the output of
    :func:`_extract_remediation_plan`.

    The plan uses lines like::

        [01] iptables -A INPUT -s 10.0.0.50 -p tcp --dport 22 -j DROP
        [02] ufw deny from 10.0.0.50 to any port 22

    This function strips the ``[NN]`` prefix and returns bare commands.
    Falls back to scanning for raw command prefixes if no bracketed lines
    are found (e.g. when the LLM fallback section was used).
    """
    commands: list[str] = []
    # Primary pattern — lines produced by _extract_remediation_plan
    bracket_re = re.compile(r"^\s*\[\d+\]\s+(.+)$")
    for line in plan_text.splitlines():
        m = bracket_re.match(line)
        if m:
            cmd = m.group(1).strip()
            if cmd:
                commands.append(cmd)

    if commands:
        return commands

    # Fallback — scan for raw command prefixes (same patterns as
    # _extract_remediation_plan so we don't duplicate logic)
    raw_patterns = [
        re.compile(r"^\s*(iptables\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(ufw\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(aws\s+ec2\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(systemctl\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(apt-get\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(yum\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(dnf\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(sudo\s.+)", re.IGNORECASE),
    ]
    for line in plan_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            continue
        for pat in raw_patterns:
            m = pat.match(stripped)
            if m:
                cmd = m.group(1).strip()
                if cmd and cmd not in commands:
                    commands.append(cmd)
                break
    return commands


# ---------------------------------------------------------------------------
# Bold SECURITY ACTION PLAN GENERATED banner
# ---------------------------------------------------------------------------
def _print_action_plan_banner(risk_level: str) -> None:
    """Print the bold **SECURITY ACTION PLAN GENERATED** banner."""
    border = "═" * 60

    color = _RED if risk_level in ("CRITICAL", "HIGH") else _CYAN

    print(f"\n{color}{_BOLD}")
    print(f"╔{border}╗")
    print(f"║{'SECURITY ACTION PLAN GENERATED':^60}║")
    print(f"║{'Risk Level: ' + risk_level:^60}║")
    print(f"╚{border}╝")
    print(f"{_RESET}")


# ---------------------------------------------------------------------------
# Extract structured remediation plan from LLM output
# ---------------------------------------------------------------------------
def _extract_remediation_plan(
    llm_output: str,
    target_ip: str,
    risk_score: int,
    category: str,
) -> str:
    """
    Parse the LLM's mitigation plan and extract all executable commands
    into a clean, structured remediation plan string.

    Pulls out:
    - iptables commands
    - ufw commands
    - aws ec2 commands
    - systemctl / apt-get / yum commands
    - Any other shell commands (lines starting with $ or #)
    """
    lines = llm_output.splitlines()
    commands: list[str] = []

    # Patterns that indicate an executable command
    command_patterns = [
        re.compile(r"^\s*(iptables\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(ufw\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(aws\s+ec2\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(systemctl\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(apt-get\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(yum\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(dnf\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(firewall-cmd\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(nft\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(service\s.+)", re.IGNORECASE),
        re.compile(r"^\s*(sudo\s.+)", re.IGNORECASE),
        re.compile(r"^\s*\$\s*(.+)"),          # lines starting with $
        re.compile(r"^\s*#\s*(iptables.+)"),    # commented iptables examples
    ]

    for line in lines:
        stripped = line.strip()
        # Skip markdown fences
        if stripped.startswith("```"):
            continue
        for pattern in command_patterns:
            match = pattern.match(stripped)
            if match:
                cmd = match.group(1).strip()
                if cmd and cmd not in commands:
                    commands.append(cmd)
                break

    # Build the structured plan
    header = (
        f"FINAL REMEDIATION PLAN\n"
        f"{'─'*50}\n"
        f"Target IP : {target_ip}\n"
        f"Risk Score: {risk_score}/10\n"
        f"Category  : {category}\n"
        f"Status    : Awaiting Human Approval\n"
        f"{'─'*50}\n"
    )

    if commands:
        cmd_section = "EXECUTABLE COMMANDS:\n"
        for i, cmd in enumerate(commands, 1):
            cmd_section += f"  [{i:02d}] {cmd}\n"
    else:
        # Fallback: if we couldn't parse specific commands, include the
        # full Technical Remediation Commands section from the LLM output.
        tech_section = _extract_section(
            llm_output, "TECHNICAL REMEDIATION COMMANDS"
        )
        if tech_section:
            cmd_section = f"TECHNICAL REMEDIATION COMMANDS:\n{tech_section}\n"
        else:
            cmd_section = (
                "No specific commands could be auto-extracted.\n"
                "Review the full mitigation plan above for manual steps.\n"
            )

    return header + cmd_section


def _extract_section(text: str, heading: str) -> str:
    """Extract content between a markdown heading and the next heading."""
    pattern = re.compile(
        rf"###?\s*{re.escape(heading)}\s*\n(.*?)(?=\n###?\s|\nSUGGESTED_ACTIONS_COMPLETE|\Z)",
        re.DOTALL | re.IGNORECASE,
    )
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


# ---------------------------------------------------------------------------
# Console output — red SECURITY ALERT (CRITICAL / HIGH only)
# ---------------------------------------------------------------------------
def _print_security_alert(
    target_ip: str,
    risk_score: int,
    risk_level: str,
    category: str,
    remediation_plan: str,
) -> None:
    """
    Print a formatted SECURITY ALERT to the console in **red text**
    using ANSI escape codes.  Only called for CRITICAL / HIGH risk.
    """
    border = "═" * 62
    thin = "─" * 62

    print(f"\n{_RED}{_BOLD}")
    print(f"╔{border}╗")
    print(f"║{'🚨  SECURITY ALERT  🚨':^62}║")
    print(f"╠{border}╣")
    print(f"║  {'Target IP':16}: {target_ip:<42} ║")
    print(f"║  {'Risk Score':16}: {str(risk_score) + '/10':42} ║")
    print(f"║  {'Risk Level':16}: {risk_level:<42} ║")
    print(f"║  {'Category':16}: {category:<42} ║")
    print(f"║  {'Threat Detected':16}: {'YES':<42} ║")
    print(f"╠{border}╣")
    print(f"║  {'ACTION REQUIRED — HUMAN APPROVAL NEEDED':^60} ║")
    print(f"╚{border}╝")
    print(f"{_RESET}")

    # Print the extracted commands in yellow for visibility
    print(f"{_YELLOW}{_BOLD}{thin}")
    print("SUGGESTED REMEDIATION COMMANDS")
    print(f"{thin}{_RESET}")

    # Print each line of the remediation plan, highlighting commands
    for line in remediation_plan.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and "]" in stripped:
            # Command lines like [01] iptables ...
            print(f"  {_CYAN}{line}{_RESET}")
        elif stripped.startswith("EXECUTABLE") or stripped.startswith("FINAL"):
            print(f"  {_YELLOW}{_BOLD}{line}{_RESET}")
        elif stripped.startswith("─"):
            print(f"  {_YELLOW}{line}{_RESET}")
        else:
            print(f"  {line}")

    print(f"{_YELLOW}{thin}{_RESET}\n")


# ---------------------------------------------------------------------------
# Console output — monitoring summary (LOW / MEDIUM)
# ---------------------------------------------------------------------------
def _print_monitoring_summary(
    target_ip: str,
    risk_score: int,
    risk_level: str,
    category: str,
    monitoring_plan: str,
) -> None:
    """Print a formatted monitoring summary for LOW / MEDIUM risk."""
    thin = "─" * 62

    print(f"\n{_GREEN}{_BOLD}{thin}")
    print(f"  MONITORING PLAN — {target_ip}")
    print(f"  Risk: {risk_score}/10 ({risk_level}) | Category: {category}")
    print(f"{thin}{_RESET}")

    for line in monitoring_plan.splitlines():
        stripped = line.strip()
        if stripped.startswith("###"):
            print(f"  {_CYAN}{_BOLD}{stripped}{_RESET}")
        elif stripped.startswith("-") or stripped.startswith("*"):
            print(f"  {_YELLOW}{stripped}{_RESET}")
        else:
            print(f"  {stripped}")

    print(f"{_GREEN}{thin}{_RESET}\n")
