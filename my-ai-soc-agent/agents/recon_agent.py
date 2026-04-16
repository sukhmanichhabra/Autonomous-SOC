"""
Reconnaissance Agent
====================
The first agent in the pipeline. Performs network scanning using Nmap
**and** web technology fingerprinting to discover hosts, open ports,
running services, server software, frameworks, and security header
posture on the target.
"""

import re
import os

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agents.state import AgentState
from tools.recon_toolkit import run_quick_scan, scan_web_tech
from tools.cve_lookup import scan_web_headers
from config import settings


RECON_SYSTEM_PROMPT = """You are an expert cybersecurity reconnaissance agent working as part of a Security Operations Center (SOC).

Your role is to:
1. Analyze network scan results to identify open ports, running services, and their versions.
2. Analyze web technology fingerprinting results to identify the server software, web frameworks, CMS platforms, JavaScript libraries, and security headers in use.
3. Highlight any services running outdated or vulnerable versions.
4. Flag missing security headers and their implications.
5. Identify potential attack surfaces based on the exposed services and technologies.
6. Provide a structured summary of your findings.

Format your analysis as:
- **Open Ports & Services**: List all discovered ports and services.
- **Web Technologies**: Summarize the detected server software, frameworks, libraries, and CMS.
- **Security Header Audit**: Note which security headers are present and which critical ones are missing.
- **Potential Vulnerabilities**: Flag any concerning findings.
- **Attack Surface Assessment**: Summarize the overall exposure.
- **Recommendations**: Suggest immediate actions for the next agent.

Be thorough, precise, and focus on actionable intelligence."""


def create_recon_agent(model_name: str | None = None):
    """
    Create the Reconnaissance Agent node function.

    Args:
        model_name: Groq model to use.

    Returns:
        A function that can be used as a LangGraph node.
    """
    resolved_model = model_name or os.getenv("GROQ_MODEL_MAIN", settings.groq_model_main)
    groq_api_key = os.getenv("GROQ_API_KEY", settings.groq_api_key)
    llm = ChatGroq(model=resolved_model, temperature=0, api_key=groq_api_key)

    def recon_node(state: AgentState) -> AgentState:
        """
        Execute reconnaissance scanning and analysis.

        1. Reads ``target_ip`` from the incoming state.
        2. Calls ``run_quick_scan`` for Nmap service-detection.
        3. Calls ``scan_web_tech`` to fingerprint web technologies on
           port 80/443.
        4. Combines both outputs into the state's ``incident_report``.
        5. Asks the LLM to produce a structured analysis of all results.
        6. Returns the updated state with ``scan_results`` and
           ``web_tech_results``.
        """
        # --- resolve target IP (prefer target_ip, fall back to target) ---
        target_ip = state.get("target_ip") or state.get("target", "127.0.0.1")
        stealth = bool(state.get("stealth_mode", False))
        nmap_path = os.getenv("NMAP_PATH", settings.nmap_path)

        print(f"\n{'='*60}")
        print(f"[Recon Agent] Starting reconnaissance on target: {target_ip}")
        print(f"[Recon Agent] Nmap path: {nmap_path}")
        if stealth:
            print(f"[Recon Agent] 🥷 Stealth mode ENABLED — using -sS -T2 -f")
        print(f"{'='*60}")

        # --- 1. Nmap service-detection scan ---
        print(f"\n[Recon Agent] Phase 1: Nmap "
              f"{'stealth SYN' if stealth else 'service-detection'} scan")
        raw_scan_output = run_quick_scan(target_ip, stealth=stealth)

        # --- 1b. Web header scan — if port 80 or 443 is open ----------
        #
        # We check the Nmap text output for lines that indicate port
        # 80 or 443 is open (e.g. "80  open  http" / "443  open  https").
        # If found we call scan_web_headers() from cve_lookup and append
        # the results to raw_scan_output so the Threat Analysis agent
        # receives web-technology context automatically.
        _WEB_PORT_RE = re.compile(r"\b(80|443)\b\s+open\b", re.IGNORECASE)
        if _WEB_PORT_RE.search(raw_scan_output):
            print(f"\n[Recon Agent] Phase 1b: Web port(s) detected — "
                  f"running HTTP header scan on {target_ip}")
            web_headers = scan_web_headers(target_ip)
            if web_headers:
                hdr_lines = [
                    "",
                    "=" * 50,
                    f"Web Header Scan — {target_ip}",
                    "=" * 50,
                ]
                if web_headers.get("server"):
                    hdr_lines.append(f"  Server            : {web_headers['server']}")
                if web_headers.get("x_powered_by"):
                    hdr_lines.append(f"  X-Powered-By      : {web_headers['x_powered_by']}")
                for hdr_name, hdr_val in web_headers.get("technologies", {}).items():
                    if hdr_name not in ("Server", "X-Powered-By"):
                        hdr_lines.append(f"  {hdr_name:<20}: {hdr_val}")
                if web_headers.get("security_headers_present"):
                    hdr_lines.append(f"  Security headers ✓: "
                                     f"{', '.join(web_headers['security_headers_present'])}")
                if web_headers.get("security_headers_missing"):
                    hdr_lines.append(f"  Security headers ✗: "
                                     f"{', '.join(web_headers['security_headers_missing'])}")
                if web_headers.get("endpoints_reached"):
                    hdr_lines.append(f"  Endpoints reached : "
                                     f"{', '.join(web_headers['endpoints_reached'])}")
                hdr_lines.append("")
                raw_scan_output += "\n" + "\n".join(hdr_lines)
                print(f"[Recon Agent] Web header findings appended to scan results")
            else:
                print(f"[Recon Agent] Web header scan returned no data")
        else:
            print(f"\n[Recon Agent] No web ports (80/443) detected — "
                  f"skipping HTTP header scan")

        # --- 2. Web technology fingerprinting ---
        print(f"\n[Recon Agent] Phase 2: Web technology fingerprinting")
        web_tech = scan_web_tech(target_ip)
        web_tech_raw = web_tech.get("raw_output", "")
        web_tech_techs = web_tech.get("technologies_found", [])
        web_tech_missing = web_tech.get("missing_security_headers", [])

        if web_tech.get("error"):
            print(f"[Recon Agent] Web tech scan note: {web_tech['error']}")
        else:
            print(f"[Recon Agent] Detected {len(web_tech_techs)} web "
                  f"technolog{'y' if len(web_tech_techs) == 1 else 'ies'}")
            if web_tech_missing:
                print(f"[Recon Agent] Missing security headers: "
                      f"{', '.join(web_tech_missing)}")

        # --- 3. Build / append to the running incident report ---
        existing_report = state.get("incident_report", "") or ""
        report_section = (
            f"\n{'='*60}\n"
            f"RECONNAISSANCE SCAN — {target_ip}\n"
            f"{'='*60}\n"
            f"{raw_scan_output}\n"
            f"\n{'='*60}\n"
            f"WEB TECHNOLOGY FINGERPRINT — {target_ip}\n"
            f"{'='*60}\n"
            f"{web_tech_raw}\n"
        )
        updated_report = existing_report + report_section

        # --- 4. LLM analysis of combined results ---
        combined_context = (
            f"## Nmap Scan Results\n```\n{raw_scan_output}\n```\n\n"
            f"## Web Technology Fingerprinting\n```\n{web_tech_raw}\n```"
        )

        messages = [
            SystemMessage(content=RECON_SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Analyze the following reconnaissance results for "
                    f"target {target_ip}:\n\n{combined_context}"
                )
            ),
        ]
        response = llm.invoke(messages)

        print(f"\n[Recon Agent] Analysis complete.")

        # --- 5. Return the updated state ---
        return {
            "target_ip": target_ip,
            "scan_results": {"raw_output": raw_scan_output},
            "web_tech_results": web_tech,
            "incident_report": updated_report,
            "messages": [HumanMessage(content=f"[Recon Agent]\n{response.content}")],
            "current_agent": "recon",
        }

    return recon_node
