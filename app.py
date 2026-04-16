#!/usr/bin/env python3
"""
Streamlit Dashboard — Autonomous Cybersecurity Defense Agent
============================================================
A modern web UI that wraps the LangGraph 3-agent pipeline
(Recon → Threat Analysis → Response) with real-time progress,
human-in-the-loop approval, and a three-column results view.

Launch:
    streamlit run app.py
"""

import sys
import os
import uuid
import sqlite3

# ---------------------------------------------------------------------------
# Make the project package importable
# ---------------------------------------------------------------------------
PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "my-ai-soc-agent")
sys.path.insert(0, PROJECT_DIR)

import streamlit as st
from dotenv import load_dotenv

# Load .env from the project folder (fallback values)
load_dotenv(os.path.join(PROJECT_DIR, ".env"))

from langgraph.checkpoint.postgres import PostgresSaver

from config import settings, ensure_directories_exist
from checkpointer import get_postgres_connection, validate_database_connection
from main import build_graph, make_thread_id
from agents.state import AgentState
from incident_io import save_incident
from tools.report_generator import save_incident_bundle

# Ensure directories exist on startup
ensure_directories_exist()

# Normalize key runtime environment variables for downstream tools/agents.
os.environ.setdefault("NMAP_PATH", os.getenv("NMAP_PATH", settings.nmap_path))
os.environ.setdefault("DB_URL", os.getenv("DB_URL", settings.db_url))

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="AI Cybersecurity Defense Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* Global */
    .block-container { padding-top: 2rem; }

    /* Header */
    .main-header {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
        padding: 1.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        border: 1px solid #3a3a5c;
    }
    .main-header h1 {
        color: #00d4ff;
        margin: 0;
        font-size: 1.8rem;
    }
    .main-header p {
        color: #a0a0c0;
        margin: 0.3rem 0 0 0;
        font-size: 0.95rem;
    }

    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid #2a2a4a;
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
    }
    .metric-card h3 { color: #8892b0; margin: 0; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; }
    .metric-card .value { font-size: 2rem; font-weight: 700; margin: 0.4rem 0; }
    .metric-card .sub { color: #6a6a8a; font-size: 0.8rem; }

    /* Risk colours */
    .risk-critical { color: #ff4757; }
    .risk-low      { color: #ffa502; }
    .risk-none     { color: #2ed573; }

    /* Agent column headers */
    .agent-header {
        background: #1a1a2e;
        border: 1px solid #2a2a4a;
        border-radius: 8px;
        padding: 0.8rem 1rem;
        margin-bottom: 0.8rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .agent-header .icon { font-size: 1.4rem; }
    .agent-header .title { font-weight: 600; font-size: 1rem; }

    /* Approval banner */
    .approval-box {
        background: linear-gradient(135deg, #2d1b00 0%, #3d2400 100%);
        border: 2px solid #ff9f43;
        border-radius: 10px;
        padding: 1.5rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown("""
<div class="main-header">
    <h1>🛡️ AI Cybersecurity Defense Agent</h1>
    <p>Autonomous threat detection powered by LangGraph &nbsp;·&nbsp; Recon → Threat Analysis → Response</p>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## ⚙️ Configuration")
    st.markdown("---")

    api_key = st.text_input(
        "🔑 Groq API Key",
        type="password",
        value=os.getenv("GROQ_API_KEY", settings.groq_api_key),
        help="Your Groq API key. Stored only for this session.",
    )

    model_name = st.selectbox(
        "🤖 Model",
        ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
        index=0,
        help="Groq model used by all three agents.",
    )

    st.markdown("---")
    st.markdown("## 🎯 Target")

    target_ip = st.text_input(
        "Target IP / Hostname",
        value=os.getenv("SCAN_TARGET", "127.0.0.1"),
        help="The IP address or hostname to scan.",
    )

    st.markdown("---")
    st.markdown("## 📦 Options")

    seed_db = st.checkbox(
        "Seed threat-intel DB",
        value=False,
        help="Pre-populate the ChromaDB vector store with sample MITRE ATT&CK data.",
    )

    stealth_mode = st.checkbox(
        "🥷 Stealth Mode",
        value=False,
        help=(
            "Use SYN Stealth scan (-sS -T2 -f) instead of service-version "
            "detection (-sV). Evades simple firewalls and IDS/IPS but "
            "returns less version information."
        ),
    )

    st.markdown("---")
    st.markdown("### ⚡ Execution Mode")
    default_dry_run = os.getenv("DRY_RUN", str(settings.dry_run)).strip().lower() in (
        "1", "true", "yes", "on"
    )
    live_execution = st.checkbox(
        "🔴 Live Execution",
        value=not default_dry_run,
        help=(
            "**DANGER — only enable after reviewing the threat report.**\n\n"
            "When OFF (default) every remediation command is simulated "
            "(dry-run) and no changes are made to the host.\n\n"
            "When ON, approved iptables / ufw / systemctl commands are "
            "executed directly on this machine via subprocess."
        ),
    )
    if live_execution:
        st.warning(
            "⚠️ **Live Execution is ON.** Approved commands will modify "
            "the host firewall and services.",
            icon="⚠️",
        )
    else:
        st.info("🔵 Dry-run mode — commands will be simulated only.", icon="ℹ️")

    st.markdown("---")
    run_clicked = st.button(
        "🚀 Run Security Audit",
        type="primary",
        use_container_width=True,
    )

    st.markdown("---")
    st.caption("Built with LangGraph · LangChain · ChromaDB")


# ---------------------------------------------------------------------------
# Helper: risk colour
# ---------------------------------------------------------------------------
def _risk_css(level: str) -> str:
    level = (level or "").upper()
    if level == "CRITICAL":
        return "risk-critical"
    if level == "LOW":
        return "risk-low"
    return "risk-none"


# ---------------------------------------------------------------------------
# Helper: run the pipeline with st.status progress updates
# ---------------------------------------------------------------------------
DB_PATH = os.getenv("DB_URL", settings.db_url)


@st.cache_resource
def get_checkpointer() -> PostgresSaver:
    """
    Create a PostgreSQL checkpointer for LangGraph state persistence.

    Using ``@st.cache_resource`` means this function runs exactly once
    per server process, caching the checkpointer instance.
    
    Returns:
        PostgresSaver instance for production-ready state management.
        
    Raises:
        Exception: If PostgreSQL connection fails.
    """
    from checkpointer import create_postgres_checkpointer, validate_database_connection
    
    # Validate connection before creating checkpointer
    if not validate_database_connection():
        raise RuntimeError(
            "PostgreSQL connection failed. "
            "Run: python my-ai-soc-agent/init_db.py"
        )
    
    return create_postgres_checkpointer()


def get_worker_checkpointer() -> PostgresSaver:
    """
    Create a PostgreSQL checkpointer for non-Streamlit workers.

    This uses the same checkpointer module and DB URL resolution
    as the Streamlit dashboard so checkpoint history stays shared.
    """
    from checkpointer import create_postgres_checkpointer, validate_database_connection

    if not validate_database_connection():
        raise RuntimeError(
            "PostgreSQL connection failed. "
            "Run: python my-ai-soc-agent/init_db.py"
        )

    return create_postgres_checkpointer()


def get_compiled_graph_for_worker(checkpointer: PostgresSaver, model_name: str | None = None):
    """Compile the app graph for background workers using the same pipeline."""
    selected_model = model_name or os.getenv("GROQ_MODEL_MAIN", settings.groq_model_main)
    return build_graph(model_name=selected_model, checkpointer=checkpointer)


def run_pipeline(target: str, model: str, api_key_val: str, do_seed: bool, stealth: bool = False, live_exec: bool = False):
    """Execute the 3-agent LangGraph pipeline and return the final state."""

    # Set the API key for this run
    os.environ["GROQ_API_KEY"] = api_key_val

    # Optionally seed the vector DB
    if do_seed:
        with st.status("📦 Seeding threat intelligence database…", expanded=False) as seed_status:
            try:
                from vector_db.pgvector_store import ThreatIntelStore
                store = ThreatIntelStore()
                store.seed_sample_data()
                seed_status.update(label="📦 Threat intel DB seeded ✅", state="complete")
            except Exception as exc:
                seed_status.update(label=f"⚠️ Could not seed threat intel DB: {exc}", state="error")

    thread_id = make_thread_id(target, f"streamlit-{target}-{uuid.uuid4().hex[:8]}")

    checkpointer = get_checkpointer()
    graph = build_graph(model_name=model, checkpointer=checkpointer)
    config = {"configurable": {"thread_id": thread_id}}

    initial_state: AgentState = {
        "messages": [],
        "target": target,
        "target_ip": target,
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
        "stealth_mode": stealth,
        "dry_run": not live_exec,
        "execution_results": [],
        "current_agent": "",
        "confidence_score": 0.0,
        "incident_logs": [],
        "raw_log_data": "",
        "is_vulnerable": False,
    }

    # ── Run the full pipeline with real-time progress ─────────
    final_state = None
    with st.status("🔍 Running security audit…", expanded=True) as status:

        # — Step 1: Recon —
        status.update(label="🔍 Agent 1/3 — Reconnaissance: scanning target…")
        st.write(f"📡 Scanning **{target}** with Nmap service detection…")

        final_state = graph.invoke(initial_state, config)

        # Show recon result snippet
        scan_raw = final_state.get("scan_results", {}).get("raw_output", "")
        if scan_raw:
            st.code(scan_raw[:500], language="text")

        # — Step 2: Threat Analysis —
        status.update(label="🧠 Agent 2/3 — Threat Analysis: correlating with MITRE ATT&CK…")
        risk_score = final_state.get("risk_score", 0)
        risk_level = final_state.get("risk_level", "NONE")
        category = final_state.get("category", "")
        threat_detected = final_state.get("threat_detected", False)
        st.write(f"📊 Risk Score: **{risk_score}/10** ({risk_level}) — Category: **{category}**")

        # — Step 3: Response —
        if threat_detected:
            status.update(label="🚨 Agent 3/3 — Response: generating mitigation plan…")
            st.write("⚠️ Threat detected — remediation plan generated.")
            status.update(label="⏸️ Awaiting human approval…", state="running")
        else:
            status.update(label="✅ Audit complete — no critical threats detected", state="complete")
            st.write("✅ No critical threats — skipping incident response.")

    # ── Check for interrupt (human approval via interrupt_before) ──
    graph_state = graph.get_state(config)
    has_interrupt = graph_state.next and "response" in graph_state.next

    if has_interrupt:
        # Store graph + config in session state so the approval
        # buttons can resume the execution on a subsequent rerun.
        st.session_state["pending_graph"] = graph
        st.session_state["pending_config"] = config
        st.session_state["awaiting_approval"] = True
        # Store the paused state for display in the approval widget
        paused_state = graph_state.values
        st.session_state["interrupt_payload"] = {
            "question": "Do you approve running the Response Agent?",
            "target_ip": paused_state.get("target_ip", "N/A"),
            "risk_score": paused_state.get("risk_score", 0),
            "risk_level": paused_state.get("risk_level", "UNKNOWN"),
            "category": paused_state.get("category", "N/A"),
        }
    else:
        st.session_state["awaiting_approval"] = False
        # Pipeline completed without interrupt — save artefacts now
        save_incident(thread_id, final_state)
        save_incident_bundle(final_state, thread_id)

    st.session_state["thread_id"] = thread_id
    st.session_state["final_state"] = final_state
    st.session_state["audit_done"] = True


# ---------------------------------------------------------------------------
# Trigger the audit
# ---------------------------------------------------------------------------
if run_clicked:
    if not api_key:
        st.error("🔑 Please enter your OpenAI API Key in the sidebar.")
        st.stop()
    if not target_ip:
        st.error("🎯 Please enter a target IP address in the sidebar.")
        st.stop()

    # Reset state
    for key in ["final_state", "audit_done", "awaiting_approval",
                "pending_graph", "pending_config", "pending_state",
                "interrupt_payload", "approval_processed", "thread_id"]:
        st.session_state.pop(key, None)

    run_pipeline(target_ip, model_name, api_key, seed_db, stealth=stealth_mode, live_exec=live_execution)


# ---------------------------------------------------------------------------
# Human-in-the-loop approval widget
# ---------------------------------------------------------------------------
if st.session_state.get("awaiting_approval") and not st.session_state.get("approval_processed"):
    payload = st.session_state.get("interrupt_payload", {})

    st.markdown("---")
    st.markdown("""
    <div class="approval-box">
        <h3 style="color:#ff9f43; margin-top:0;">⏸️ Human Approval Required</h3>
        <p style="color:#ddd;">The Response Agent has generated a remediation plan and is awaiting your approval before finalising.</p>
    </div>
    """, unsafe_allow_html=True)

    col_a, col_b, col_c = st.columns([2, 1, 1])
    with col_a:
        st.info(
            f"**{payload.get('question', 'Do you approve the remediation plan?')}**\n\n"
            f"Target: `{payload.get('target_ip', 'N/A')}` · "
            f"Risk: **{payload.get('risk_score', '?')}/10** · "
            f"Category: **{payload.get('category', 'N/A')}**"
        )
    with col_b:
        if st.button("✅ Approve", type="primary", use_container_width=True):
            st.session_state["approval_answer"] = "y"
            st.session_state["approval_processed"] = True
            st.rerun()
    with col_c:
        if st.button("❌ Reject", type="secondary", use_container_width=True):
            st.session_state["approval_answer"] = "n"
            st.session_state["approval_processed"] = True
            st.rerun()


# ---------------------------------------------------------------------------
# Process the approval answer (runs on rerun after button click)
# ---------------------------------------------------------------------------
if st.session_state.get("approval_processed") and st.session_state.get("pending_graph"):
    graph = st.session_state["pending_graph"]
    config = st.session_state["pending_config"]
    answer = st.session_state.get("approval_answer", "n")

    with st.status(
        "✅ Applying approval…" if answer == "y" else "❌ Applying rejection…",
        expanded=False,
    ) as resume_status:
        if answer == "y":
            # Resume: let the response node execute
            final_state = graph.invoke(None, config)
        else:
            # Rejected: update state directly, skip response node
            graph.update_state(
                config,
                {
                    "final_decision": "Rejected by Human Operator",
                    "response_plan": "",
                    "final_remediation_plan": "",
                    "current_agent": "response",
                },
                as_node="response",
            )
            final_state = graph.get_state(config).values
        label = "✅ Remediation plan approved — audit finalised." if answer == "y" \
                else "❌ Remediation plan rejected — audit finalised."
        resume_status.update(label=label, state="complete")

    st.session_state["final_state"] = final_state
    st.session_state["audit_done"] = True
    st.session_state["awaiting_approval"] = False

    # Persist incident artefacts after approval / rejection
    tid = st.session_state.get("thread_id", "unknown")
    save_incident(tid, final_state)
    save_incident_bundle(final_state, tid)

    for key in ["pending_graph", "pending_config", "pending_state"]:
        st.session_state.pop(key, None)


# ---------------------------------------------------------------------------
# Display results
# ---------------------------------------------------------------------------
if st.session_state.get("audit_done") and st.session_state.get("final_state"):
    state = st.session_state["final_state"]

    target = state.get("target_ip") or state.get("target", "N/A")
    risk_score = state.get("risk_score", 0)
    risk_level = state.get("risk_level", "NONE")
    category = state.get("category", "N/A")
    threat_detected = state.get("threat_detected", False)
    final_decision = state.get("final_decision", "")

    # ── Metric cards ──────────────────────────────────────────────
    st.markdown("---")
    m1, m2, m3, m4, m5 = st.columns(5)
    risk_class = _risk_css(risk_level)

    with m1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>Target</h3>
            <div class="value" style="font-size:1.3rem; color:#00d4ff;">{target}</div>
        </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
        <div class="metric-card">
            <h3>Risk Score</h3>
            <div class="value {risk_class}">{risk_score}/10</div>
        </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div class="metric-card">
            <h3>Risk Level</h3>
            <div class="value {risk_class}">{risk_level}</div>
        </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
        <div class="metric-card">
            <h3>Category</h3>
            <div class="value" style="font-size:1rem; color:#a78bfa;">{category}</div>
        </div>
        """, unsafe_allow_html=True)
    with m5:
        decision_color = "#2ed573" if "Approved" in final_decision else (
            "#ff4757" if "Rejected" in final_decision else "#ffa502"
        )
        st.markdown(f"""
        <div class="metric-card">
            <h3>Decision</h3>
            <div class="value" style="font-size:0.9rem; color:{decision_color};">{final_decision or 'N/A'}</div>
        </div>
        """, unsafe_allow_html=True)

    # ── Three-column agent output ─────────────────────────────────
    st.markdown("---")
    col1, col2, col3 = st.columns(3)

    # — Column 1: Recon Results —
    with col1:
        st.markdown("""
        <div class="agent-header">
            <span class="icon">🔍</span>
            <span class="title">Recon Results</span>
        </div>
        """, unsafe_allow_html=True)

        scan_raw = state.get("scan_results", {}).get("raw_output", "")
        if scan_raw:
            st.code(scan_raw, language="text")
        else:
            st.info("No raw scan output available.")

        # Show web technology fingerprinting results
        web_tech = state.get("web_tech_results", {}) or {}
        web_tech_raw = web_tech.get("raw_output", "")
        web_tech_techs = web_tech.get("technologies_found", [])
        web_tech_missing = web_tech.get("missing_security_headers", [])

        if web_tech_techs or web_tech_raw:
            with st.expander("🌐 Web Technology Fingerprint", expanded=True):
                if web_tech_techs:
                    st.markdown("**Detected Technologies:** " + ", ".join(
                        f"`{t}`" for t in web_tech_techs
                    ))
                if web_tech_missing:
                    st.markdown("**Missing Security Headers:** " + ", ".join(
                        f"⚠️ `{h}`" for h in web_tech_missing
                    ))
                if web_tech_raw:
                    st.code(web_tech_raw, language="text")
        elif web_tech.get("error"):
            st.caption(f"🌐 Web tech scan: {web_tech['error']}")

        # Show LLM's recon analysis from messages
        recon_msg = ""
        for msg in state.get("messages", []):
            content = msg.content if hasattr(msg, "content") else str(msg)
            if "[Recon Agent]" in content:
                recon_msg = content.replace("[Recon Agent]\n", "").replace("[Recon Agent]", "")
                break
        if recon_msg:
            with st.expander("📄 Recon Agent Analysis", expanded=False):
                st.markdown(recon_msg)

    # — Column 2: Threat Analysis —
    with col2:
        st.markdown("""
        <div class="agent-header">
            <span class="icon">🧠</span>
            <span class="title">Threat Analysis</span>
        </div>
        """, unsafe_allow_html=True)

        # Risk bar
        risk_pct = risk_score * 10
        bar_colour = "#ff4757" if risk_score >= 7 else ("#ffa502" if risk_score >= 4 else "#2ed573")
        st.markdown(f"""
        <div style="background:#1a1a2e; border-radius:8px; padding:1rem; margin-bottom:0.8rem; border:1px solid #2a2a4a;">
            <div style="display:flex; justify-content:space-between; margin-bottom:0.3rem;">
                <span style="color:#8892b0; font-size:0.85rem;">Risk Score</span>
                <span style="color:{bar_colour}; font-weight:700;">{risk_score}/10</span>
            </div>
            <div style="background:#2a2a4a; border-radius:4px; height:10px; overflow:hidden;">
                <div style="background:{bar_colour}; width:{risk_pct}%; height:100%; border-radius:4px; transition:width 0.5s;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if threat_detected:
            st.error(f"🚨 **Threat Detected** — {category}")
        else:
            st.success("✅ No critical threat detected")

        # Threat Summary — plain-English paragraph from the SOC Analyst
        threat_summary = state.get("threat_summary", "")
        if threat_summary:
            st.markdown(f"""
            <div style="background:#1a1a2e; border:1px solid #2a2a4a; border-radius:8px;
                        padding:0.9rem 1rem; margin-bottom:0.8rem;">
                <p style="color:#8892b0; font-size:0.75rem; margin:0 0 0.4rem 0;
                           text-transform:uppercase; letter-spacing:1px;">
                    🗒️ Threat Summary
                </p>
                <p style="color:#c8d3f5; font-size:0.9rem; margin:0; line-height:1.5;">
                    {threat_summary}
                </p>
            </div>
            """, unsafe_allow_html=True)

        threat = state.get("threat_analysis", {})
        analysis_text = threat.get("analysis", "")
        if analysis_text:
            with st.expander("📝 Full Threat Analysis", expanded=True):
                st.markdown(analysis_text)

        # Show the structured threat_analysis_report
        threat_analysis_report = state.get("threat_analysis_report", "")
        if threat_analysis_report:
            with st.expander("📄 Threat Analysis Report", expanded=False):
                st.code(threat_analysis_report, language="text")

        intel_matches = threat.get("threat_intel_matches", 0)
        if intel_matches:
            st.caption(f"🔗 {intel_matches} threat intel matches from vector DB")

    # — Column 3: Response Plan —
    with col3:
        st.markdown("""
        <div class="agent-header">
            <span class="icon">🚨</span>
            <span class="title">Response Plan</span>
        </div>
        """, unsafe_allow_html=True)

        response_plan = state.get("response_plan", "")
        remediation = state.get("final_remediation_plan", "")

        if not threat_detected:
            st.success("No incident response required — risk level is acceptable.")
        else:
            if final_decision:
                if "Approved" in final_decision:
                    st.success(f"📌 **{final_decision}**")
                elif "Rejected" in final_decision:
                    st.error(f"📌 **{final_decision}**")
                else:
                    st.warning(f"📌 **{final_decision}**")

            if remediation:
                st.markdown("**🛠️ Remediation Commands**")
                st.code(remediation, language="bash")

            if response_plan:
                with st.expander("📋 Full Response Plan", expanded=False):
                    st.markdown(response_plan)

    # ── Full incident report (collapsible) ────────────────────────
    st.markdown("---")
    incident_report = state.get("incident_report", "")
    if incident_report:
        with st.expander("📄 Full Incident Report", expanded=False):
            st.text(incident_report)

    # ── Execution Results panel ───────────────────────────────────
    exec_results: list = state.get("execution_results", []) or []
    if exec_results:
        st.markdown("---")
        st.markdown("### ⚡ Action Executor — Execution Results")

        # Summary metrics
        statuses = [r.get("status", "") for r in exec_results]
        n_dry     = statuses.count("DRY_RUN")
        n_ok      = statuses.count("SUCCESS")
        n_fail    = statuses.count("FAILED")
        n_blocked = statuses.count("BLOCKED")
        n_other   = len(statuses) - n_dry - n_ok - n_fail - n_blocked

        sm1, sm2, sm3, sm4 = st.columns(4)
        with sm1:
            st.metric("🔵 Dry-run", n_dry)
        with sm2:
            st.metric("✅ Success", n_ok)
        with sm3:
            st.metric("❌ Failed", n_fail)
        with sm4:
            st.metric("🚫 Blocked", n_blocked + n_other)

        # Per-command detail
        with st.expander("🔍 Per-Command Detail", expanded=True):
            for idx, r in enumerate(exec_results, 1):
                status = r.get("status", "UNKNOWN")
                cmd    = r.get("command", "")
                stdout = r.get("stdout", "")
                stderr = r.get("stderr", "")
                rc     = r.get("returncode")
                ms     = r.get("duration_ms", 0)
                is_dry = r.get("dry_run", True)

                icon_map = {
                    "DRY_RUN": "🔵", "SUCCESS": "✅", "FAILED": "❌",
                    "TIMEOUT": "⏱️", "BLOCKED": "🚫", "ERROR": "💥",
                }
                icon = icon_map.get(status, "❓")

                col_icon, col_detail = st.columns([1, 11])
                with col_icon:
                    st.markdown(f"### {icon}")
                with col_detail:
                    st.markdown(
                        f"**[{idx:02d}]** `{cmd}`  \n"
                        f"<span style='color:#8892b0; font-size:0.8rem;'>"
                        f"status={status} · returncode={rc} · {ms}ms · "
                        f"{'dry-run' if is_dry else '⚠️ live'}"
                        f"</span>",
                        unsafe_allow_html=True,
                    )
                    if stdout:
                        st.code(stdout, language="text")
                    if stderr:
                        st.error(f"stderr: {stderr}")


# ---------------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------------
if not st.session_state.get("audit_done"):
    st.markdown("---")
    st.markdown(
        "<div style='text-align:center; padding:4rem 0; color:#6a6a8a;'>"
        "<p style='font-size:3rem; margin:0;'>🛡️</p>"
        "<h3 style='color:#8892b0; margin:0.5rem 0;'>Ready to Scan</h3>"
        "<p>Configure the target IP and OpenAI key in the sidebar, then click <b>Run Security Audit</b>.</p>"
        "</div>",
        unsafe_allow_html=True,
    )
