"""
Threat Analysis Agent  —  High-Precision Vulnerability Assessment
=================================================================
The second agent in the pipeline.  Operates in **four** distinct stages:

Stage 1 — Service Extraction
    Parse every open port / service / version string from the Nmap raw
    output (regex ``_extract_service_versions``).  These are the ground-
    truth facts that every subsequent step is anchored to.

Stage 2 — CVE Retrieval (ChromaDB, top-5)
    Query the threat-intel vector store with a *service-focused* search
    string built from the extracted versions.  We request exactly **5**
    results so the context window for the re-ranker stays small and the
    signal-to-noise ratio stays high.
a
Stage 3 — Mini-LLM Re-ranking (llama-3.1-8b-instant, ≥ 90 % match)
    A lightweight Groq model scores each retrieved CVE document against
    the *specific* service versions from Stage 1.  Each document receives
    a numeric **match_pct** between 0 and 100.  Only documents scoring
    **≥ 90** are kept.  This two-stage retrieval-then-filter approach:

    * Minimises false positives — the defender never blocks legitimate
      traffic due to a generic or version-mismatched CVE.
    * Compresses context — the final LLM receives a concise, verified
      threat picture rather than a noisy bag of loosely related CVEs.

    If the re-ranker discards *all* candidates, a single-document fallback
    containing the top-1 ChromaDB hit is retained so the final analysis
    always has at least some threat-intel anchor.

Stage 4 — Full Analysis (llama-3.3-70b-versatile)
    The 70 B model receives *only* the high-confidence CVE matches, the
    Nmap output, web-tech fingerprinting, log analysis, and live NVD/CIRCL
    data.  It produces the MITRE ATT&CK mapping, risk score, category, and
    actionable remediation advice.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
import os

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agents.state import AgentState
from tools.log_analyzer import analyze_logs
from tools.cve_lookup import (
    fetch_live_cve_data,
    extract_cve_ids_from_text,
    bulk_fetch_cve_data,
)
import json
import re
from config import settings

if TYPE_CHECKING:
    from vector_db.threat_intel_store import ThreatIntelStore


# ---------------------------------------------------------------------------
# System prompt — Expert SOC Analyst persona (user-specified)
# ---------------------------------------------------------------------------
THREAT_ANALYSIS_SYSTEM_PROMPT = (
    "You are an expert Security Operations Center (SOC) Analyst. "
    "Analyze the following port scan results and web technology "
    "fingerprinting data. Identify vulnerabilities "
    "and map them to MITRE ATT&CK techniques. Determine if the risk is "
    "CRITICAL, HIGH, MEDIUM, or LOW.\n\n"
    "Structure your response using these exact sections:\n\n"
    "## Open Ports & Services\n"
    "List every discovered port, protocol, service name, and version.\n\n"
    "## Web Technologies & Security Headers\n"
    "Summarize detected server software, frameworks, CMS platforms, and "
    "JavaScript libraries. Flag any missing security headers (e.g. "
    "Strict-Transport-Security, Content-Security-Policy, X-Frame-Options) "
    "and explain the risk each omission introduces.\n\n"
    "## MITRE ATT&CK Mapping\n"
    "Map each finding to one or more MITRE ATT&CK technique IDs "
    "(e.g. T1190, T1046, T1021, T1059). For each technique explain "
    "how the discovered service could be exploited.\n\n"
    "## Vulnerability Assessment\n"
    "For each service, note known CVEs (with CVSS scores where possible) "
    "and whether the version is outdated or mis-configured. If a "
    "'Live CVE Intelligence' section is provided, incorporate the real "
    "CVSS scores, severity ratings, and descriptions into your analysis "
    "instead of guessing.\n\n"
    "## Key Findings\n"
    "Provide a prioritized list of the most critical issues, ordered by "
    "severity (most dangerous first).\n\n"
    "## Risk Assessment\n"
    "Assign a numeric risk score from 0 to 10:\n"
    "- 0: No open ports, no attack surface.\n"
    "- 1-3: LOW — Ports open but services appear current and hardened.\n"
    "- 4-6: MEDIUM — Some outdated services or slight misconfigurations.\n"
    "- 7-8: HIGH — Vulnerable services exposed, known CVEs likely exploitable.\n"
    "- 9-10: CRITICAL — Actively exploitable vulnerabilities, dangerous "
    "services wide open.\n\n"
    "Assign exactly one threat category:\n"
    "- Information Disclosure\n"
    "- Unauthenticated Access\n"
    "- Remote Code Execution\n"
    "- Privilege Escalation\n"
    "- Denial of Service\n"
    "- Data Exfiltration\n"
    "- Lateral Movement\n"
    "- Credential Theft\n"
    "- Misconfiguration\n"
    "- No Threat\n\n"
    "## Threat Summary\n"
    "Write a single plain-English paragraph (3-5 sentences) summarising "
    "the key threats found, the MITRE ATT&CK techniques that apply, and "
    "the most important immediate actions the defender should take. "
    "Start this paragraph with 'THREAT_SUMMARY:' on its own line.\n\n"
    "IMPORTANT: You MUST end your response with exactly these two lines "
    "and nothing else after them:\n"
    "RISK_SCORE: <integer 0-10>\n"
    "CATEGORY: <one of the categories above>"
)


# ---------------------------------------------------------------------------
# Helper: extract service+version strings from Nmap output
# ---------------------------------------------------------------------------
_SERVICE_VERSION_RE = re.compile(
    r"(\d+)/\w+\s+open\s+(\S+)\s+(.+)",
    re.IGNORECASE,
)


def _extract_service_versions(nmap_text: str) -> list[dict]:
    """
    Parse Nmap output lines and extract ``(port, service, version_string)``
    tuples for every open port that has a non-empty version/product field.

    Returns a list of dicts:
        [{"port": 3306, "service": "mysql", "version": "MySQL 5.5.62"}, …]
    """
    services: list[dict] = []
    for line in nmap_text.splitlines():
        m = _SERVICE_VERSION_RE.search(line.strip())
        if m:
            port_str, service, version = m.group(1), m.group(2), m.group(3).strip()
            if version and version.lower() not in ("", "unknown", "n/a"):
                services.append({
                    "port": int(port_str),
                    "service": service,
                    "version": version,
                })
    return services


def _get_candidate_cve_ids(
    llm: ChatGroq,
    services: list[dict],
) -> list[str]:
    """
    Ask the LLM to suggest likely CVE IDs for each service+version pair.

    We use a cheap, fast system message that asks for *only* CVE IDs so
    we can then verify them against the live NVD/CIRCL APIs.  This keeps
    API calls focused on real IDs rather than scanning blindly.

    Returns:
        A list of CVE ID strings (may be empty).
    """
    if not services:
        return []

    service_lines = "\n".join(
        f"- Port {s['port']}/{s['service']}: {s['version']}"
        for s in services
    )

    messages = [
        SystemMessage(
            content=(
                "You are a cybersecurity vulnerability researcher. "
                "Given the following service versions discovered on a "
                "network scan, list the most likely CVE IDs (up to 3 per "
                "service) that could affect each version. "
                "Output ONLY the CVE IDs, one per line, in the format "
                "CVE-YYYY-NNNNN. Do not include any other text."
            )
        ),
        HumanMessage(content=f"Service versions:\n{service_lines}"),
    ]

    try:
        response = llm.invoke(messages)
        return extract_cve_ids_from_text(response.content)
    except Exception as exc:
        print(f"[Threat Analysis] ⚠️  CVE-candidate LLM call failed: {exc}")
        return []


def _enrich_with_live_cves(
    llm: ChatGroq,
    nmap_results: str,
) -> str:
    """
    End-to-end CVE enrichment pipeline:

    1. Extract service versions from Nmap output.
    2. Ask the LLM for candidate CVE IDs.
    3. Also extract any CVE IDs already mentioned in the Nmap text itself.
    4. Fetch live data for every candidate from NVD / CIRCL.
    5. Return a formatted Markdown string (or empty string if nothing found).
    """
    # Step 1 — parse service+version pairs
    services = _extract_service_versions(nmap_results)
    if not services:
        print("[Threat Analysis] No versioned services found — skipping CVE lookup.")
        return ""

    print(f"[Threat Analysis] Extracted {len(services)} versioned service(s) "
          f"from Nmap output — querying for CVE candidates…")

    # Step 2 — ask LLM for likely CVE IDs
    candidate_ids = _get_candidate_cve_ids(llm, services)

    # Step 3 — also grab any CVE IDs already in the raw Nmap text
    inline_ids = extract_cve_ids_from_text(nmap_results)
    all_ids = sorted(set(candidate_ids + inline_ids))

    if not all_ids:
        print("[Threat Analysis] No CVE candidates identified.")
        return ""

    print(f"[Threat Analysis] Looking up {len(all_ids)} CVE(s): "
          f"{', '.join(all_ids[:10])}"
          + (" …" if len(all_ids) > 10 else ""))

    # Step 4 & 5 — bulk fetch and format
    return bulk_fetch_cve_data(all_ids)


# ---------------------------------------------------------------------------
# Stage 2 helper: build a service-focused ChromaDB query string
# ---------------------------------------------------------------------------

def _build_cve_query(services: list[dict]) -> str:
    """
    Build a compact query string for ChromaDB that emphasises product names
    and version numbers so the vector similarity search returns CVEs that
    are as close as possible to what is *actually* running on the target.

    Examples
    --------
    ``[{"port": 22, "service": "ssh", "version": "OpenSSH 7.4"}]``
    → ``"CVE vulnerability OpenSSH 7.4 SSH service"``
    """
    if not services:
        return "Common network service vulnerabilities and attack patterns"

    # Extract product tokens — take everything after the first space in
    # the version field to get "OpenSSH", "Apache httpd", "MySQL", etc.
    tokens: list[str] = []
    for svc in services:
        tokens.append(svc["service"])
        tokens.append(svc["version"])

    # Join unique tokens and prepend CVE-focused keywords
    unique = list(dict.fromkeys(tokens))          # preserve order, deduplicate
    return "CVE vulnerability " + " ".join(unique[:12])  # cap at 12 tokens


# ---------------------------------------------------------------------------
# Stage 3 helper: Mini-LLM CVE re-ranking at ≥ 90 % match threshold
# ---------------------------------------------------------------------------

_CVE_MATCH_THRESHOLD = 90   # minimum match_pct to keep a CVE document
_CVE_FALLBACK_N      = 1    # documents to keep when everything is filtered out


def _rerank_cves_against_services(
    services: list[dict],
    cve_documents: list[str],
    cve_metadatas: list[dict] | None = None,
    rerank_model: str = "llama-3.1-8b-instant",
) -> tuple[list[str], list[dict]]:
    """
    Stage 3 — High-precision CVE re-ranking.

    Use a small, fast LLM to compare each ChromaDB CVE document against the
    *exact* service versions discovered during the Nmap scan.  Each document
    receives a numeric ``match_pct`` (0–100).  Only documents with
    ``match_pct ≥ 90`` are returned so the final analysis contains only
    high-confidence, version-matched vulnerabilities.

    This two-stage approach (ChromaDB retrieval → Mini-LLM filter) minimises
    false positives: the defender will not block legitimate traffic due to a
    generic CVE that merely mentions the same product family without matching
    the specific version running on the target.

    Args:
        services:       Parsed service dicts from ``_extract_service_versions()``.
        cve_documents:  The top-5 document strings returned by ChromaDB.
        cve_metadatas:  Optional corresponding metadata dicts from ChromaDB.
        rerank_model:   Groq model for the re-ranking call.
                        Default: ``llama-3.1-8b-instant`` (fast, cheap).

    Returns:
        A 2-tuple ``(kept_docs, kept_metas)`` containing only the
        high-confidence documents (and their matching metadata).
        If nothing survives the ≥ 90 % filter the top-1 ChromaDB result
        is returned as a fallback so the final analysis always has context.
    """
    if not cve_documents:
        return [], []

    # ── If there are no versioned services just return everything ──────
    if not services:
        return cve_documents, (cve_metadatas or [{}] * len(cve_documents))

    # ── Build the service-version context for the mini-LLM ────────────
    service_lines = "\n".join(
        f"  • Port {s['port']}/{s['service']}: {s['version']}"
        for s in services
    )

    # Number each document so the LLM can reference them by index
    numbered_docs = "\n---\n".join(
        f"[{i + 1}]\n{doc}" for i, doc in enumerate(cve_documents)
    )

    rerank_prompt = (
        "You are a cybersecurity vulnerability matching specialist.\n\n"
        "## Exact Service Versions Running on the Target\n"
        f"{service_lines}\n\n"
        "## CVE / Threat Intel Documents to Evaluate (top 5 from vector DB)\n"
        f"{numbered_docs}\n\n"
        "## Your Task\n"
        "For each numbered document, determine what percentage (0–100) of "
        "its described vulnerability *specifically and directly* applies to "
        "the exact service versions listed above.\n\n"
        "Scoring rules:\n"
        "  90–100 — The CVE targets THIS exact product version or version range "
        "that includes what is running. High-confidence match.\n"
        "  50–89  — Same product family but version range uncertain or partially "
        "overlapping. Moderate confidence.\n"
        "  0–49   — Different product, version is outside scope, or the document "
        "is a general TTP/IOC with no version-specific binding.\n\n"
        "Output ONLY a JSON array — no prose, no markdown fences:\n"
        '[{"index": 1, "match_pct": 95, "reason": "CVE targets OpenSSH < 7.5, '
        'target runs 7.4"}, ...]\n\n'
        "Every document from [1] to [" + str(len(cve_documents)) + "] MUST appear "
        "in your output."
    )

    metas = cve_metadatas or [{}] * len(cve_documents)

    try:
        resolved_rerank_model = os.getenv("GROQ_MODEL_RANKER", rerank_model)
        groq_api_key = os.getenv("GROQ_API_KEY", settings.groq_api_key)
        mini_llm = ChatGroq(model=resolved_rerank_model, temperature=0, api_key=groq_api_key)
        response  = mini_llm.invoke([HumanMessage(content=rerank_prompt)])
        content   = response.content.strip()

        # Strip optional markdown code fence
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*", "", content)
            content = re.sub(r"\s*```$", "", content.strip())

        rankings: list[dict] = json.loads(content)

        kept_docs:  list[str]  = []
        kept_metas: list[dict] = []
        filtered_out: list[tuple[int, int, str]] = []   # (idx, pct, reason)

        for entry in rankings:
            idx       = entry.get("index")
            pct       = int(entry.get("match_pct", 0))
            reason    = entry.get("reason", "")

            if not isinstance(idx, int) or not (1 <= idx <= len(cve_documents)):
                continue

            doc_text = cve_documents[idx - 1]
            doc_meta = metas[idx - 1] if idx - 1 < len(metas) else {}

            if pct >= _CVE_MATCH_THRESHOLD:
                kept_docs.append(doc_text)
                kept_metas.append(doc_meta)
                print(f"[CVE Re-ranker] ✅ Doc [{idx}] KEPT    — "
                      f"{pct}% match | {reason[:80]}")
            else:
                filtered_out.append((idx, pct, reason))
                print(f"[CVE Re-ranker] ❌ Doc [{idx}] DROPPED — "
                      f"{pct}% match | {reason[:80]}")

        # ── Summary ───────────────────────────────────────────────────
        print(
            f"[CVE Re-ranker] Result: {len(kept_docs)}/{len(cve_documents)} "
            f"documents passed the ≥{_CVE_MATCH_THRESHOLD}% threshold."
        )

        # ── Fallback — never pass zero context to the final LLM ──────
        if not kept_docs:
            print(
                f"[CVE Re-ranker] ⚠️  All CVEs filtered out — "
                f"retaining top-{_CVE_FALLBACK_N} ChromaDB result(s) as fallback."
            )
            return (
                cve_documents[:_CVE_FALLBACK_N],
                metas[:_CVE_FALLBACK_N],
            )

        return kept_docs, kept_metas

    except Exception as exc:
        # On any failure fall through gracefully with all documents
        print(
            f"[CVE Re-ranker] ⚠️  Mini-LLM re-ranking failed: {exc} "
            f"— using all {len(cve_documents)} docs unfiltered."
        )
        return cve_documents, metas


# ---------------------------------------------------------------------------
# Backward-compat general threat-intel re-ranker (HIGH/MEDIUM filter)
# Used for non-CVE documents (TTPs, IOCs, APT profiles) from ChromaDB.
# ---------------------------------------------------------------------------

def _rerank_threat_intel(
    services: list[dict],
    raw_documents: list[str],
    raw_metadatas: list[dict] | None = None,
    rerank_model: str = "llama-3.1-8b-instant",
) -> str:
    """
    Re-rank general threat-intel documents (TTPs, IOCs, APT profiles) that
    are *not* CVE entries.  Uses a HIGH / MEDIUM / LOW relevance label rather
    than a numeric percentage — appropriate for non-version-specific context.

    CVE documents are handled by the dedicated
    ``_rerank_cves_against_services()`` function (Stage 3) which applies the
    stricter ≥ 90 % numeric threshold.

    Returns:
        A newline-joined string of kept documents, or an empty string.
    """
    if not services or not raw_documents:
        return "\n\n".join(raw_documents) if raw_documents else ""

    service_summary = "\n".join(
        f"- Port {s['port']}/{s['service']}: {s['version']}"
        for s in services
    )
    numbered_docs = "\n---\n".join(
        f"[{i+1}] {doc}" for i, doc in enumerate(raw_documents)
    )

    rerank_prompt = (
        "You are a cybersecurity relevance filter.\n\n"
        "## Discovered Services\n"
        f"{service_summary}\n\n"
        "## Candidate Threat Intel Documents\n"
        f"{numbered_docs}\n\n"
        "For each numbered document, decide whether it is specifically "
        "relevant to the services and versions listed above.\n"
        "Output ONLY a JSON array:\n"
        '[{"index": 1, "relevance": "HIGH"}, {"index": 3, "relevance": "MEDIUM"}]\n'
        "Use: HIGH, MEDIUM, or LOW. No other text."
    )

    try:
        resolved_rerank_model = os.getenv("GROQ_MODEL_RANKER", rerank_model)
        groq_api_key = os.getenv("GROQ_API_KEY", settings.groq_api_key)
        mini_llm = ChatGroq(model=resolved_rerank_model, temperature=0, api_key=groq_api_key)
        response = mini_llm.invoke([HumanMessage(content=rerank_prompt)])
        content  = response.content.strip()

        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*", "", content)
            content = re.sub(r"\s*```$", "", content.strip())

        rankings: list[dict] = json.loads(content)
        keep_indices: list[int] = [
            e["index"] for e in rankings
            if isinstance(e.get("index"), int)
            and (e.get("relevance") or "").upper() in ("HIGH", "MEDIUM")
        ]

        if not keep_indices:
            print("[Threat Analysis] Re-ranker (general) kept 0 docs — "
                  "falling back to top-3.")
            return "\n\n".join(raw_documents[:3])

        kept = [raw_documents[i - 1] for i in sorted(keep_indices)
                if 1 <= i <= len(raw_documents)]
        print(f"[Threat Analysis] Re-ranker (general) kept "
              f"{len(kept)}/{len(raw_documents)} docs.")
        return "\n\n".join(kept)

    except Exception as exc:
        print(f"[Threat Analysis] ⚠️  General re-ranking failed: {exc} "
              f"— using all {len(raw_documents)} docs unfiltered.")
        return "\n\n".join(raw_documents)


def create_threat_analysis_agent(
    model_name: str | None = None,
    threat_store: ThreatIntelStore | None = None,
):
    """
    Create the Threat Analysis Agent node function.

    Args:
        model_name: Groq model to use (default: llama-3.3-70b-versatile).
        threat_store: ThreatIntelStore instance for querying threat intel.

    Returns:
        A function that can be used as a LangGraph node.
    """
    resolved_model = model_name or os.getenv("GROQ_MODEL_MAIN", settings.groq_model_main)
    groq_api_key = os.getenv("GROQ_API_KEY", settings.groq_api_key)
    llm = ChatGroq(model=resolved_model, temperature=0, api_key=groq_api_key)

    def threat_analysis_node(state: AgentState) -> dict:
        """
        Analyze Nmap scan results for security threats and vulnerabilities.

        Steps:
        1.  Extract ``nmap_results`` from ``scan_results["raw_output"]``
            in AgentState (populated by the Recon Agent).  Falls back to
            ``incident_report`` when ``scan_results`` is empty.
        1b. Extract web technology results if available.
        2.  Analyse logs if provided.
        3.  Stage 2 — ChromaDB CVE retrieval (top-5, service-focused query).
            Stage 3 — Mini-LLM (llama-3.1-8b) re-ranks the 5 CVEs against
            exact service versions; keeps only ≥ 90 % matches.
            Separate general threat-intel (TTPs/IOCs) query with HIGH/MEDIUM
            relevance filter via the general re-ranker.
        4.  Enrich with live CVE data from NVD / CIRCL APIs.
        5.  Build full LLM prompt — includes only high-confidence CVEs.
        6.  Stage 4 — Invoke ChatGroq (llama-3.3-70b-versatile) for the full
            MITRE ATT&CK mapping, risk score, and remediation advice.
        7.  Parse ``RISK_SCORE``, ``CATEGORY``, and ``THREAT_SUMMARY`` tags.
        8-11. Build structured reports and return the updated state.
        """
        print(f"\n{'='*60}")
        print("[Threat Analysis Agent] Starting threat analysis...")
        print(f"{'='*60}")

        # ── 1. Extract nmap_results from AgentState ──────────────────
        # Primary source: scan_results dict written by the Recon Agent.
        scan_results: dict = state.get("scan_results", {}) or {}
        nmap_results = scan_results.get("raw_output", "")

        # Fallback: use the running incident_report when scan_results is
        # absent (e.g. in test graphs that skip the Recon Agent).
        incident_report: str = state.get("incident_report", "") or ""
        if not nmap_results:
            nmap_results = incident_report

        print(
            f"[Threat Analysis] Nmap results length: "
            f"{len(nmap_results)} chars"
        )

        log_data: str = state.get("log_data", "") or ""

        # ── 1b. Extract web technology results if available ──────────
        web_tech: dict = state.get("web_tech_results", {}) or {}
        web_tech_raw: str = web_tech.get("raw_output", "") or ""
        if web_tech_raw:
            print(
                f"[Threat Analysis] Web tech results length: "
                f"{len(web_tech_raw)} chars  |  "
                f"Technologies: {', '.join(web_tech.get('technologies_found', []))}"
            )

        # ── 2. Analyse logs if provided ──────────────────────────────
        log_analysis: dict = {}
        if log_data:
            log_analysis = analyze_logs(log_data)
            print(
                "[Threat Analysis] Log risk level: "
                f"{log_analysis.get('summary', {}).get('risk_level', 'N/A')}"
            )

        # ── 3. CVE Retrieval + Mini-LLM Re-ranking (Stages 2 & 3) ──────
        #
        # Stage 2: Query ChromaDB with a service-version–focused search
        # string, requesting exactly 5 results (not 10) to keep the
        # re-ranker context compact.
        #
        # Stage 3: Mini-LLM (llama-3.1-8b-instant) scores each document
        # 0–100 % against the exact service versions.  Only documents that
        # score ≥ 90 % are passed to the final analysis LLM.  This prevents
        # generic or version-mismatched CVEs from triggering false positives.
        # ─────────────────────────────────────────────────────────────────

        # Parse service versions early — needed by both Stage 2 query
        # building and Stage 3 re-ranking.
        services_for_rerank = _extract_service_versions(nmap_results)

        high_confidence_cve_context = ""   # populated by Stage 3
        general_threat_context      = ""   # populated by general re-ranker
        reranked_cve_count          = 0
        reranked_cve_docs: list[str] = []

        if threat_store:
            # ── Stage 2: Retrieve top-5 CVE-focused documents ─────────
            cve_query = _build_cve_query(services_for_rerank)
            print(
                f"[Threat Analysis] Stage 2 — ChromaDB CVE query "
                f"(top-5): «{cve_query[:80]}»"
            )
            cve_results = threat_store.query_threats(cve_query, n_results=5)
            cve_docs    = (
                cve_results.get("documents", [[]])[0]
                if cve_results.get("documents") else []
            )
            cve_metas   = (
                cve_results.get("metadatas", [[]])[0]
                if cve_results.get("metadatas") else []
            )

            if cve_docs:
                print(
                    f"[Threat Analysis] Stage 2 — retrieved {len(cve_docs)} "
                    f"CVE candidate(s) from ChromaDB."
                )

                # ── Stage 3: Mini-LLM re-ranking at ≥ 90 % ───────────
                print(
                    "[Threat Analysis] Stage 3 — Mini-LLM (llama-3.1-8b) "
                    "re-ranking CVEs against exact service versions …"
                )
                reranked_cve_docs, reranked_cve_metas = _rerank_cves_against_services(
                    services=services_for_rerank,
                    cve_documents=cve_docs,
                    cve_metadatas=cve_metas,
                )
                reranked_cve_count = len(reranked_cve_docs)

                if reranked_cve_docs:
                    high_confidence_cve_context = "\n\n".join(reranked_cve_docs)
                    print(
                        f"[Threat Analysis] Stage 3 complete — "
                        f"{reranked_cve_count} high-confidence CVE(s) "
                        f"(≥90% match) forwarded to final analysis."
                    )
                else:
                    print(
                        "[Threat Analysis] Stage 3 — no CVEs passed the "
                        "≥90% threshold; fallback document(s) used."
                    )
            else:
                print("[Threat Analysis] Stage 2 — ChromaDB returned no CVE documents.")

            # ── General threat-intel (TTPs, IOCs) — separate query ────
            # We also retrieve broader threat-intel context (MITRE TTPs,
            # IOC lists, APT profiles) using the existing general re-ranker
            # so those are not lost when the CVE filter is strict.
            general_query = nmap_results[:500] if nmap_results else (
                "Common network service attack patterns TTPs"
            )
            general_results = threat_store.query_threats(general_query, n_results=5)
            general_docs    = (
                general_results.get("documents", [[]])[0]
                if general_results.get("documents") else []
            )
            general_metas   = (
                general_results.get("metadatas", [[]])[0]
                if general_results.get("metadatas") else []
            )

            # Filter out CVE-type docs (already handled above)
            non_cve_docs  = [
                d for d, m in zip(general_docs, general_metas or [{}] * len(general_docs))
                if (m.get("type", "").upper() != "CVE")
            ]

            if non_cve_docs:
                print(
                    f"[Threat Analysis] General threat-intel: "
                    f"{len(non_cve_docs)} non-CVE doc(s) — running general re-ranker…"
                )
                general_threat_context = _rerank_threat_intel(
                    services=services_for_rerank,
                    raw_documents=non_cve_docs,
                )

        # Combine both contexts for the threat_context used in the prompt
        threat_context_parts: list[str] = []
        if high_confidence_cve_context:
            threat_context_parts.append(high_confidence_cve_context)
        if general_threat_context:
            threat_context_parts.append(general_threat_context)
        threat_context = "\n\n".join(threat_context_parts)

        # ── 4. Enrich with live CVE data from NVD / CIRCL ────────
        live_cve_context = ""
        try:
            live_cve_context = _enrich_with_live_cves(llm, nmap_results)
            if live_cve_context:
                print(f"[Threat Analysis] Live CVE enrichment added "
                      f"({len(live_cve_context)} chars)")
        except Exception as exc:
            print(f"[Threat Analysis] ⚠️  Live CVE enrichment failed: {exc}")

        # ── 5. Build the LLM prompt ──────────────────────────────────
        context_parts = [
            f"## Nmap Scan Results\n```\n{nmap_results[:4000]}\n```",
        ]
        if web_tech_raw:
            context_parts.append(
                f"## Web Technology Fingerprinting\n```\n{web_tech_raw[:2000]}\n```"
            )
            missing_sec = web_tech.get("missing_security_headers", [])
            if missing_sec:
                context_parts.append(
                    f"## Missing Security Headers\n"
                    f"{', '.join(missing_sec)}"
                )
        if log_analysis:
            context_parts.append(
                f"## Log Analysis\n```json\n"
                f"{json.dumps(log_analysis.get('summary', {}), indent=2)}\n```"
            )
            if log_analysis.get("suspicious_ips"):
                context_parts.append(
                    f"## Suspicious IPs\n"
                    f"{json.dumps(log_analysis['suspicious_ips'], indent=2)}"
                )
        if threat_context:
            context_parts.append(
                f"## High-Confidence Threat Intelligence\n"
                f"*(Filtered by Mini-LLM re-ranker — only ≥{_CVE_MATCH_THRESHOLD}% "
                f"version-matched CVEs and relevant TTPs/IOCs are shown)*\n\n"
                f"{threat_context}"
            )
        if live_cve_context:
            context_parts.append(live_cve_context)

        full_context = "\n\n".join(context_parts)

        messages = [
            SystemMessage(content=THREAT_ANALYSIS_SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    "Analyze the following port scan results. Identify "
                    "vulnerabilities and map them to MITRE ATT&CK techniques. "
                    "Determine if the risk is CRITICAL, HIGH, MEDIUM, or LOW:\n\n"
                    + full_context
                )
            ),
        ]

        # ── 6. Invoke ChatGroq ────────────────────────────────────────
        response = llm.invoke(messages)

        # ── 7. Parse structured tags from the LLM response ───────────
        risk_score   = _parse_risk_score(response.content)
        category     = _parse_category(response.content)
        threat_summary = _parse_threat_summary(response.content)

        # Derive risk_level from the numeric score
        if risk_score >= 9:
            risk_level = "CRITICAL"
        elif risk_score >= 7:
            risk_level = "HIGH"
        elif risk_score >= 4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # threat_detected is True when risk_score exceeds HIGH threshold
        threat_detected = risk_score > 7

        print(f"[Threat Analysis Agent] Risk score : {risk_score}/10")
        print(f"[Threat Analysis Agent] Risk level : {risk_level}")
        print(f"[Threat Analysis Agent] Category   : {category}")
        print(f"[Threat Analysis Agent] Threat detected: {threat_detected}")

        # ── 8. Build the structured analysis dict ────────────────────
        threat_analysis = {
            "analysis":            response.content,
            "log_analysis":        log_analysis.get("summary", {}),
            "risk_level":          risk_level,
            "risk_score":          risk_score,
            "category":            category,
            "threat_detected":     threat_detected,
            "threat_summary":      threat_summary,
            # Re-ranking telemetry — useful for dashboards / auditing
            "cve_high_confidence_kept": reranked_cve_count,
            "cve_match_threshold":      _CVE_MATCH_THRESHOLD,
            "threat_intel_matches": len(
                threat_context.split("\n\n") if threat_context else []
            ),
        }

        # ── 9. Build the structured threat_analysis_report ───────────
        threat_analysis_report = (
            f"{'='*60}\n"
            f"THREAT ANALYSIS REPORT\n"
            f"{'='*60}\n"
            f"Risk Score        : {risk_score}/10\n"
            f"Risk Level        : {risk_level}\n"
            f"Category          : {category}\n"
            f"Threat Detected   : {threat_detected}\n"
            f"CVE Re-ranking    : {reranked_cve_count} high-confidence CVE(s) "
            f"kept (≥{_CVE_MATCH_THRESHOLD}% match threshold)\n"
            f"{'─'*60}\n"
            f"{response.content}\n"
            f"{'='*60}\n"
        )

        # ── 10. Append findings to the running incident report ────────
        report_section = (
            f"\n{'='*60}\n"
            f"THREAT ANALYSIS — Risk Score: {risk_score}/10 ({risk_level})"
            f" | Category: {category}"
            f" | Threat Detected: {threat_detected}\n"
            f"{'='*60}\n"
            f"{response.content}\n"
        )
        updated_report = incident_report + report_section

        # ── 11. Return the updated state ──────────────────────────────
        return {
            "threat_analysis":        threat_analysis,
            "threat_analysis_report": threat_analysis_report,
            "threat_summary":         threat_summary,
            "threat_detected":        threat_detected,
            "threat_intel_context":   threat_context,
            "risk_level":             risk_level,
            "risk_score":             risk_score,
            "category":               category,
            "incident_report":        updated_report,
            "messages": [
                HumanMessage(
                    content=f"[Threat Analysis Agent]\n{response.content}"
                )
            ],
            "current_agent": "threat_analysis",
        }

    return threat_analysis_node


# ---------------------------------------------------------------------------
# Helpers: parse risk score and category from LLM output
# ---------------------------------------------------------------------------

_VALID_CATEGORIES = {
    "Information Disclosure",
    "Unauthenticated Access",
    "Remote Code Execution",
    "Privilege Escalation",
    "Denial of Service",
    "Data Exfiltration",
    "Lateral Movement",
    "Credential Theft",
    "Misconfiguration",
    "No Threat",
}


def _parse_threat_summary(llm_output: str) -> str:
    """
    Extract the plain-English threat summary paragraph from the LLM response.

    Looks for the ``THREAT_SUMMARY:`` tag written by the prompt, then
    captures everything up to the next section header or the end of the
    text.  Returns a cleaned single-paragraph string.

    Falls back to returning the first non-empty paragraph in the response
    if the explicit tag is missing.
    """
    # Preferred: explicit THREAT_SUMMARY: tag
    match = re.search(
        r"THREAT_SUMMARY:\s*(.+?)(?=\n##|\nRISK_SCORE:|\nCATEGORY:|$)",
        llm_output,
        re.IGNORECASE | re.DOTALL,
    )
    if match:
        return match.group(1).strip()

    # Fallback: return the first substantive paragraph
    for para in llm_output.split("\n\n"):
        cleaned = para.strip()
        if cleaned and not cleaned.startswith("#") and len(cleaned) > 40:
            return cleaned

    return "Threat analysis complete. Review the full report for details."


def _parse_risk_score(llm_output: str) -> int:
    """
    Extract the numeric risk score (0–10) from the LLM's response.

    Looks for the explicit ``RISK_SCORE: <value>`` tag first, then falls
    back to scanning for a bare integer near risk-related keywords.
    Defaults to ``5`` (moderate) if nothing is found.
    """
    # Prefer the explicit tag the prompt asks for
    match = re.search(r"RISK_SCORE:\s*(\d{1,2})", llm_output, re.IGNORECASE)
    if match:
        score = int(match.group(1))
        return max(0, min(10, score))  # clamp to 0–10

    # Fallback: look for a pattern like "risk score: 8" or "risk score of 8"
    match = re.search(r"risk\s*score[:\s]+(?:of\s+)?(\d{1,2})", llm_output, re.IGNORECASE)
    if match:
        score = int(match.group(1))
        return max(0, min(10, score))

    # Last resort: derive from old-style labels if present
    upper = llm_output.upper()
    if "CRITICAL" in upper:
        return 9
    if "HIGH" in upper:
        return 8
    if "MEDIUM" in upper or "MODERATE" in upper:
        return 5
    if "LOW" in upper:
        return 3
    if "NONE" in upper or "NO THREAT" in upper:
        return 0

    return 5  # safe default


def _parse_category(llm_output: str) -> str:
    """
    Extract the threat category from the LLM's response.

    Looks for the explicit ``CATEGORY: <value>`` tag first, then falls
    back to checking whether any known category name appears in the text.
    Defaults to ``"Misconfiguration"`` if nothing is found.
    """
    # Prefer the explicit tag the prompt asks for
    match = re.search(r"CATEGORY:\s*(.+)", llm_output, re.IGNORECASE)
    if match:
        raw = match.group(1).strip().rstrip(".")
        # Validate against known categories (case-insensitive)
        for valid in _VALID_CATEGORIES:
            if valid.lower() == raw.lower():
                return valid
        # Return the raw value title-cased if it's close enough
        return raw.title()

    # Fallback: find the first known category that appears in the text
    for cat in _VALID_CATEGORIES:
        if cat.lower() in llm_output.lower():
            return cat

    return "Misconfiguration"
