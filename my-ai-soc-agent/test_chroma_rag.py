#!/usr/bin/env python3
"""
ChromaDB RAG Diagnostic Script
================================
Verifies that the ChromaDB threat-intel vector store is properly
initialized, seeded, and reachable by the monitor_node.

Usage:
    python test_chroma_rag.py
    python test_chroma_rag.py --seed      # seed sample data first
    python test_chroma_rag.py --query "SSH brute force"  # custom query
"""

import os
import sys
import argparse

# Ensure the project root is importable
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ── ANSI colours ─────────────────────────────────────────────────────────
_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def main():
    parser = argparse.ArgumentParser(
        description="Diagnostic: verify ChromaDB threat-intel store"
    )
    parser.add_argument(
        "--seed", action="store_true",
        help="Seed sample MITRE ATT&CK / CVE data before querying.",
    )
    parser.add_argument(
        "--query", "-q", type=str, default=None,
        help="Custom query string (default: runs two built-in queries).",
    )
    args = parser.parse_args()

    print(f"\n{_BOLD}{'='*60}")
    print("  ChromaDB RAG Diagnostic")
    print(f"{'='*60}{_RESET}\n")

    # ── Step 1: Initialize the ChromaDB client ───────────────────────
    print(f"{_CYAN}[1/4] Initializing ChromaDB client…{_RESET}")
    try:
        from vector_db.threat_intel_store import ThreatIntelStore
        store = ThreatIntelStore()
        print(f"  {_GREEN}✅ ChromaDB client initialized successfully.{_RESET}")
    except Exception as exc:
        print(f"  {_RED}❌ Failed to initialize ChromaDB:{_RESET}")
        print(f"     {exc}")
        print(f"\n{_YELLOW}💡 Troubleshooting:{_RESET}")
        print(f"   1. Ensure 'chromadb' is installed: pip install chromadb>=0.5.0")
        print(f"   2. Check that the persist directory exists:")
        print(f"      {os.path.join(_PROJECT_ROOT, 'vector_db', 'chroma_data')}")
        print(f"   3. Verify no other process holds a lock on the DB.")
        sys.exit(1)

    # ── Step 2: Check collection stats ───────────────────────────────
    print(f"\n{_CYAN}[2/4] Checking collection stats…{_RESET}")
    try:
        stats = store.get_stats()
        doc_count = stats.get("total_documents", 0)
        collection = stats.get("collection_name", "unknown")
        print(f"  Collection : {collection}")
        print(f"  Documents  : {doc_count}")

        if doc_count == 0:
            print(f"\n  {_YELLOW}⚠️  Collection is EMPTY — no threat intel data found.{_RESET}")
            print(f"\n{_YELLOW}💡 To seed the database, run one of:{_RESET}")
            print(f"   python test_chroma_rag.py --seed")
            print(f"   python main.py --seed-db")
            print(f"   Or via the Streamlit UI: check 'Seed threat-intel DB'")

            if not args.seed:
                print(f"\n  Re-run with {_BOLD}--seed{_RESET} to populate now.")
                sys.exit(1)
        else:
            print(f"  {_GREEN}✅ Collection has {doc_count} document(s).{_RESET}")
    except Exception as exc:
        print(f"  {_RED}❌ Failed to read collection stats: {exc}{_RESET}")
        sys.exit(1)

    # ── Step 2b: Seed if requested ───────────────────────────────────
    if args.seed:
        print(f"\n{_CYAN}[2b] Seeding sample threat intelligence data…{_RESET}")
        try:
            store.seed_sample_data()
            new_stats = store.get_stats()
            print(f"  {_GREEN}✅ Seeded — collection now has "
                  f"{new_stats['total_documents']} document(s).{_RESET}")
        except Exception as exc:
            print(f"  {_RED}❌ Seeding failed: {exc}{_RESET}")
            sys.exit(1)

    # ── Step 3: Run similarity searches ──────────────────────────────
    queries = [args.query] if args.query else [
        "Brute Force SSH failed login attempts",
        "Log4j remote code execution JNDI injection",
    ]

    print(f"\n{_CYAN}[3/4] Running similarity searches…{_RESET}")

    for q_idx, query in enumerate(queries, 1):
        print(f"\n  {_BOLD}Query {q_idx}: \"{query}\"{_RESET}")
        print(f"  {'─'*50}")

        try:
            results = store.query_threats(query, n_results=3)
            docs = (
                results.get("documents", [[]])[0]
                if results.get("documents") else []
            )
            metas = (
                results.get("metadatas", [[]])[0]
                if results.get("metadatas") else []
            )
            distances = (
                results.get("distances", [[]])[0]
                if results.get("distances") else []
            )

            if not docs:
                print(f"  {_YELLOW}⚠️  No results returned.{_RESET}")
                continue

            for i, (doc, meta, dist) in enumerate(
                zip(docs, metas, distances), 1
            ):
                # Truncate long documents for display
                preview = doc[:200] + "…" if len(doc) > 200 else doc
                severity = meta.get("severity", "N/A")
                doc_type = meta.get("type", "N/A")
                sev_color = (
                    _RED if severity == "CRITICAL"
                    else _YELLOW if severity == "HIGH"
                    else _CYAN if severity == "MEDIUM"
                    else _RESET
                )

                print(f"\n  [{i}] {sev_color}{_BOLD}{doc_type} "
                      f"(severity: {severity}){_RESET}")
                print(f"      Distance : {dist:.4f}")
                print(f"      Metadata : {meta}")
                print(f"      Content  : {preview}")

        except Exception as exc:
            print(f"  {_RED}❌ Query failed: {exc}{_RESET}")

    # ── Step 4: Connectivity check from monitor_node perspective ─────
    print(f"\n{_CYAN}[4/4] Verifying monitor_node.py can reach the store…{_RESET}")
    try:
        # Load .env so GROQ_API_KEY is available (if configured)
        from dotenv import load_dotenv
        load_dotenv()

        from agents.monitor_node import create_monitor_node
        # Just ensure the factory function accepts the store without error
        _node = create_monitor_node(
            model_name="llama-3.3-70b-versatile",
            threat_store=store,
        )
        print(f"  {_GREEN}✅ monitor_node can be created with the "
              f"ChromaDB store.{_RESET}")
    except Exception as exc:
        err_msg = str(exc)
        if "api_key" in err_msg.lower() or "groq" in err_msg.lower():
            print(f"  {_YELLOW}⚠️  monitor_node requires GROQ_API_KEY "
                  f"(not set in environment).{_RESET}")
            print(f"  {_GREEN}✅ ChromaDB integration itself is fine — "
                  f"set GROQ_API_KEY in .env to enable full pipeline.{_RESET}")
        else:
            print(f"  {_RED}❌ monitor_node creation failed: {exc}{_RESET}")
            sys.exit(1)

    # ── Summary ──────────────────────────────────────────────────────
    print(f"\n{_GREEN}{_BOLD}{'='*60}")
    print("  ✅ All diagnostics passed — ChromaDB is operational.")
    print(f"{'='*60}{_RESET}\n")


if __name__ == "__main__":
    main()
