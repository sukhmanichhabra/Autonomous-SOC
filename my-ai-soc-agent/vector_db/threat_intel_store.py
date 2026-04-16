"""
Threat Intelligence Vector Store (Compatibility Layer)
======================================================
Legacy import path shim.

The project now uses PostgreSQL + pgvector for RAG via
`vector_db.pgvector_store.ThreatIntelStore`.
This module preserves the historical import path:

    from vector_db.threat_intel_store import ThreatIntelStore
"""

from vector_db.pgvector_store import ThreatIntelStore, get_embeddings

__all__ = ["ThreatIntelStore", "get_embeddings"]
