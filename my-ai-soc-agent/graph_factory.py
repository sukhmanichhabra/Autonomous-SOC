#!/usr/bin/env python3
"""Shared graph/checkpointer factory for non-UI runtimes."""

from __future__ import annotations

import os

from langgraph.checkpoint.postgres import PostgresSaver

from config import settings
from checkpointer import create_postgres_checkpointer, validate_database_connection
from main import build_graph


# Ensure runtime env vars are aligned for scanner/checkpointer modules.
os.environ.setdefault("NMAP_PATH", os.getenv("NMAP_PATH", settings.nmap_path))
os.environ.setdefault("DB_URL", os.getenv("DB_URL", settings.db_url))


def get_worker_checkpointer() -> PostgresSaver:
    """Create a PostgreSQL checkpointer for background workers."""
    if not validate_database_connection():
        raise RuntimeError(
            "PostgreSQL connection failed. "
            "Run: python my-ai-soc-agent/init_db.py"
        )
    return create_postgres_checkpointer()


def get_compiled_graph_for_worker(
    checkpointer: PostgresSaver,
    model_name: str | None = None,
):
    """Compile the LangGraph pipeline for worker processes."""
    selected_model = model_name or os.getenv("GROQ_MODEL_MAIN", settings.groq_model_main)
    return build_graph(model_name=selected_model, checkpointer=checkpointer)
