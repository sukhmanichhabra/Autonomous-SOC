#!/usr/bin/env python3
"""Consume Redis security events and invoke the LangGraph SOC pipeline."""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import redis  # type: ignore[import-not-found]

PROJECT_ROOT = Path(__file__).resolve().parent
PROJECT_PKG = PROJECT_ROOT / "my-ai-soc-agent"
sys.path.insert(0, str(PROJECT_PKG))

import app as streamlit_app


def _parse_event(fields: dict) -> dict | None:
    raw_event = fields.get("event") or fields.get(b"event")
    if raw_event is None:
        ip_value = fields.get("ip") or fields.get(b"ip")
        ts_value = fields.get("timestamp") or fields.get(b"timestamp")
        if ip_value is None:
            return None
        if isinstance(ip_value, bytes):
            ip_value = ip_value.decode("utf-8", errors="replace")
        if isinstance(ts_value, bytes):
            ts_value = ts_value.decode("utf-8", errors="replace")
        event = {"ip": str(ip_value).strip(), "timestamp": ts_value or "now"}
        return event if event["ip"] else None

    if isinstance(raw_event, bytes):
        raw_event = raw_event.decode("utf-8", errors="replace")

    try:
        event = json.loads(raw_event)
    except json.JSONDecodeError:
        return None

    if not isinstance(event, dict):
        return None

    ip = str(event.get("ip", "")).strip()
    if not ip:
        return None

    event.setdefault("type", "brute_force")
    event["ip"] = ip
    return event


def main() -> None:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    stream_name = os.getenv("REDIS_STREAM", "security_alerts")

    redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
    redis_client.ping()

    last_id = "$"

    checkpointer = streamlit_app.get_worker_checkpointer()
    graph = streamlit_app.get_compiled_graph_for_worker(checkpointer=checkpointer)
    print(f"[Consumer] Listening on stream '{stream_name}'")

    while True:
        events = redis_client.xread({stream_name: last_id}, count=10, block=5000)
        if not events:
            continue

        for _, messages in events:
            for message_id, fields in messages:
                last_id = message_id
                event = _parse_event(fields)
                if event is None:
                    print(f"[Consumer] Skipping invalid event payload: {fields}")
                    continue

                thread_id = f"streamlit-{event['ip']}-{uuid.uuid4().hex[:8]}"

                print(f"[Consumer] Processing event={event} thread_id={thread_id}")
                try:
                    graph.invoke(
                        {"target_ip": event["ip"]},
                        config={"configurable": {"thread_id": thread_id}},
                    )
                    print(f"[Consumer] Graph run completed for {event['ip']}")
                except Exception as exc:
                    print(f"[Consumer] Graph invocation failed for {event['ip']}: {exc}")


if __name__ == "__main__":
    main()
