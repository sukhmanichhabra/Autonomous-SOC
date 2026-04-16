#!/usr/bin/env python3
"""Watch logs/alerts.txt and publish security events to a Redis Stream."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import redis  # type: ignore[import-not-found]
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class AlertFileHandler(FileSystemEventHandler):
    """Tracks appended lines in alerts.txt and emits Redis stream events."""

    def __init__(self, alerts_file: Path, redis_client: redis.Redis, stream_name: str):
        self.alerts_file = alerts_file.resolve()
        self.redis_client = redis_client
        self.stream_name = stream_name
        self.offset = self.alerts_file.stat().st_size if self.alerts_file.exists() else 0

    def on_modified(self, event):
        if not event.is_directory and Path(event.src_path).resolve() == self.alerts_file:
            self._process_new_lines()

    def on_created(self, event):
        if not event.is_directory and Path(event.src_path).resolve() == self.alerts_file:
            self.offset = 0
            self._process_new_lines()

    def _process_new_lines(self):
        if not self.alerts_file.exists():
            return

        file_size = self.alerts_file.stat().st_size
        if file_size < self.offset:
            self.offset = 0

        with self.alerts_file.open("r", encoding="utf-8", errors="ignore") as file_obj:
            file_obj.seek(self.offset)
            for line in file_obj:
                self._publish_event_from_line(line)
            self.offset = file_obj.tell()

    def _publish_event_from_line(self, line: str):
        matches = IPV4_REGEX.findall(line)
        if not matches:
            return

        for detected_ip in matches:
            payload = {
                "ip": detected_ip,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            message_id = self.redis_client.xadd(self.stream_name, {"event": json.dumps(payload)})
            print(f"[Producer] Published {payload} to {self.stream_name} (id={message_id})")


def main() -> None:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    stream_name = os.getenv("REDIS_STREAM", "security_alerts")
    alerts_file = Path(os.getenv("ALERTS_FILE", "logs/alerts.txt"))

    alerts_file.parent.mkdir(parents=True, exist_ok=True)
    alerts_file.touch(exist_ok=True)

    redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
    redis_client.ping()

    handler = AlertFileHandler(alerts_file=alerts_file, redis_client=redis_client, stream_name=stream_name)
    observer = Observer()
    observer.schedule(handler, str(alerts_file.parent), recursive=False)
    observer.start()

    print(f"[Producer] Watching {alerts_file} and writing to stream '{stream_name}'")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Producer] Stopping observer")
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
