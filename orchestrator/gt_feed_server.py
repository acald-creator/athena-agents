"""Ground-truth JSONL HTTP feed for Console Agent Feed (replaces day9 bridge shim).

Exposes the athena-agents contract expected by platform/api-gateway AthenaClient:
  GET /sessions
  GET /events   (SSE stream of OPAR-shaped events from GT tail)
  GET /approvals
  POST /approvals/{id}/decision

Run:
  ATHENA_GT_OUTPUT=/tmp/run-gt.jsonl python -m orchestrator.gt_feed_server
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from queue import Empty, Queue
from typing import Any

GT_PATH = Path(os.environ.get("ATHENA_GT_OUTPUT", "/tmp/athena-gt.jsonl"))
BIND_HOST = os.environ.get("ATHENA_GT_FEED_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("ATHENA_GT_FEED_PORT", "8080"))
SESSION_ID = os.environ.get("ATHENA_GT_SESSION", f"gt-{uuid.uuid4().hex[:8]}")
TARGET = os.environ.get("ATHENA_GT_FEED_TARGET", "lab-target")

_subscribers: list[Queue] = []
_sub_lock = threading.Lock()
_session_started = time.time()
_event_count = 0
_event_lock = threading.Lock()


def gt_to_opar(record: dict[str, Any]) -> dict[str, Any]:
    global _event_count
    with _event_lock:
        _event_count += 1
        n = _event_count
    label = record.get("label", "")
    outcome = "pending" if label == "needs_review" else "success"
    return {
        "id": f"{record.get('run_id', SESSION_ID)}-{n}",
        "timestamp": record.get("timestamp")
        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sessionId": record.get("run_id") or SESSION_ID,
        "phase": "act",
        "target": record.get("target") or TARGET,
        "toolName": record.get("payload_family") or "opar",
        "outcomeStatus": outcome,
        "payload": {
            "technique": record.get("technique"),
            "expected_result": record.get("expected_result"),
            "label": label,
            "scenario_id": record.get("scenario_id"),
            "source": "athena-gt-feed",
        },
    }


def broadcast(event: dict[str, Any]) -> None:
    with _sub_lock:
        subs = list(_subscribers)
    for q in subs:
        try:
            q.put_nowait(event)
        except Exception:
            pass


def tail_gt() -> None:
    """Follow GT JSONL; reopen on truncate or inode replace."""
    GT_PATH.parent.mkdir(parents=True, exist_ok=True)
    GT_PATH.touch(exist_ok=True)
    seen_inode: int | None = None
    offset = 0
    while True:
        try:
            st = GT_PATH.stat()
        except FileNotFoundError:
            GT_PATH.touch(exist_ok=True)
            time.sleep(0.2)
            continue
        if seen_inode != st.st_ino:
            seen_inode = st.st_ino
            offset = 0
        with GT_PATH.open("r", encoding="utf-8") as fh:
            fh.seek(offset)
            while True:
                line = fh.readline()
                if not line:
                    offset = fh.tell()
                    try:
                        st2 = GT_PATH.stat()
                    except FileNotFoundError:
                        break
                    if st2.st_ino != seen_inode or st2.st_size < offset:
                        break
                    time.sleep(0.15)
                    continue
                offset = fh.tell()
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                broadcast(gt_to_opar(record))
        time.sleep(0.1)


class GTFeedHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[gt-feed] {fmt % args}", flush=True)

    def _json_response(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.startswith("/sessions"):
            with _event_lock:
                count = _event_count
            body = json.dumps(
                [
                    {
                        "id": SESSION_ID,
                        "target": TARGET,
                        "status": "running",
                        "started_at": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(_session_started)
                        ),
                        "event_count": count,
                        "gt_path": str(GT_PATH),
                    }
                ]
            ).encode()
            self._json_response(200, body)
            return

        if self.path.startswith("/approvals"):
            self._json_response(200, b"[]")
            return

        if self.path.startswith("/events"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q: Queue = Queue(maxsize=200)
            with _sub_lock:
                _subscribers.append(q)
            hello = {
                "id": f"{SESSION_ID}-hello",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "sessionId": SESSION_ID,
                "phase": "observe",
                "target": TARGET,
                "outcomeStatus": "pending",
                "payload": {"message": "gt feed connected", "gt_path": str(GT_PATH)},
            }
            try:
                self.wfile.write(f"data: {json.dumps(hello)}\n\n".encode())
                self.wfile.flush()
                while True:
                    try:
                        event = q.get(timeout=10.0)
                        self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                        self.wfile.flush()
                    except Empty:
                        self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with _sub_lock:
                    if q in _subscribers:
                        _subscribers.remove(q)
            return

        self.send_error(404)

    def do_POST(self) -> None:
        if self.path.startswith("/approvals/") and self.path.endswith("/decision"):
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)
            self._json_response(200, json.dumps({"status": "recorded"}).encode())
            return
        self.send_error(404)


def main() -> None:
    threading.Thread(target=tail_gt, name="gt-tail", daemon=True).start()
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), GTFeedHandler)
    print(
        f"athena gt feed: http://{BIND_HOST}:{BIND_PORT} tailing {GT_PATH}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
