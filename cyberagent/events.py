"""Run log — append-only JSONL events.

Bounded like an audit trail: event names match a regex, payloads cap at
32 fields and 64 KiB per line. No hash chain — the run log is evidence
for humans; the scope file itself is the authorization record.

(Shared design with FailureLab's run log — same author, MIT.)
"""

from __future__ import annotations

import json
import re

__all__ = ["RunLogError", "RunLog", "read_events"]

EVENT_RE = re.compile(r"^[a-z][a-z0-9.]{0,63}$")
MAX_FIELDS = 32
MAX_LINE = 64 * 1024


class RunLogError(ValueError):
    """Event is outside the log's bounds (fail closed)."""


class RunLog:
    """Append-only JSONL event log."""

    def __init__(self, path):
        self._path = path
        self._fh = open(path, "a", encoding="utf-8")

    def record(self, event, **fields):
        if not isinstance(event, str) or not EVENT_RE.match(event):
            raise RunLogError(f"event name must match {EVENT_RE.pattern}")
        if len(fields) > MAX_FIELDS:
            raise RunLogError(f"events carry at most {MAX_FIELDS} fields")
        payload = {"event": event, **fields}
        try:
            line = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError) as exc:
            raise RunLogError(f"event {event} is not JSON-safe: {exc}") from exc
        if len(line) > MAX_LINE:
            raise RunLogError(f"event {event} exceeds {MAX_LINE} chars")
        self._fh.write(line + "\n")
        self._fh.flush()

    def close(self):
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def read_events(path):
    """Read a run log back as a list of event dicts (validated)."""
    events = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except ValueError as exc:
                raise RunLogError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            if not isinstance(payload, dict) or "event" not in payload:
                raise RunLogError(f"{path}:{lineno}: event name missing")
            if not isinstance(payload["event"], str) or not EVENT_RE.match(
                payload["event"]
            ):
                raise RunLogError(f"{path}:{lineno}: bad event name")
            events.append(payload)
    return events
