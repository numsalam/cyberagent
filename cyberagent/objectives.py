"""Findings → Bridge objectives — deterministic, evidence-linked.

Every open port becomes one objective in the Bridge's shape (id, topic,
prerequisite_ids, evidence_sha256, expected_terms) plus recon-specific
fields. Ids are sha256-derived, so the same finding always maps to the
same objective — the Bridge can dedupe and link evidence across runs.

The exact DB ingestion is follow-up work; this export is the stable,
deterministic contract.
"""

from __future__ import annotations

import hashlib
import json
import time

__all__ = ["build_objectives"]


def build_objectives(events):
    """Bridge-compatible objective dicts for every open port in a run log."""
    if not isinstance(events, list):
        raise ValueError("events must be a list")
    run_id = ""
    for event in events:
        if event.get("event") == "scan.started":
            run_id = event.get("run_id", "")
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = []
    for event in events:
        if event.get("event") != "probe.result" or event.get("state") != "open":
            continue
        host = event.get("host")
        port = event.get("port")
        service = event.get("service") or "open"
        evidence = json.dumps(
            {
                "host": host,
                "port": port,
                "service": service,
                "banner": event.get("banner", ""),
                "http_status": event.get("http_status", 0),
                "server_header": event.get("server_header", ""),
                "run_id": run_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        out.append({
            "id": hashlib.sha256(
                f"cyberagent:{run_id}:{host}:{port}".encode()
            ).hexdigest(),
            "topic": f"{service} service on {host}:{port}",
            "prerequisite_ids": [],
            "evidence_sha256": hashlib.sha256(evidence.encode()).hexdigest(),
            "expected_terms": [service, host, str(port)],
            "kind": "recon-finding",
            "source": "cyberagent",
            "run_id": run_id,
            "host": host,
            "port": port,
            "service": service,
            "created_at": created_at,
        })
    return out
