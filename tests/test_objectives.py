"""Objectives — findings become deterministic, evidence-linked Bridge objectives."""

import re

import pytest

from cyberagent.objectives import build_objectives

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _events(run_id="r1"):
    return [
        {
            "event": "scan.started",
            "run_id": run_id,
            "started_at": "2026-11-21 12:00:00",
            "timeout": 2.0,
            "workers": 4,
            "targets": [{"host": "127.0.0.1", "reason": "local dev", "ports": [22, 80]}],
        },
        {
            "event": "probe.result",
            "host": "127.0.0.1",
            "port": 22,
            "state": "open",
            "service": "ssh",
            "banner": "SSH-2.0-Test",
            "http_status": 0,
            "server_header": "",
            "duration": 0.01,
        },
        {
            "event": "probe.result",
            "host": "127.0.0.1",
            "port": 80,
            "state": "closed",
            "service": "",
            "banner": "",
            "http_status": 0,
            "server_header": "",
            "duration": 0.0,
        },
        {
            "event": "scan.finished",
            "host": "127.0.0.1",
            "duration": 0.02,
            "open": 1,
            "closed": 1,
            "filtered": 0,
            "error": 0,
        },
        {
            "event": "run.finished",
            "hosts": 1,
            "probes": 2,
            "open": 1,
            "closed": 1,
            "filtered": 0,
            "error": 0,
        },
    ]


def test_only_open_ports_become_objectives():
    (obj,) = build_objectives(_events())
    assert obj["host"] == "127.0.0.1"
    assert obj["port"] == 22
    assert obj["service"] == "ssh"
    assert obj["topic"] == "ssh service on 127.0.0.1:22"
    assert obj["expected_terms"] == ["ssh", "127.0.0.1", "22"]


def test_bridge_shape():
    (obj,) = build_objectives(_events())
    for key in ("id", "topic", "prerequisite_ids", "evidence_sha256", "expected_terms"):
        assert key in obj
    assert HEX64.match(obj["id"])
    assert HEX64.match(obj["evidence_sha256"])
    assert obj["prerequisite_ids"] == []
    assert obj["kind"] == "recon-finding"
    assert obj["source"] == "cyberagent"
    assert obj["run_id"] == "r1"
    assert obj["created_at"].endswith("Z")


def test_ids_are_deterministic():
    a = build_objectives(_events())
    b = build_objectives(_events())
    assert a[0]["id"] == b[0]["id"]
    assert a[0]["evidence_sha256"] == b[0]["evidence_sha256"]


def test_different_run_different_id():
    a = build_objectives(_events("r1"))[0]
    b = build_objectives(_events("r2"))[0]
    assert a["id"] != b["id"]
    assert a["evidence_sha256"] != b["evidence_sha256"]


def test_service_falls_back_to_open():
    events = [
        {"event": "scan.started", "run_id": "r1", "targets": []},
        {
            "event": "probe.result",
            "host": "h",
            "port": 1,
            "state": "open",
            "service": "",
            "banner": "",
            "http_status": 0,
            "server_header": "",
            "duration": 0.0,
        },
    ]
    (obj,) = build_objectives(events)
    assert obj["service"] == "open"
    assert obj["topic"] == "open service on h:1"


def test_empty_and_invalid():
    assert build_objectives([]) == []
    with pytest.raises(ValueError):
        build_objectives("nope")
