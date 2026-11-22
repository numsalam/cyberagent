"""Report — fold events into one summary, render Markdown/JSON."""

import json

import pytest

from cyberagent.report import ReportError, render_json, render_markdown, summarize


def _events():
    return [
        {
            "event": "scan.started",
            "run_id": "r1",
            "started_at": "2026-11-21 12:00:00",
            "timeout": 2.0,
            "workers": 4,
            "targets": [
                {"host": "127.0.0.1", "reason": "local dev", "ports": [22, 80]},
                {"host": "10.0.0.1", "reason": "lab host", "ports": [443]},
            ],
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
            "event": "probe.result",
            "host": "10.0.0.1",
            "port": 443,
            "state": "filtered",
            "service": "",
            "banner": "",
            "http_status": 0,
            "server_header": "",
            "duration": 2.0,
        },
        {
            "event": "scan.finished",
            "host": "10.0.0.1",
            "duration": 2.0,
            "open": 0,
            "closed": 0,
            "filtered": 1,
            "error": 0,
        },
        {
            "event": "run.finished",
            "hosts": 2,
            "probes": 3,
            "open": 1,
            "closed": 1,
            "filtered": 1,
            "error": 0,
        },
    ]


def test_summarize():
    summary = summarize(_events())
    assert summary["run_id"] == "r1"
    assert summary["started_at"] == "2026-11-21 12:00:00"
    assert summary["timeout"] == 2.0
    assert summary["workers"] == 4
    assert summary["totals"] == {
        "hosts": 2,
        "probes": 3,
        "open": 1,
        "closed": 1,
        "filtered": 1,
        "error": 0,
    }
    by_host = {h["host"]: h for h in summary["hosts"]}
    assert by_host["127.0.0.1"]["reason"] == "local dev"
    assert by_host["10.0.0.1"]["reason"] == "lab host"
    assert by_host["127.0.0.1"]["counts"] == {
        "open": 1,
        "closed": 1,
        "filtered": 0,
        "error": 0,
    }
    assert by_host["10.0.0.1"]["counts"]["filtered"] == 1
    assert by_host["127.0.0.1"]["duration"] == 0.02
    assert [p["port"] for p in by_host["127.0.0.1"]["probes"]] == [22, 80]


def test_summarize_reason_falls_back_empty():
    events = _events()[:1] + [
        {
            "event": "probe.result",
            "host": "unknown.host",
            "port": 1,
            "state": "error",
            "service": "",
            "banner": "",
            "http_status": 0,
            "server_header": "",
            "duration": 0.0,
        },
    ]
    (host,) = summarize(events)["hosts"]
    assert host["host"] == "unknown.host"
    assert host["reason"] == ""


def test_render_markdown():
    text = render_markdown(summarize(_events()))
    assert text.startswith("# CYBERAGENT Report")
    assert "Run `r1`" in text
    assert "## 127.0.0.1" in text
    assert "## 10.0.0.1" in text
    assert "_authorized: local dev_" in text
    assert "_authorized: lab host_" in text
    assert "| 22 | OPEN | ssh | — | SSH-2.0-Test |" in text
    assert "| 80 | CLOSED | — | — | — |" in text
    assert "| 443 | FILTERED |" in text
    assert "2 probes in 0.02s — 1 open, 1 closed, 0 filtered, 0 errors" in text


def test_render_json_roundtrip():
    summary = summarize(_events())
    assert json.loads(render_json(summary)) == summary


def test_errors():
    with pytest.raises(ReportError):
        summarize([])
    with pytest.raises(ReportError):
        summarize("nope")
