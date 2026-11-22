"""CLI end-to-end — real loopback servers, real files, real exit codes."""

import json
import os
import subprocess
import sys

import pytest

from cyberagent import cli
from cyberagent.events import RunLog, read_events

from loopback import LocalServer, closed_port

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _scope_text(ports, host="127.0.0.1", expires=None):
    lines = [
        "scope:",
        f"  - host: {host}",
        "    reason: end-to-end test of my own loopback services",
        "    ports:",
    ]
    lines += [f"      - {p}" for p in ports]
    if expires:
        lines.append(f"    expires: {expires}")
    return "\n".join(lines) + "\n"


def _write(tmp_path, text):
    path = tmp_path / "scope.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


# -- scope -----------------------------------------------------------------


def test_scope_command(capsys, tmp_path):
    path = _write(tmp_path, _scope_text(["22", "8000-8008"], expires="2027-12-31"))
    assert cli.main(["scope", path]) == 0
    out = capsys.readouterr().out
    assert "127.0.0.1  [active]" in out
    assert "ports: 22,8000,8001,8002,8003,8004,8005,8006,8007,8008" in out
    assert "reason: end-to-end test of my own loopback services" in out


def test_scope_command_shows_expired(capsys, tmp_path):
    path = _write(tmp_path, _scope_text(["22"], expires="2020-01-01"))
    assert cli.main(["scope", path]) == 0
    assert "[expired 2020-01-01]" in capsys.readouterr().out


# -- scan ------------------------------------------------------------------


def test_scan_end_to_end(capsys, tmp_path):
    server = LocalServer(greeting=b"SSH-2.0-OpenSSH_9.6\r\n")
    closed = closed_port()
    try:
        path = _write(tmp_path, _scope_text([str(server.port), str(closed)]))
        outdir = tmp_path / "run"
        rc = cli.main(["scan", path, "--timeout", "0.5", "--out", str(outdir)])
        assert rc == 0
    finally:
        server.close()
    out = capsys.readouterr().out
    assert f"127.0.0.1: open {server.port}" in out
    assert "1 open, 1 closed" in out
    assert f"run: {outdir / 'run.jsonl'}" in out

    events = read_events(str(outdir / "run.jsonl"))
    names = [e["event"] for e in events]
    assert names[0] == "scan.started"
    assert names[-1] == "run.finished"
    assert names.count("probe.result") == 2
    assert names.count("scan.finished") == 1
    started = events[0]
    assert started["targets"][0]["reason"] == (
        "end-to-end test of my own loopback services"
    )
    finished = events[-1]
    assert finished["hosts"] == 1
    assert finished["probes"] == 2
    assert finished["open"] == 1
    assert finished["closed"] == 1

    report_md = (outdir / "report.md").read_text()
    assert "## 127.0.0.1" in report_md
    assert "SSH-2.0-OpenSSH_9.6" in report_md
    assert f"| {server.port} | OPEN | ssh |" in report_md

    objectives = json.loads((outdir / "objectives.json").read_text())
    assert len(objectives) == 1
    assert objectives[0]["port"] == server.port
    assert objectives[0]["service"] == "ssh"


def test_scan_default_outdir(capsys, tmp_path):
    server = LocalServer(greeting=b"SSH-2.0-Test\r\n")
    try:
        path = _write(tmp_path, _scope_text([str(server.port)]))
        assert cli.main(["scan", path, "--timeout", "0.5"]) == 0
    finally:
        server.close()
    capsys.readouterr()
    runs = tmp_path / "runs"
    (run_id,) = [p.name for p in runs.iterdir()]
    assert (runs / run_id / "run.jsonl").exists()
    assert (runs / run_id / "report.md").exists()
    assert (runs / run_id / "objectives.json").exists()


def test_scan_json(capsys, tmp_path):
    server = LocalServer(greeting=b"SSH-2.0-Test\r\n")
    try:
        path = _write(tmp_path, _scope_text([str(server.port)]))
        outdir = tmp_path / "run"
        rc = cli.main(
            ["scan", path, "--timeout", "0.5", "--out", str(outdir), "--json"]
        )
        assert rc == 0
    finally:
        server.close()
    summary = json.loads(capsys.readouterr().out)
    assert summary["totals"]["open"] == 1
    assert (outdir / "report.json").exists()


def test_target_scans_only_that_host(capsys, tmp_path):
    server = LocalServer(greeting=b"SSH-2.0-Test\r\n")
    try:
        text = (
            "scope:\n"
            "  - host: 127.0.0.1\n"
            "    reason: first\n"
            "    ports:\n"
            f"      - {server.port}\n"
            "  - host: 127.0.0.2\n"
            "    reason: second\n"
            "    ports:\n"
            "      - 22\n"
        )
        path = _write(tmp_path, text)
        outdir = tmp_path / "run"
        rc = cli.main(
            [
                "scan",
                path,
                "--target",
                "127.0.0.1",
                "--timeout",
                "0.5",
                "--out",
                str(outdir),
            ]
        )
        assert rc == 0
    finally:
        server.close()
    capsys.readouterr()
    hosts = {
        e.get("host") for e in read_events(str(outdir / "run.jsonl"))
        if e["event"] == "probe.result"
    }
    assert hosts == {"127.0.0.1"}


def test_target_must_be_in_scope(capsys, tmp_path):
    path = _write(tmp_path, _scope_text(["22"]))
    assert cli.main(["scan", path, "--target", "10.9.9.9"]) == 2
    assert "not in the scope" in capsys.readouterr().err


def test_target_expired_entry_refuses(capsys, tmp_path):
    path = _write(tmp_path, _scope_text(["22"], expires="2020-01-01"))
    assert cli.main(["scan", path, "--target", "127.0.0.1"]) == 2
    assert "expired" in capsys.readouterr().err


def test_all_expired_refuses(capsys, tmp_path):
    path = _write(tmp_path, _scope_text(["22"], expires="2020-01-01"))
    assert cli.main(["scan", path]) == 2
    assert "no active targets" in capsys.readouterr().err


# -- report + objectives ----------------------------------------------------


def test_report_and_objectives_commands(capsys, tmp_path):
    log = tmp_path / "run.jsonl"
    with RunLog(str(log)) as rl:
        rl.record(
            "scan.started",
            run_id="r1",
            started_at="2026-11-21 12:00:00",
            timeout=2.0,
            workers=4,
            targets=[{"host": "127.0.0.1", "reason": "local dev", "ports": [22]}],
        )
        rl.record(
            "probe.result",
            host="127.0.0.1",
            port=22,
            state="open",
            service="ssh",
            banner="SSH-2.0-Test",
            http_status=0,
            server_header="",
            duration=0.01,
        )
        rl.record(
            "scan.finished",
            host="127.0.0.1",
            duration=0.01,
            open=1,
            closed=0,
            filtered=0,
            error=0,
        )
        rl.record(
            "run.finished", hosts=1, probes=1, open=1, closed=0, filtered=0, error=0
        )

    assert cli.main(["report", str(log)]) == 0
    out = capsys.readouterr().out
    assert "# CYBERAGENT Report" in out
    assert "## 127.0.0.1" in out

    assert cli.main(["report", str(log), "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["totals"]["open"] == 1

    assert cli.main(["objectives", str(log)]) == 0
    objectives = json.loads(capsys.readouterr().out)
    assert len(objectives) == 1
    assert objectives[0]["topic"] == "ssh service on 127.0.0.1:22"


# -- failure paths ----------------------------------------------------------


def test_missing_scope_file(capsys, tmp_path):
    assert cli.main(["scope", str(tmp_path / "nope.yaml")]) == 2
    assert "error:" in capsys.readouterr().err


def test_no_args_exits_2():
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_module_invocation(tmp_path):
    path = _write(tmp_path, _scope_text(["22"], expires="2027-12-31"))
    for mod in ("cyberagent.cli", "cyberagent"):
        proc = subprocess.run(
            [sys.executable, "-m", mod, "scope", path],
            capture_output=True,
            text=True,
            cwd=REPO,
        )
        assert proc.returncode == 0, proc.stderr
        assert "[active]" in proc.stdout
