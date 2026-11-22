"""Run log — append-only JSONL events, bounded like an audit trail."""

import pytest

from cyberagent.events import RunLog, RunLogError, read_events


def test_roundtrip(tmp_path):
    path = tmp_path / "run.jsonl"
    log = RunLog(str(path))
    log.record("scan.started", run_id="r1", timeout=2.0)
    log.record("probe.result", host="127.0.0.1", port=22, state="open")
    log.record("run.finished", hosts=1)
    log.close()
    events = read_events(str(path))
    assert [e["event"] for e in events] == [
        "scan.started",
        "probe.result",
        "run.finished",
    ]
    assert events[1]["port"] == 22


def test_fields_sorted_and_compact(tmp_path):
    path = tmp_path / "run.jsonl"
    log = RunLog(str(path))
    log.record("e", b=2, a=1)
    log.close()
    assert path.read_text().strip() == '{"a":1,"b":2,"event":"e"}'


def test_event_name_rules(tmp_path):
    log = RunLog(str(tmp_path / "run.jsonl"))
    with pytest.raises(RunLogError):
        log.record("BadName")
    with pytest.raises(RunLogError):
        log.record("x" * 100)
    with pytest.raises(RunLogError):
        log.record(123)
    log.close()


def test_max_fields(tmp_path):
    log = RunLog(str(tmp_path / "run.jsonl"))
    log.record("e", **{f"f{i}": i for i in range(32)})
    log.close()
    log2 = RunLog(str(tmp_path / "run2.jsonl"))
    with pytest.raises(RunLogError):
        log2.record("e", **{f"f{i}": i for i in range(33)})
    log2.close()


def test_not_json_safe(tmp_path):
    log = RunLog(str(tmp_path / "run.jsonl"))
    with pytest.raises(RunLogError):
        log.record("e", data=object())
    with pytest.raises(RunLogError):
        log.record("e", data=float("nan"))
    log.close()


def test_line_cap(tmp_path):
    log = RunLog(str(tmp_path / "run.jsonl"))
    with pytest.raises(RunLogError):
        log.record("e", blob="x" * (64 * 1024))
    log.close()


def test_read_events_validation(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"event": "e"}\nnot json\n')
    with pytest.raises(RunLogError):
        read_events(str(bad))

    no_name = tmp_path / "no_name.jsonl"
    no_name.write_text('{"no_event": 1}\n')
    with pytest.raises(RunLogError):
        read_events(str(no_name))

    ok = tmp_path / "ok.jsonl"
    ok.write_text('\n{"event": "a.b", "x": 1}\n')
    assert read_events(str(ok)) == [{"event": "a.b", "x": 1}]


def test_context_manager(tmp_path):
    path = tmp_path / "run.jsonl"
    with RunLog(str(path)) as log:
        log.record("e", x=1)
    assert read_events(str(path)) == [{"event": "e", "x": 1}]
