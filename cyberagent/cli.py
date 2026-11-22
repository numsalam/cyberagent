"""CYBERAGENT command line.

    cyberagent scope <file>                    show what is authorized
    cyberagent scan <file> [options]           probe the authorized scope
    cyberagent report <run.jsonl> [--json]     re-render a report
    cyberagent objectives <run.jsonl>          print Bridge objectives JSON

Exit codes: 0 ok, 2 error or denied. (1 reserved for future use.)

The scan command only ever probes ports allowlisted in the scope file;
``--target`` must itself be in scope and active or the run refuses.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid

from . import report
from .events import RunLog, RunLogError, read_events
from .objectives import build_objectives
from .scan import ScanError, check_timeout, check_workers, scan_entry
from .scope import ScopeError, load_scope_file, today_utc

__all__ = ["main"]


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ScopeError, ScanError, RunLogError, report.ReportError,
            json.JSONDecodeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


# -- subcommands ------------------------------------------------------------


def _cmd_scope(args):
    scope = load_scope_file(args.file)
    day = today_utc()
    for entry in scope.entries:
        state = "active" if entry.active(day) else f"expired {entry.expires}"
        ports = ",".join(str(p) for p in sorted(entry.ports))
        print(f"{entry.host}  [{state}]  ports: {ports}")
        print(f"  reason: {entry.reason}")
        if entry.owner:
            print(f"  owner: {entry.owner}")
    return 0


def _cmd_scan(args):
    scope = load_scope_file(args.file)
    timeout = check_timeout(args.timeout)
    workers = check_workers(args.workers)
    day = today_utc()

    if args.target:
        entry = scope.entry_for(args.target)
        if entry is None:
            raise ScopeError(f"host {args.target!r} is not in the scope")
        if not entry.active(day):
            raise ScopeError(f"entry for {entry.host!r} expired on {entry.expires}")
        entries = [entry]
    else:
        entries = list(scope.active_entries(day))
        if not entries:
            raise ScopeError("no active targets in scope (all expired?)")

    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    outdir = args.out or os.path.join(
        os.path.dirname(os.path.abspath(args.file)), "runs", run_id
    )
    os.makedirs(outdir, exist_ok=True)
    log_path = os.path.join(outdir, "run.jsonl")

    log = RunLog(log_path)
    try:
        log.record(
            "scan.started",
            run_id=run_id,
            started_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            timeout=timeout,
            workers=workers,
            targets=[
                {"host": e.host, "reason": e.reason, "ports": sorted(e.ports)}
                for e in entries
            ],
        )
        records = []
        for entry in entries:
            record = scan_entry(entry, timeout, workers)
            records.append(record)
            for result in record.results:
                log.record(
                    "probe.result",
                    host=entry.host,
                    port=result.port,
                    state=result.state,
                    service=result.service,
                    banner=result.banner[:200],
                    http_status=result.http_status,
                    server_header=result.server_header,
                    duration=result.duration,
                )
            counts = {"open": 0, "closed": 0, "filtered": 0, "error": 0}
            for result in record.results:
                if result.state in counts:
                    counts[result.state] += 1
            log.record(
                "scan.finished",
                host=entry.host,
                duration=record.duration,
                **counts,
            )
        totals = {"hosts": len(records), "probes": 0,
                  "open": 0, "closed": 0, "filtered": 0, "error": 0}
        for record in records:
            totals["probes"] += len(record.results)
            for result in record.results:
                if result.state in ("open", "closed", "filtered", "error"):
                    totals[result.state] += 1
        log.record("run.finished", **totals)
    finally:
        log.close()

    events = read_events(log_path)
    summary = report.summarize(events)
    _write_text(os.path.join(outdir, "report.md"), report.render_markdown(summary))
    _write_text(
        os.path.join(outdir, "objectives.json"),
        json.dumps(build_objectives(events), indent=2, sort_keys=True),
    )
    if args.json:
        _write_text(os.path.join(outdir, "report.json"), report.render_json(summary))
        print(report.render_json(summary))
    else:
        for host in summary["hosts"]:
            open_ports = [str(p["port"]) for p in host["probes"] if p["state"] == "open"]
            shown = ",".join(open_ports) if open_ports else "none"
            print(f"{host['host']}: open {shown}")
        t = summary["totals"]
        print(
            f"{t['hosts']} hosts, {t['probes']} probes: "
            f"{t['open']} open, {t['closed']} closed, "
            f"{t['filtered']} filtered, {t['error']} errors"
        )
        print(f"run: {log_path}")
    return 0


def _cmd_report(args):
    summary = report.summarize(read_events(args.log))
    if args.json:
        print(report.render_json(summary))
    else:
        print(report.render_markdown(summary))
    return 0


def _cmd_objectives(args):
    objectives = build_objectives(read_events(args.log))
    print(json.dumps(objectives, indent=2, sort_keys=True))
    return 0


# -- helpers ---------------------------------------------------------------


def _parser():
    parser = argparse.ArgumentParser(
        prog="cyberagent",
        description="Authorized recon engine — the scope file bounds every probe",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scope", help="show what is authorized")
    p.add_argument("file")
    p.set_defaults(func=_cmd_scope)

    p = sub.add_parser("scan", help="probe the authorized scope")
    p.add_argument("file")
    p.add_argument("--target", help="scan only this in-scope host")
    p.add_argument("--timeout", type=float, default=None,
                   help="per-probe timeout 0.1..10.0s (default 2.0)")
    p.add_argument("--workers", type=int, default=None,
                   help="worker threads 1..32 (default 8)")
    p.add_argument("--out", help="output directory (default: <file dir>/runs/<run id>)")
    p.add_argument("--json", action="store_true",
                   help="write report.json and print JSON instead of text")
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("report", help="render a report from a run log")
    p.add_argument("log")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_report)

    p = sub.add_parser("objectives", help="print Bridge objectives JSON for a run")
    p.add_argument("log")
    p.set_defaults(func=_cmd_objectives)

    return parser


def _write_text(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
