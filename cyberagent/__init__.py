"""CYBERAGENT — authorized recon engine.

The scope file bounds every probe. Findings become Bridge objectives.
Pure Python, zero dependencies, fail closed, bounded everywhere.

    from cyberagent import load_scope_file, scan_entry

    scope = load_scope_file("scope.yaml")
    for entry in scope.active_entries():
        record = scan_entry(entry, timeout=2.0, workers=8)
        print(entry.host, [r.port for r in record.results if r.state == "open"])
"""

from .events import RunLog, RunLogError, read_events
from .objectives import build_objectives
from .report import ReportError, render_json, render_markdown, summarize
from .scan import (
    ScanError,
    ScanRecord,
    ProbeResult,
    check_timeout,
    check_workers,
    probe,
    scan_entry,
)
from .scope import Scope, ScopeEntry, ScopeError, load_scope_file, today_utc
from .service import guess_service

__version__ = "0.1.0"

__all__ = [
    "ProbeResult",
    "ReportError",
    "RunLog",
    "RunLogError",
    "ScanError",
    "ScanRecord",
    "Scope",
    "ScopeEntry",
    "ScopeError",
    "build_objectives",
    "check_timeout",
    "check_workers",
    "guess_service",
    "load_scope_file",
    "probe",
    "read_events",
    "render_json",
    "render_markdown",
    "scan_entry",
    "summarize",
    "today_utc",
]
