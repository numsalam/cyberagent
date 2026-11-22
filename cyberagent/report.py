"""Report — fold a run log into one summary, rendered as Markdown or JSON."""

from __future__ import annotations

import json

__all__ = ["ReportError", "summarize", "render_markdown", "render_json"]


class ReportError(ValueError):
    """Run log does not have the shape of a CYBERAGENT run."""


def summarize(events):
    """Fold event dicts (from :func:`read_events`) into one summary dict."""
    if not isinstance(events, list):
        raise ReportError("events must be a list")
    run = None
    reasons = {}
    hosts = {}
    order = []
    for event in events:
        name = event.get("event")
        if name == "scan.started":
            run = event
            for target in event.get("targets", []):
                reasons[target.get("host")] = target.get("reason", "")
        elif name == "probe.result":
            host = event.get("host")
            if host not in hosts:
                hosts[host] = {
                    "host": host,
                    "reason": reasons.get(host, ""),
                    "probes": [],
                    "duration": 0.0,
                }
                order.append(host)
            hosts[host]["probes"].append({
                "port": event.get("port"),
                "state": event.get("state"),
                "service": event.get("service", ""),
                "banner": event.get("banner", ""),
                "http_status": event.get("http_status", 0),
                "server_header": event.get("server_header", ""),
                "duration": event.get("duration", 0.0),
            })
        elif name == "scan.finished":
            host = event.get("host")
            if host in hosts:
                hosts[host]["duration"] = event.get("duration", 0.0)
    if run is None:
        raise ReportError("missing scan.started event")
    host_list = [hosts[h] for h in order]
    totals = {"hosts": len(host_list), "probes": 0,
              "open": 0, "closed": 0, "filtered": 0, "error": 0}
    for host in host_list:
        counts = {"open": 0, "closed": 0, "filtered": 0, "error": 0}
        for probe in host["probes"]:
            if probe["state"] in counts:
                counts[probe["state"]] += 1
        host["counts"] = counts
        totals["probes"] += len(host["probes"])
        for key in ("open", "closed", "filtered", "error"):
            totals[key] += counts[key]
    return {
        "run_id": run.get("run_id", ""),
        "started_at": run.get("started_at", ""),
        "timeout": run.get("timeout", 0.0),
        "workers": run.get("workers", 0),
        "hosts": host_list,
        "totals": totals,
    }


def render_json(summary):
    """Summary as indented, sorted JSON."""
    return json.dumps(summary, indent=2, sort_keys=True, allow_nan=False)


def render_markdown(summary):
    """Summary as a human-readable Markdown report."""
    t = summary["totals"]
    lines = [
        "# CYBERAGENT Report",
        "",
        f"Run `{summary['run_id']}` — started {summary['started_at']} "
        f"— timeout {summary['timeout']:.1f}s — {summary['workers']} workers",
        "",
        f"**{t['hosts']} hosts, {t['probes']} probes: "
        f"{t['open']} open, {t['closed']} closed, "
        f"{t['filtered']} filtered, {t['error']} errors**",
        "",
    ]
    for host in summary["hosts"]:
        lines.append(f"## {host['host']}")
        lines.append("")
        if host["reason"]:
            lines.append(f"_authorized: {host['reason']}_")
            lines.append("")
        lines.append("| Port | State | Service | HTTP | Banner |")
        lines.append("|---|---|---|---|---|")
        for probe in host["probes"]:
            state = probe["state"].upper()
            service = probe["service"] or "—"
            http = str(probe["http_status"]) if probe["http_status"] else "—"
            banner = probe["banner"][:60] or "—"
            lines.append(
                f"| {probe['port']} | {state} | {service} | {http} | {banner} |"
            )
        c = host["counts"]
        lines.append("")
        lines.append(
            f"{len(host['probes'])} probes in {host['duration']:.2f}s — "
            f"{c['open']} open, {c['closed']} closed, "
            f"{c['filtered']} filtered, {c['error']} errors"
        )
        lines.append("")
    return "\n".join(lines)
