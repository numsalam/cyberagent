# CYBERAGENT

Authorized recon engine — **the scope file bounds every probe.**

CYBERAGENT is a port scanner that is *incapable* of touching anything
not explicitly listed in a scope file. Every entry must say **why** it
is authorized. Expired entries go silent. Findings become deterministic,
evidence-linked objectives in the Bridge's shape, ready to feed the
neural training loop.

Pure Python, zero dependencies, fail closed, bounded everywhere.

## Why

Recon tools default to "scan first, ask later." CYBERAGENT inverts that:
no scope file → no scanning. The engine never defaults, never sweeps,
never guesses authorization. This is TrustContract's fail-closed pattern
applied to reconnaissance — the tool and the permission are one artifact.

## Install

    pip install .          # or run from the repo: python3 -m cyberagent

## The scope file

    scope:
      - host: 127.0.0.1
        reason: local development services on my own machine
        ports:
          - 22
          - 8000-8008        # inclusive range
        owner: numsalam      # optional
        expires: 2027-12-31  # optional, YYYY-MM-DD (UTC)

Rules, all enforced eagerly at load time:

- `reason` is required (1..500 chars) — authorization is designed, not assumed
- ports are an allowlist, ≤ 64 per host; ranges are inclusive
- `expires` is a UTC date; past-due entries go inactive
- unknown keys, duplicate hosts, duplicate ports, bad dates all reject
- ≤ 32 entries per file

## CLI

    cyberagent scope examples/scope.yaml          # what is authorized?
    cyberagent scan examples/scope.yaml           # probe it
    cyberagent report runs/<id>/run.jsonl         # re-render a report
    cyberagent objectives runs/<id>/run.jsonl     # Bridge objectives JSON

Exit codes: 0 ok, 2 error or denied. (1 reserved for future use.)

`scan` writes `run.jsonl` (append-only event log), `report.md`, and
`objectives.json` to `<scope dir>/runs/<run id>/` — or `--out DIR`.
`--target HOST` scans a single host, but only if that host is itself
in scope and active; otherwise the run refuses. `--timeout` (0.1..10.0s)
and `--workers` (1..32) bound every probe.

## What a probe does

1. TCP connect with a bounded timeout
   - refused → `closed`, timeout → `filtered`, other OSError → `error`
2. When open: passive banner read (≤ 256 bytes, short wait)
3. When the service stays quiet: one HTTP-shaped `HEAD` request,
   then a status-line + `Server` header parse
4. Deterministic service guess from a fixed signature table
   (ssh, http, pop3, redis, mysql, jenkins, ftp, smtp, imap,
   nginx, apache, caddy, iis, tomcat, jetty, gunicorn, uvicorn, traefik)

`scan_entry` fans an entry's allowlisted ports over a bounded thread
pool. Total work is bounded by the scope itself: ≤ 32 hosts × ≤ 64 ports,
each capped by the connect timeout. The scanner never sweeps.

## Findings → Bridge objectives

Every open port becomes one objective:

```json
{
  "id": "0847d0f2…",
  "topic": "http service on 127.0.0.1:8000",
  "prerequisite_ids": [],
  "evidence_sha256": "ae3ce5b8…",
  "expected_terms": ["http", "127.0.0.1", "8000"],
  "kind": "recon-finding",
  "source": "cyberagent",
  "run_id": "20261121-221903-71454c5b",
  "host": "127.0.0.1",
  "port": 8000,
  "service": "http",
  "created_at": "2026-11-22T04:19:04Z"
}
```

Ids are sha256-derived — the same finding always maps to the same
objective, so the Bridge can dedupe and link evidence across runs.
The shape matches numaware-brain's `Objective` (id, topic,
prerequisite_ids, evidence_sha256, expected_terms); exact DB ingestion
is follow-up work, this export is the stable contract.

## Library

    from cyberagent import load_scope_file, scan_entry

    scope = load_scope_file("scope.yaml")
    for entry in scope.active_entries():
        record = scan_entry(entry, timeout=2.0, workers=8)
        print(entry.host, [r.port for r in record.results if r.state == "open"])

`scope.permits(host, port)` / `scope.why_denied(host, port)` answer
authorization queries directly — other tools can adopt the same contract.

## Limitations (v0)

- TCP connect + banner/HEAD only; no TLS, no UDP, no OS fingerprinting
- service guesses come from a fixed table; unknown stays unknown (`—`)
- hostnames resolve through the OS resolver at probe time
- no run-to-run diffing yet

## Layout

    cyberagent/scope.py       the authorization contract (fail closed)
    cyberagent/scan.py        TCP probe + banner/HEAD grab, bounded pool
    cyberagent/service.py     deterministic signature table
    cyberagent/events.py      run log (JSONL, bounded)
    cyberagent/report.py      summary → Markdown / JSON
    cyberagent/objectives.py  findings → Bridge objectives
    cyberagent/cli.py         command line
    tests/                    82 tests, real loopback sockets

## Tests

    python3 -m pytest -q

MIT © Numsalam (NUMAWARE)
