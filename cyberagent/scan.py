"""Scanner — TCP probes bounded by the scope. Never sweeps.

``probe`` connects to one host:port, classifies the outcome, and — when
open — grabs what the service says about itself:

1. passive banner read (short wait, ≤ 256 bytes)
2. if the service stayed quiet, one HTTP-shaped ``HEAD`` request and a
   status-line + Server-header parse

Classification is deterministic: ConnectionRefused → closed, timeout →
filtered, other OSError → error (DNS failure, unreachable, …).

``scan_entry`` fans an entry's allowlisted ports over a bounded thread
pool (1..32 workers). Total work is bounded by the scope itself:
≤ 32 hosts × ≤ 64 ports, each capped by the connect timeout.
"""

from __future__ import annotations

import concurrent.futures
import socket
import time
from dataclasses import dataclass

from .scope import ScopeEntry
from .service import guess_service

__all__ = [
    "ScanError",
    "ProbeResult",
    "ScanRecord",
    "check_timeout",
    "check_workers",
    "probe",
    "scan_entry",
]

MIN_TIMEOUT, MAX_TIMEOUT, DEFAULT_TIMEOUT = 0.1, 10.0, 2.0
MIN_WORKERS, MAX_WORKERS, DEFAULT_WORKERS = 1, 32, 8
BANNER_BYTES, HTTP_BYTES = 256, 512
BANNER_WAIT = 1.0
CLIP = 256


class ScanError(ValueError):
    """Scan parameter is out of bounds (fail closed)."""


def check_timeout(value) -> float:
    if value is None:
        return DEFAULT_TIMEOUT
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        raise ScanError(f"timeout must be a number in {MIN_TIMEOUT}..{MAX_TIMEOUT}")
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ScanError(f"timeout must be in {MIN_TIMEOUT}..{MAX_TIMEOUT} seconds")
    return timeout


def check_workers(value) -> int:
    if value is None:
        return DEFAULT_WORKERS
    if not isinstance(value, int) or isinstance(value, bool) or not MIN_WORKERS <= value <= MAX_WORKERS:
        raise ScanError(f"workers must be an int in {MIN_WORKERS}..{MAX_WORKERS}")
    return value


@dataclass(frozen=True)
class ProbeResult:
    """One port's outcome."""

    port: int
    state: str          # open / closed / filtered / error
    banner: str = ""
    http_status: int = 0
    server_header: str = ""
    service: str = ""
    duration: float = 0.0
    error: str = ""


@dataclass(frozen=True)
class ScanRecord:
    """One host's outcome — the authorization travels with the result."""

    host: str
    reason: str
    results: tuple      # tuple[ProbeResult, ...], sorted by port
    duration: float


# -- single probe ----------------------------------------------------------


def probe(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Connect to one host:port and classify + fingerprint the outcome."""
    started = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        return ProbeResult(port, "closed", duration=_elapsed(started))
    except (TimeoutError, socket.timeout):
        return ProbeResult(port, "filtered", duration=_elapsed(started))
    except OSError as exc:
        return ProbeResult(port, "error", error=_clip(str(exc)), duration=_elapsed(started))

    try:
        banner, http_status, server_header = _grab(sock, timeout)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    service = guess_service(banner, server_header)
    return ProbeResult(
        port,
        "open",
        banner=banner,
        http_status=http_status,
        server_header=server_header,
        service=service,
        duration=_elapsed(started),
    )


def _grab(sock, timeout):
    """Passive banner first; if the service stays quiet, one HTTP probe."""
    banner, http_status, server_header = "", 0, ""
    try:
        sock.settimeout(min(timeout, BANNER_WAIT))
        data = sock.recv(BANNER_BYTES)
        if data:
            banner = _clean(data)
    except OSError:
        banner = ""
    if not banner:
        try:
            sock.settimeout(timeout)
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: cyberagent\r\n\r\n")
            data = sock.recv(HTTP_BYTES)
        except OSError:
            data = b""
        if data:
            text = _clean(data)
            http_status, server_header = _parse_http(text)
            if not http_status and text.startswith("HTTP/"):
                banner = text
    return banner, http_status, server_header


def _parse_http(text):
    """Status code + Server header from an HTTP response head (bounded)."""
    status, server = 0, ""
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    first = lines[0]
    if first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    for line in lines[1:20]:
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() == "server":
            server = value.strip()[:100]
            break
    return status, server


def _clean(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace").strip()
    return text[:CLIP]


def _elapsed(started) -> float:
    return round(time.monotonic() - started, 6)


def _clip(text, limit=CLIP):
    text = str(text)
    return text if len(text) <= limit else text[:limit] + "…"


# -- one scope entry -------------------------------------------------------


def scan_entry(entry: ScopeEntry, timeout: float = DEFAULT_TIMEOUT,
               workers: int = DEFAULT_WORKERS) -> ScanRecord:
    """Probe every allowlisted port of one scope entry, bounded pool."""
    timeout = check_timeout(timeout)
    workers = check_workers(workers)
    ports = sorted(entry.ports)
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe, entry.host, port, timeout) for port in ports]
        results = [future.result() for future in futures]
    results.sort(key=lambda r: r.port)
    return ScanRecord(
        host=entry.host,
        reason=entry.reason,
        results=tuple(results),
        duration=round(time.monotonic() - started, 6),
    )
