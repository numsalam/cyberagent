"""Scope — the authorization contract. Fail closed.

A scope file lists exactly what may be scanned and why::

    scope:
      - host: 127.0.0.1
        reason: local development services on my own machine
        ports:
          - 22
          - 8000-8008        # inclusive range
        owner: numsalam      # optional
        expires: 2027-12-31  # optional, YYYY-MM-DD (UTC)

Rules, all enforced eagerly at load time:

- no scope file → no scanning (the engine refuses; it never defaults)
- every entry carries a ``reason`` — authorization is designed, not assumed
- ports are an allowlist (≤ 64 per host); the scanner never sweeps
- expired entries go inactive; ``permits`` returns False for them
- unknown keys, duplicate hosts, duplicate ports, bad dates all reject
"""

from __future__ import annotations

import datetime
import ipaddress
import re
import time
from dataclasses import dataclass

from . import yaml_min

__all__ = ["ScopeError", "ScopeEntry", "Scope", "load_scope_file", "today_utc"]


class ScopeError(ValueError):
    """Scope file is invalid (fail closed)."""


HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")
PORT_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")
DATE_FORMAT = "%Y-%m-%d"

MAX_ENTRIES = 32
MAX_PORTS = 64
MAX_REASON = 500
MAX_OWNER = 100

_ALLOWED_KEYS = {"host", "reason", "ports", "expires", "owner"}


def today_utc() -> str:
    """Current UTC date as YYYY-MM-DD (the expiry comparison basis)."""
    return time.strftime(DATE_FORMAT, time.gmtime())


# -- models ----------------------------------------------------------------


@dataclass(frozen=True)
class ScopeEntry:
    """One authorized host: why, which ports, until when."""

    host: str
    reason: str
    ports: frozenset   # frozenset[int]
    expires: str = ""  # "" or YYYY-MM-DD
    owner: str = ""

    def active(self, day: str = "") -> bool:
        """False once the expiry date has passed (UTC date compare)."""
        if not self.expires:
            return True
        return (day or today_utc()) <= self.expires


@dataclass(frozen=True)
class Scope:
    """The full authorization contract."""

    entries: tuple  # tuple[ScopeEntry, ...]

    def entry_for(self, host: str):
        """The entry for *host*, or None (hostnames case-insensitive)."""
        if not isinstance(host, str):
            return None
        key = host.strip().lower()
        for entry in self.entries:
            if entry.host == key:
                return entry
        return None

    def permits(self, host, port, day: str = "") -> bool:
        """True only when host is in scope, active, and port is allowlisted."""
        entry = self.entry_for(host)
        if entry is None or not entry.active(day):
            return False
        return port in entry.ports

    def why_denied(self, host, port, day: str = ""):
        """None when permitted; a human reason string when denied."""
        entry = self.entry_for(host)
        if entry is None:
            return f"host {host!r} is not in the scope"
        if not entry.active(day):
            return f"entry for {host!r} expired on {entry.expires}"
        if port not in entry.ports:
            return f"port {port} is not in the allowlist for {host!r}"
        return None

    def active_entries(self, day: str = ""):
        """Entries that have not expired, in file order."""
        return tuple(e for e in self.entries if e.active(day))


# -- field validators ------------------------------------------------------


def _host(value, source):
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        raise ScopeError(f"{source}: host must be 1..253 chars")
    host = value.strip().lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) > 127:
        raise ScopeError(f"{source}: host has too many labels")
    for label in labels:
        if (
            not HOSTNAME_LABEL_RE.match(label)
            or label.startswith("-")
            or label.endswith("-")
        ):
            raise ScopeError(f"{source}: host must be an IP address or hostname")
    return host


def _ports(value, source):
    if not isinstance(value, list) or not value:
        raise ScopeError(f"{source}: ports must be a non-empty list")
    out = set()
    for i, item in enumerate(value):
        where = f"{source}: ports[{i}]"
        if isinstance(item, bool) or not isinstance(item, (int, str)):
            raise ScopeError(f"{where}: must be a port (1..65535) or range 'lo-hi'")
        if isinstance(item, int):
            candidates = (item,)
        else:
            match = PORT_RANGE_RE.match(item)
            if not match:
                raise ScopeError(f"{where}: bad range {item!r} (expected 'lo-hi')")
            lo, hi = int(match.group(1)), int(match.group(2))
            if lo > hi:
                raise ScopeError(f"{where}: range must be ascending")
            if hi - lo + 1 > MAX_PORTS:
                raise ScopeError(f"{where}: range exceeds {MAX_PORTS} ports")
            candidates = range(lo, hi + 1)
        for port in candidates:
            if not 1 <= port <= 65535:
                raise ScopeError(f"{where}: port {port} outside 1..65535")
            if port in out:
                raise ScopeError(f"{where}: duplicate port {port}")
            out.add(port)
        if len(out) > MAX_PORTS:
            raise ScopeError(f"{source}: at most {MAX_PORTS} ports per entry")
    return frozenset(out)


def _expires(value, source):
    if value is None:
        return ""
    if isinstance(value, datetime.date):
        # full YAML parsers turn unquoted 2027-12-31 into a date object;
        # coerce back so both parsers behave identically
        value = value.isoformat()
    if not isinstance(value, str):
        raise ScopeError(f"{source}: expires must be YYYY-MM-DD")
    try:
        time.strptime(value, DATE_FORMAT)
    except ValueError:
        raise ScopeError(f"{source}: expires must be YYYY-MM-DD") from None
    return value


def _entry(data, source):
    if not isinstance(data, dict):
        raise ScopeError(f"{source}: must be a mapping")
    unknown = set(data) - _ALLOWED_KEYS
    if unknown:
        raise ScopeError(f"{source}: unknown keys {sorted(unknown)}")
    host = _host(data.get("host"), source)
    reason = data.get("reason")
    if not isinstance(reason, str) or not 1 <= len(reason) <= MAX_REASON:
        raise ScopeError(f"{source}: reason is required (1..{MAX_REASON} chars)")
    ports = _ports(data.get("ports"), source)
    expires = _expires(data.get("expires"), source)
    owner = data.get("owner")
    if owner is None:
        owner = ""
    if not isinstance(owner, str) or len(owner) > MAX_OWNER:
        raise ScopeError(f"{source}: owner must be 0..{MAX_OWNER} chars")
    return ScopeEntry(host, reason, ports, expires, owner)


# -- loading ---------------------------------------------------------------


def load_scope_file(path: str) -> Scope:
    """Load and fully validate a scope file (top-level ``scope:`` list)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise ScopeError(f"cannot read {path}: {exc}") from exc
    try:
        data = yaml_min.loads(text)
    except (yaml_min.YamlMinError, ValueError) as exc:
        raise ScopeError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict) or "scope" not in data:
        raise ScopeError(f"{path}: expected a top-level 'scope' list")
    extra = set(data) - {"scope"}
    if extra:
        raise ScopeError(f"{path}: unknown top-level keys {sorted(extra)}")
    items = data["scope"]
    if not isinstance(items, list) or not items:
        raise ScopeError(f"{path}: 'scope' must be a non-empty list")
    if len(items) > MAX_ENTRIES:
        raise ScopeError(f"{path}: at most {MAX_ENTRIES} entries")
    entries = []
    seen = set()
    for i, item in enumerate(items):
        entry = _entry(item, f"{path}: scope[{i}]")
        if entry.host in seen:
            raise ScopeError(f"{path}: duplicate host {entry.host!r}")
        seen.add(entry.host)
        entries.append(entry)
    return Scope(tuple(entries))
