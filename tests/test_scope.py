"""Scope — the authorization contract. Fail closed on everything."""

import pytest

from cyberagent.scope import ScopeError, load_scope_file

VALID = """\
scope:
  - host: 127.0.0.1
    reason: local development services on my own machine
    ports:
      - 22
      - 8000-8008
    owner: numsalam
    expires: 2027-12-31
"""


def _load(tmp_path, text):
    path = tmp_path / "scope.yaml"
    path.write_text(text, encoding="utf-8")
    return load_scope_file(str(path))


def _rejects(tmp_path, text):
    with pytest.raises(ScopeError):
        _load(tmp_path, text)


# -- happy path ------------------------------------------------------------


def test_valid_scope(tmp_path):
    scope = _load(tmp_path, VALID)
    (entry,) = scope.entries
    assert entry.host == "127.0.0.1"
    assert entry.reason == "local development services on my own machine"
    assert entry.ports == frozenset({22, *range(8000, 8009)})
    assert entry.owner == "numsalam"
    assert entry.expires == "2027-12-31"
    assert entry.active("2027-12-31") is True
    assert entry.active("2028-01-01") is False


def test_permits_and_denials(tmp_path):
    scope = _load(tmp_path, VALID)
    day = "2026-11-21"
    assert scope.permits("127.0.0.1", 22, day) is True
    assert scope.permits("127.0.0.1", 8005, day) is True
    assert scope.permits("127.0.0.1", 23, day) is False
    assert scope.permits("10.0.0.1", 22, day) is False
    assert scope.why_denied("127.0.0.1", 22, day) is None
    assert scope.why_denied("127.0.0.1", 23, day) == (
        "port 23 is not in the allowlist for '127.0.0.1'"
    )
    assert "not in the scope" in scope.why_denied("10.0.0.1", 22, day)


def test_expired_entry_is_inactive(tmp_path):
    scope = _load(tmp_path, VALID)
    assert scope.permits("127.0.0.1", 22, "2028-01-01") is False
    assert "expired" in scope.why_denied("127.0.0.1", 22, "2028-01-01")
    assert scope.active_entries("2028-01-01") == ()
    assert len(scope.active_entries("2026-01-01")) == 1


def test_entry_for_is_case_insensitive(tmp_path):
    scope = _load(tmp_path, VALID.replace("127.0.0.1", "MyServer.Example.COM"))
    assert scope.entry_for("myserver.example.com") is not None
    assert scope.entry_for("MYSERVER.Example.com") is not None
    assert scope.entry_for("other.example.com") is None
    assert scope.entry_for(123) is None


def test_ipv6_host(tmp_path):
    scope = _load(tmp_path, VALID.replace("127.0.0.1", "::1"))
    assert scope.entries[0].host == "::1"
    assert scope.permits("::1", 22, "2026-11-21") is True


def test_no_expires_never_expires(tmp_path):
    scope = _load(tmp_path, VALID.split("    owner")[0])
    assert scope.entries[0].expires == ""
    assert scope.entries[0].active("2099-01-01") is True


def test_max_entries_boundary(tmp_path):
    lines = ["scope:"]
    for i in range(32):
        lines += [
            f"  - host: host{i}.example.com",
            "    reason: r",
            "    ports:",
            "      - 22",
        ]
    scope = _load(tmp_path, "\n".join(lines) + "\n")
    assert len(scope.entries) == 32


# -- fail closed -----------------------------------------------------------


def test_missing_file():
    with pytest.raises(ScopeError):
        load_scope_file("/nonexistent/scope.yaml")


def test_too_many_entries(tmp_path):
    lines = ["scope:"]
    for i in range(33):
        lines += [
            f"  - host: host{i}.example.com",
            "    reason: r",
            "    ports:",
            "      - 22",
        ]
    _rejects(tmp_path, "\n".join(lines) + "\n")


def test_reason_is_required(tmp_path):
    _rejects(tmp_path, "scope:\n  - host: a.com\n    ports:\n      - 22\n")
    _rejects(tmp_path, "scope:\n  - host: a.com\n    reason: ''\n    ports:\n      - 22\n")


def test_reason_too_long(tmp_path):
    text = VALID.replace("local development services on my own machine", "x" * 501)
    _rejects(tmp_path, text)


def test_port_rules(tmp_path):
    base = "scope:\n  - host: a.com\n    reason: r\n    ports:\n"
    _rejects(tmp_path, base + "      - 0\n")
    _rejects(tmp_path, base + "      - 65536\n")
    _rejects(tmp_path, base + "      - true\n")
    _rejects(tmp_path, base + "      - http\n")
    _rejects(tmp_path, base + "      - 80-22\n")
    _rejects(tmp_path, base + "      - 1-100\n")
    _rejects(tmp_path, base + "      - 22\n      - 22\n")
    _rejects(tmp_path, base + "      - 22\n      - 20-24\n")
    _rejects(tmp_path, base + "      - 1-64\n      - 65\n")
    _rejects(tmp_path, "scope:\n  - host: a.com\n    reason: r\n    ports: []\n")
    _rejects(tmp_path, "scope:\n  - host: a.com\n    reason: r\n")


def test_port_range_boundary_ok(tmp_path):
    base = "scope:\n  - host: a.com\n    reason: r\n    ports:\n"
    scope = _load(tmp_path, base + "      - 1-64\n")
    assert scope.entries[0].ports == frozenset(range(1, 65))


def test_expires_rules(tmp_path):
    _rejects(tmp_path, VALID.replace("2027-12-31", "2027/12/31"))
    _rejects(tmp_path, VALID.replace("2027-12-31", "2027-02-30"))
    _rejects(tmp_path, VALID.replace("2027-12-31", "not-a-date"))


def test_owner_too_long(tmp_path):
    _rejects(tmp_path, VALID.replace("numsalam", "x" * 101))


def test_unknown_keys(tmp_path):
    _rejects(tmp_path, VALID + "extra: 1\n")
    _rejects(tmp_path, VALID.replace("    owner: numsalam", "    extra: 1"))


def test_duplicate_host(tmp_path):
    text = VALID + "  - host: 127.0.0.1\n    reason: again\n    ports:\n      - 22\n"
    _rejects(tmp_path, text)


def test_scope_must_be_a_non_empty_list(tmp_path):
    _rejects(tmp_path, "scope: 5\n")
    _rejects(tmp_path, "other: 1\n")


def test_host_rules(tmp_path):
    base = "scope:\n  - host: {host}\n    reason: r\n    ports:\n      - 22\n"
    _rejects(tmp_path, base.format(host="-bad.example.com"))
    _rejects(tmp_path, base.format(host="a..b"))
    _rejects(tmp_path, base.format(host="x" * 254))
    _rejects(tmp_path, base.format(host=""))
