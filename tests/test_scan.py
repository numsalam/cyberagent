"""Scanner — real loopback sockets; classification is deterministic."""

import pytest

import cyberagent.scan as scan_mod
from cyberagent.scan import ScanError, check_timeout, check_workers, probe, scan_entry
from cyberagent.scope import ScopeEntry

from loopback import LocalServer, closed_port


def test_open_port_with_ssh_banner():
    server = LocalServer(greeting=b"SSH-2.0-OpenSSH_9.6\r\n")
    try:
        result = probe("127.0.0.1", server.port, timeout=0.5)
    finally:
        server.close()
    assert result.state == "open"
    assert result.banner == "SSH-2.0-OpenSSH_9.6"
    assert result.service == "ssh"
    assert result.http_status == 0
    assert result.server_header == ""
    assert result.error == ""
    assert result.duration >= 0.0


def test_open_port_with_http_head_probe():
    response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n"
    server = LocalServer(respond=True, response=response)
    try:
        result = probe("127.0.0.1", server.port, timeout=0.5)
    finally:
        server.close()
    assert result.state == "open"
    assert result.http_status == 200
    assert result.server_header == "nginx/1.24.0"
    assert result.service == "http (nginx)"
    assert result.banner == ""


def test_closed_port():
    result = probe("127.0.0.1", closed_port(), timeout=0.5)
    assert result.state == "closed"
    assert result.banner == ""
    assert result.service == ""


def test_refused_maps_to_closed(monkeypatch):
    def refused(*args, **kwargs):
        raise ConnectionRefusedError

    monkeypatch.setattr(scan_mod.socket, "create_connection", refused)
    assert probe("127.0.0.1", 9999).state == "closed"


def test_timeout_maps_to_filtered(monkeypatch):
    def timed_out(*args, **kwargs):
        raise TimeoutError

    monkeypatch.setattr(scan_mod.socket, "create_connection", timed_out)
    result = probe("10.255.255.1", 9999)
    assert result.state == "filtered"


def test_oserror_maps_to_error(monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("name resolution failed")

    monkeypatch.setattr(scan_mod.socket, "create_connection", broken)
    result = probe("no.such.host.invalid", 80)
    assert result.state == "error"
    assert "name resolution failed" in result.error


def test_check_timeout_bounds():
    assert check_timeout(None) == 2.0
    assert check_timeout(0.1) == 0.1
    assert check_timeout(10.0) == 10.0
    assert check_timeout("1.5") == 1.5
    with pytest.raises(ScanError):
        check_timeout(0.05)
    with pytest.raises(ScanError):
        check_timeout(10.1)
    with pytest.raises(ScanError):
        check_timeout("fast")


def test_check_workers_bounds():
    assert check_workers(None) == 8
    assert check_workers(1) == 1
    assert check_workers(32) == 32
    with pytest.raises(ScanError):
        check_workers(0)
    with pytest.raises(ScanError):
        check_workers(33)
    with pytest.raises(ScanError):
        check_workers(True)
    with pytest.raises(ScanError):
        check_workers(2.0)


def test_scan_entry_probes_the_allowlist_sorted():
    server = LocalServer(greeting=b"SSH-2.0-Test\r\n")
    try:
        entry = ScopeEntry(
            host="127.0.0.1",
            reason="test",
            ports=frozenset({server.port, closed_port()}),
        )
        record = scan_entry(entry, timeout=0.5, workers=2)
    finally:
        server.close()
    assert record.host == "127.0.0.1"
    assert record.reason == "test"
    assert len(record.results) == 2
    ports = [r.port for r in record.results]
    assert ports == sorted(ports)
    by_port = {r.port: r for r in record.results}
    assert by_port[server.port].state == "open"
    assert by_port[server.port].service == "ssh"
    assert record.duration >= 0.0
