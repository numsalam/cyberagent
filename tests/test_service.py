"""Service heuristics — the deterministic signature table."""

from cyberagent.service import guess_service


def test_prefix_rules():
    assert guess_service("SSH-2.0-OpenSSH_9.6") == "ssh"
    assert guess_service("HTTP/1.1 200 OK") == "http"
    assert guess_service("+OK POP3 server ready") == "pop3"
    assert guess_service("REDIS ready") == "redis"
    assert guess_service("mysql native protocol") == "mysql"
    assert guess_service("Jenkins-Cookie: xyz") == "jenkins"


def test_greeting_rules():
    assert guess_service("220 FTP server ready") == "ftp"
    assert guess_service("220 mail ESMTP ready") == "smtp"
    assert guess_service("220 mail SMTP ready") == "smtp"
    assert guess_service("220 IMAP4rev2 ready") == "imap"
    assert guess_service("* OK IMAP4rev2 ready") == "imap"


def test_server_header_rules():
    assert guess_service("", "nginx/1.24.0") == "http (nginx)"
    assert guess_service("", "Apache/2.4.57") == "http (apache)"
    assert guess_service("", "Caddy") == "http (caddy)"
    assert guess_service("", "Microsoft-IIS/10.0") == "http (iis)"
    assert guess_service("", "Coyote/1.1 Tomcat") == "http (tomcat)"
    assert guess_service("", "Jetty(9.4)") == "http (jetty)"
    assert guess_service("", "gunicorn/21.2") == "http (gunicorn)"
    assert guess_service("", "uvicorn") == "http (uvicorn)"
    assert guess_service("", "Traefik") == "http (traefik)"
    assert guess_service("", "weird-server/1.0") == "http"


def test_unknown_stays_unknown():
    assert guess_service("", "") == ""
    assert guess_service("garbage banner", "") == ""
    assert guess_service("220 ready", "") == ""


def test_banner_wins_over_header():
    assert guess_service("SSH-2.0-x", "nginx") == "ssh"
