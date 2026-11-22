"""Service heuristics — deterministic banner → service guesses.

A tiny signature table applied in fixed order. No sends, no deps, no
guessing beyond the table: unknown banners stay unknown ("" in reports).
"""

from __future__ import annotations

__all__ = ["guess_service"]

_PREFIX_RULES = (
    ("ssh", "ssh-"),
    ("http", "http/"),
    ("pop3", "+ok"),
    ("redis", "redis"),
    ("mysql", "mysql"),
    ("jenkins", "jenkins"),
)

# 220-class greetings identify themselves in the banner text
_GREETING_RULES = (
    ("ftp", "ftp"),
    ("smtp", "esmtp"),
    ("smtp", "smtp"),
    ("imap", "imap"),
)

_SERVER_KEYS = (
    "nginx",
    "apache",
    "caddy",
    "iis",
    "tomcat",
    "jetty",
    "gunicorn",
    "uvicorn",
    "traefik",
)


def guess_service(banner: str, server_header: str = "") -> str:
    """Best deterministic guess for a banner (+ optional HTTP Server header)."""
    low = (banner or "").lower()
    for service, prefix in _PREFIX_RULES:
        if low.startswith(prefix):
            return service
    if low.startswith("220") or low.startswith("* ok"):
        for service, needle in _GREETING_RULES:
            if needle in low:
                return service
    header = (server_header or "").lower()
    if header:
        for key in _SERVER_KEYS:
            if key in header:
                return f"http ({key})"
        return "http"
    return ""
