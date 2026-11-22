"""Loopback TCP helpers — real sockets on 127.0.0.1, no mocks."""

import socket
import threading


class LocalServer:
    """A real TCP server on 127.0.0.1:<ephemeral port>.

    greeting  bytes sent immediately on connect (banner-speaking services)
    respond   when True: wait for a request, then send ``response``
              (HTTP-shaped services that stay quiet until asked)
    """

    def __init__(self, greeting=b"", respond=False, response=b""):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(8)
        self._server.settimeout(0.05)
        self.port = self._server.getsockname()[1]
        self._greeting = greeting
        self._respond = respond
        self._response = response
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except (TimeoutError, socket.timeout, OSError):
                continue
            try:
                if self._greeting:
                    conn.sendall(self._greeting)
                conn.recv(1024)
                if self._respond:
                    conn.sendall(self._response)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self._server.close()


def closed_port():
    """A loopback port with nothing listening (bind, note, close)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port
