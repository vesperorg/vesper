"""
socksproxy.py - reach peers through Tor (or any SOCKS5 proxy), with nothing to install.

    python node.py --proxy socks5h://127.0.0.1:9050          (Tor's usual address)

Phase 4 hides which node FIRST broadcast a payment.  It does not hide the internet address of
each node from the peers it talks to.  With a proxy, every connection this node opens to a
peer - catching up, passing a stem on, broadcasting - goes through it, and so does the name
lookup ("socks5h": the proxy resolves host names, so not even a DNS question leaves this
computer).  Peers see Tor, never you.  Peers with .onion addresses can be reached this way.

What it does not do: hide a node that also ACCEPTS connections on a public address.  A node
meant to stay hidden keeps --host at 127.0.0.1 (the default); its own wallet still talks to it.
Taking part as a reachable .onion node needs Tor's own onion-service setting, outside Vesper.

Only the parts of SOCKS5 (RFC 1928) that Tor uses: no login, CONNECT, a host name or address.
"""

from __future__ import annotations

import functools
import http.client
import ipaddress
import socket
import ssl
import struct
import urllib.request
from urllib.parse import urlparse

REPLIES = {1: "general failure", 2: "not allowed by the proxy's rules", 3: "network unreachable",
           4: "host unreachable", 5: "connection refused", 6: "time to live expired",
           7: "command not supported", 8: "address type not supported"}


class ProxyError(OSError):
    pass


def parse_proxy(url: str):
    """("host", port, remote_dns) from socks5h://host:port (or socks5:// to resolve names here)."""
    parsed = urlparse(url if "://" in url else "socks5h://" + url)
    if parsed.scheme not in ("socks5", "socks5h") or not parsed.hostname or not parsed.port:
        raise ValueError("a proxy looks like socks5h://127.0.0.1:9050")
    return parsed.hostname, parsed.port, parsed.scheme == "socks5h"


def _recv(sock, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ProxyError("the proxy closed the connection")
        data += chunk
    return data


def connect(proxy, host: str, port: int, timeout=None):
    """A socket to host:port, opened by the proxy."""
    proxy_host, proxy_port, remote_dns = proxy
    sock = socket.create_connection((proxy_host, proxy_port), timeout)
    try:
        sock.sendall(b"\x05\x01\x00")                      # SOCKS5, one way to log in: none
        if _recv(sock, 2) != b"\x05\x00":
            raise ProxyError("the proxy wants a login; Vesper speaks only the plain kind Tor uses")
        try:
            ip = ipaddress.ip_address(host)
            where = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
        except ValueError:
            if remote_dns:
                name = host.encode("idna")
                where = b"\x03" + bytes([len(name)]) + name    # the proxy looks the name up
            else:
                where = b"\x01" + socket.inet_aton(socket.gethostbyname(host))
        sock.sendall(b"\x05\x01\x00" + where + struct.pack(">H", port))
        reply = _recv(sock, 4)
        if reply[0] != 5 or reply[1] != 0:
            raise ProxyError("the proxy could not reach %s:%d (%s)" % (host, port, REPLIES.get(reply[1], "error %d" % reply[1])))
        kind = reply[3]
        _recv(sock, 4 if kind == 1 else 16 if kind == 4 else _recv(sock, 1)[0])   # the address it used: not needed
        _recv(sock, 2)
        return sock
    except BaseException:
        sock.close()
        raise


class _Connection(http.client.HTTPConnection):
    def __init__(self, *args, proxy=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._proxy = proxy

    def connect(self):
        self.sock = connect(self._proxy, self.host, self.port, self.timeout)


class _SecureConnection(http.client.HTTPSConnection):
    def __init__(self, *args, proxy=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._proxy = proxy

    def connect(self):
        sock = connect(self._proxy, self.host, self.port, self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _Handler(urllib.request.HTTPHandler, urllib.request.HTTPSHandler):
    def __init__(self, proxy):
        urllib.request.HTTPHandler.__init__(self)
        urllib.request.HTTPSHandler.__init__(self, context=ssl.create_default_context())
        self._proxy = proxy

    def http_open(self, req):
        return self.do_open(functools.partial(_Connection, proxy=self._proxy), req)

    def https_open(self, req):
        return self.do_open(functools.partial(_SecureConnection, proxy=self._proxy), req, context=self._context)


def opener(proxy_url: str | None = None) -> urllib.request.OpenerDirector:
    """What the node opens peer addresses with.  With a proxy there is no way around it: the
    usual http_proxy settings are switched off and nothing is ever opened directly."""
    if not proxy_url:
        return urllib.request.build_opener()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _Handler(parse_proxy(proxy_url)))
