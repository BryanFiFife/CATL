#!/usr/bin/env python3
"""Mutual-TLS append-only CATL witness endpoint. Run on an INDEPENDENT host.

Not installed automatically. Requires operator-provisioned TLS server key/cert,
trusted client CA and separate Ed25519 signing key. This service should never
share a privileged account or filesystem with the CATL broker.
"""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import hmac
import re
import json
import os
import socket
import ssl
import stat
import sys
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import threading
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from catl.witness_protocol import DurableWitnessLog,WitnessRejected,_unique_pairs

MAX_WITNESS_CONNECTIONS = 16
TLS_HANDSHAKE_TIMEOUT = 5.0
WITNESS_CLIENT_TIMEOUT = 10.0
MAX_WITNESS_REQUEST_HEADERS = 4096


def validated_client_ips(values: list[str] | tuple[str, ...]) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Explicitly pinned source addresses; not a replacement for a firewall.

    Reject unspecified/multicast/broadcast and CIDR ranges. A certificate
    remains mandatory even when the peer's IP is pinned.
    """
    if not values or len(values) > 32:
        raise ValueError('witness_client_ip_allowlist_required')
    output = set()
    for value in values:
        if not isinstance(value, str) or not value or '/' in value:
            raise ValueError('witness_client_ip_invalid')
        try:
            addr = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError('witness_client_ip_invalid') from exc
        if (addr.is_unspecified or addr.is_multicast or
                (isinstance(addr, ipaddress.IPv4Address) and addr.is_reserved)):
            raise ValueError('witness_client_ip_not_usable')
        output.add(addr)
    return frozenset(output)


class BoundedMTLSServer(ThreadingHTTPServer):
    """Bound TLS setup and active handlers, fail closed on untrusted peers.

    The TLS handshake happens before handler dispatch and is timeout-limited.
    The worker semaphore covers the total number of active HTTP handlers.
    The service must also be enclosed by OS-level cgroup/egress controls.
    """

    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False

    def __init__(self, address, handler, *, context: ssl.SSLContext, allowed_client_ips: frozenset):
        if not allowed_client_ips:
            raise ValueError('witness_client_ip_allowlist_required')
        self.allowed_client_ips = frozenset(allowed_client_ips)
        self._tls_context = context
        self._workers = threading.BoundedSemaphore(MAX_WITNESS_CONNECTIONS)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        # Reject unauthorised sources before consuming a TLS handshake worker.
        # The kernel's peer address is not proof of broker identity: mTLS and
        # the exact client certificate pin remain mandatory.
        try:
            peer_ip = ipaddress.ip_address(client_address[0])
        except (ValueError, IndexError, TypeError):
            request.close()
            return
        if peer_ip not in self.allowed_client_ips:
            request.close()
            return
        if not self._workers.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._workers.release()
            raise

    def process_request_thread(self, request, client_address):
        # TLS handshakes run in reserved bounded workers, NEVER on the server
        # accept loop. An unauthenticated peer holding a TCP socket open
        # cannot block all subsequent legitimate accepts.
        secure = None
        try:
            request.settimeout(TLS_HANDSHAKE_TIMEOUT)
            secure = self._tls_context.wrap_socket(request, server_side=True,
                                                   do_handshake_on_connect=True)
            secure.settimeout(WITNESS_CLIENT_TIMEOUT)
            super().process_request_thread(secure, client_address)
        except (ssl.SSLError, OSError):
            # Failed handshakes are routine untrusted network input.
            if secure is not None:
                secure.close()
            else:
                request.close()
        finally:
            self._workers.release()


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    path=Path(path)
    if path.is_symlink() or path.parent.is_symlink():raise PermissionError('witness_private_key_symlink')
    parent=path.parent.stat()
    if os.name!='posix' or parent.st_uid!=os.geteuid() or parent.st_mode & 0o077:
        raise PermissionError('witness_private_key_directory_insecure')
    st=path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077 or st.st_nlink!=1:
        raise PermissionError('witness_private_key_permissions_invalid')
    from cryptography.hazmat.primitives import serialization
    key=serialization.load_pem_private_key(path.read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey):raise ValueError('witness_private_key_not_ed25519')
    return key


def make_handler(log: DurableWitnessLog, *, client_cert_sha256: str):
    if not isinstance(client_cert_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', client_cert_sha256):
        raise ValueError('witness_client_certificate_pin_invalid')
    class WitnessHandler(BaseHTTPRequestHandler):
        # Never keep a worker reserved for an idle persistent connection.
        protocol_version='HTTP/1.0'
        def log_message(self, fmt, *args):
            # Do not log payload, credentials or client certificate materials.
            return
        def do_GET(self):
            self.send_error(405)
        def do_POST(self):
            self.close_connection = True
            # Reject ambiguous framing before reading or parsing any body.
            if (self.headers.get_all('Transfer-Encoding') or
                    self.headers.get_all('Content-Length') is None or
                    len(self.headers.get_all('Content-Length')) != 1 or
                    len(self.headers.get_all('Content-Type') or ()) > 1 or
                    len(str(self.headers)) > MAX_WITNESS_REQUEST_HEADERS):
                self.send_error(400); return
            peer = self.request.getpeercert(binary_form=True)
            if (self.path != '/v1/witness' or not peer or
                    not hmac.compare_digest(hashlib.sha256(peer).hexdigest(), client_cert_sha256)):
                self.send_error(403); return
            length=self.headers.get('Content-Length')
            if not length or len(length)>4 or not length.isdigit() or not 1<=int(length)<=4096:
                self.send_error(413);return
            if self.headers.get('Content-Type','').split(';')[0].lower()!='application/json':
                self.send_error(415);return
            try:
                data=self.rfile.read(int(length))
                if len(data) != int(length):
                    self.send_error(400); return
                head=json.loads(data,object_pairs_hook=_unique_pairs)
                reply=log.receive(head)
                body=json.dumps(reply,sort_keys=True,separators=(',',':')).encode()
            except (ValueError,UnicodeError,WitnessRejected,TypeError):
                self.send_error(400);return
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return WitnessHandler


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',type=Path,required=True)
    parser.add_argument('--signing-key',type=Path,required=True)
    parser.add_argument('--tls-cert',type=Path,required=True)
    parser.add_argument('--tls-key',type=Path,required=True)
    parser.add_argument('--client-ca',type=Path,required=True)
    parser.add_argument('--client-cert-sha256',required=True,
                        help='Pinned SHA-256 of exact DER client certificate (lowercase hex)')
    parser.add_argument('--allow-client-ip', action='append', required=True,
                        help='Exact expected broker source IP (repeatable; no CIDR)')
    parser.add_argument('--listen','-l',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=9443)
    a=parser.parse_args()
    if os.name!='posix' or os.geteuid()==0:raise PermissionError('witness_must_run_nonroot_posix')
    if not 1024<=a.port<=65535:raise ValueError('invalid_witness_port')
    log=DurableWitnessLog(a.database,load_signing_key(a.signing_key))
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(a.client_ca))
    ctx.load_cert_chain(certfile=str(a.tls_cert),keyfile=str(a.tls_key))
    allowed_ips = validated_client_ips(a.allow_client_ip)
    server=BoundedMTLSServer((a.listen,a.port),
                            make_handler(log, client_cert_sha256=a.client_cert_sha256),
                            context=ctx, allowed_client_ips=allowed_ips)
    server.serve_forever(poll_interval=.3)

if __name__=='__main__':main()
