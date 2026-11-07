#!/usr/bin/env python3
"""Mutual-TLS append-only CATL witness endpoint. Run on an INDEPENDENT host.

Not installed automatically. Requires operator-provisioned TLS server key/cert,
trusted client CA and separate Ed25519 signing key. This service should never
share a privileged account or filesystem with the CATL broker.
"""
from __future__ import annotations
import argparse
import json
import os
import socket
import ssl
import stat
import sys
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from catl.witness_protocol import DurableWitnessLog,WitnessRejected,_unique_pairs


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


def make_handler(log: DurableWitnessLog):
    class WitnessHandler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self, fmt, *args):
            # Do not log payload, credentials or client certificate materials.
            return
        def do_GET(self):
            self.send_error(405)
        def do_POST(self):
            if self.path!='/v1/witness' or not self.request.getpeercert():
                self.send_error(403);return
            length=self.headers.get('Content-Length')
            if not length or not length.isdigit() or not 1<=int(length)<=4096:
                self.send_error(413);return
            if self.headers.get('Content-Type','').split(';')[0].lower()!='application/json':
                self.send_error(415);return
            try:
                data=self.rfile.read(int(length))
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
    server=ThreadingHTTPServer((a.listen,a.port),make_handler(log))
    server.socket=ctx.wrap_socket(server.socket,server_side=True)
    server.serve_forever(poll_interval=.3)

if __name__=='__main__':main()
