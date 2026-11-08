"""Witness source-IP admission tests. No claim of network-level DoS immunity."""
from __future__ import annotations
import ipaddress
import ssl
import unittest
from http.server import BaseHTTPRequestHandler
from unittest.mock import Mock
import importlib.util
from pathlib import Path
_SPEC = importlib.util.spec_from_file_location('catl_witness_service_test', Path(__file__).resolve().parents[1] / 'tools' / 'witness_service.py')
assert _SPEC and _SPEC.loader
_MOD = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MOD)
BoundedMTLSServer = _MOD.BoundedMTLSServer
validated_client_ips = _MOD.validated_client_ips

class WitnessSourceIPTests(unittest.TestCase):
    def test_explicit_ipv4_loopback_allow(self):
        self.assertEqual(validated_client_ips(['127.0.0.1']),
                         frozenset({ipaddress.ip_address('127.0.0.1')}))

    def test_valid_ipv6_loopback_and_public_addresses(self):
        allowed=validated_client_ips(['::1', '2001:4860:4860::8888'])
        self.assertEqual(len(allowed),2)

    def test_empty_missing_and_overlong_list_refused(self):
        for entries in ([],['127.0.0.1']*33):
            with self.subTest(entries=len(entries)),self.assertRaises(ValueError):
                validated_client_ips(entries)

    def test_invalid_networks_multicast_and_unspecified_rejected(self):
        bad=['0.0.0.0', '::', '255.255.255.255', '224.0.0.1', 'ff02::1',
             '127.0.0.0/8', '192.168.0.0/24','not-an-address',' 127.0.0.1', '']
        for address in bad:
            with self.subTest(address=address),self.assertRaises(ValueError):
                validated_client_ips([address])

    def test_rejects_unlisted_address_before_allocating_tls_worker(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server=BoundedMTLSServer(('127.0.0.1',0), BaseHTTPRequestHandler,
                   context=context,allowed_client_ips=validated_client_ips(['127.0.0.1']))
        try:
            fake_request=Mock()
            workers=Mock()
            workers.acquire.side_effect=AssertionError('worker exhausted by unlisted address')
            server._workers=workers
            server.process_request(fake_request, ('192.0.2.1',2345))
            fake_request.close.assert_called_once()
            workers.acquire.assert_not_called()
        finally:
            server.server_close()

    def test_invalid_peer_tuple_fails_before_worker(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server=BoundedMTLSServer(('127.0.0.1',0), BaseHTTPRequestHandler,
                  context=context, allowed_client_ips=validated_client_ips(['127.0.0.1']))
        try:
            for peer in ((),('invalid-host',1234)):
                fake=Mock(); server.process_request(fake,peer)
                fake.close.assert_called_once()
        finally:
            server.server_close()

    def test_cannot_start_without_pinned_source_address(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with self.assertRaisesRegex(ValueError, 'allowlist_required'):
            BoundedMTLSServer(('127.0.0.1',0), BaseHTTPRequestHandler,
                              context=context,allowed_client_ips=frozenset())

if __name__=='__main__':
    unittest.main()
