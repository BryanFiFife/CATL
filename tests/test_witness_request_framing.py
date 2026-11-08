"""Security regression: witness must not accept malformed HTTP framing.

Executable in CATL test tree with the actual tools/witness_service.py.
Uses a deterministic in-memory TLS peer, so no root or external effects.
"""
from __future__ import annotations
import hashlib
import io
import unittest
from pathlib import Path
import importlib.util

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location('catl_witness_framing_service', _ROOT/'tools'/'witness_service.py')
assert _SPEC is not None and _SPEC.loader is not None
_MOD = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MOD)

_CERT = b'catl-witness-framing-cert-fixture'
_PIN = hashlib.sha256(_CERT).hexdigest()
_VALID = b'{"ledger_id":"ledger-fixture","sequence":0,"head_mac":"GENESIS"}'

class _TLSRequest:
    def __init__(self, data):
        self._input = io.BytesIO(data)
        self._output = io.BytesIO()
    def makefile(self, mode, buffering=None):
        if mode == 'rb': return self._input
        if mode == 'wb': return self._output
        raise AssertionError('unexpected makefile mode')
    def sendall(self, buf):
        self._output.write(buf)
    def getpeercert(self, *, binary_form=False):
        assert binary_form
        return _CERT
    def close(self): pass
    @property
    def response(self):
        return self._output.getvalue()

class _Log:
    def __init__(self): self.calls = []
    def receive(self, head):
        self.calls.append(head)
        return dict(head)

class WitnessRequestFramingTests(unittest.TestCase):
    def _request(self, *, body=_VALID, declared_length=None, extra_headers=b''):
        log = _Log()
        n = len(body) if declared_length is None else declared_length
        raw = (b'POST /v1/witness HTTP/1.1\r\nHost: localhost\r\n'
               b'Content-Type: application/json\r\n'
               + extra_headers + f'Content-Length: {n}\r\n\r\n'.encode() + body)
        tls = _TLSRequest(raw)
        handler = _MOD.make_handler(log, client_cert_sha256=_PIN)
        handler(tls, ('127.0.0.1', 31337), object())
        code = int(tls.response.split(b'\r\n',1)[0].split()[1])
        return code, log.calls

    def test_complete_valid_body_advances_head(self):
        status, calls = self._request()
        self.assertEqual(status, 200)
        self.assertEqual(len(calls), 1)

    def test_short_body_never_advances_witness(self):
        status, calls = self._request(declared_length=len(_VALID)+10)
        self.assertEqual(status, 400)
        self.assertEqual(calls, [])

    def test_duplicate_content_type_never_advances_witness(self):
        status, calls = self._request(extra_headers=b'Content-Type: application/octet-stream\r\n')
        self.assertEqual(status, 400)
        self.assertEqual(calls, [])

    def test_identical_duplicate_content_type_also_denied(self):
        status, calls = self._request(extra_headers=b'Content-Type: application/json\r\n')
        self.assertEqual(status, 400)
        self.assertEqual(calls, [])

    def test_existing_duplicate_content_length_denied(self):
        status, calls = self._request(extra_headers=b'Content-Length: 5\r\n')
        self.assertEqual(status, 400)
        self.assertEqual(calls, [])

    def test_bounded_hostile_framing_mutations_never_advance_head(self):
        import random
        generator=random.Random(180811)
        malformed_lengths=[0,1,2,3,9,4096,4097,9999,-1,10000]
        malformed_lengths += [n for n in (generator.randrange(0,4098) for _ in range(90))
                              if n!=len(_VALID)]
        for n in malformed_lengths:
            with self.subTest(declared=n):
                code,calls=self._request(declared_length=n)
                self.assertNotEqual(code,200)
                self.assertEqual(calls,[])
        extra=(b'cOnTeNt-TyPe: application/json\r\n',
               b'Content-Type: application/octet-stream\r\n',
               b'tRaNsFeR-EnCoDiNg: chunked\r\n',
               b'Content-Length: 12\r\n',
               b'X-Padding: '+b'A'*4300+b'\r\n')
        for header in extra:
            with self.subTest(header=header[:35]):
                code,calls=self._request(extra_headers=header)
                self.assertNotEqual(code,200)
                self.assertEqual(calls,[])

    def test_existing_transfer_encoding_denied(self):
        status, calls = self._request(extra_headers=b'Transfer-Encoding: chunked\r\n')
        self.assertEqual(status, 400)
        self.assertEqual(calls, [])

if __name__ == '__main__':
    unittest.main()
