"""CATL parser regression against the authentic source, pinned to the release SHA.

No agent, external backend, cloud/API, GitHub Actions, or real effects involved.
"""
import hashlib
import json
import math
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from catl.crypto import canonical, hmac_hex, parse_json, strict_loads, MAX_WIRE_BYTES


class StrictJSONNumberTests(unittest.TestCase):
    def test_normal_finite_exponents_still_supported(self):
        for token in ['0.0', '-0.0', '1e308', '-1e308', '1E+100', '6.022e23', '1.25e-8', '12.3']:
            with self.subTest(token=token):
                val = strict_loads('{"value":' + token + '}')['value']
                self.assertTrue(math.isfinite(val))

    def test_overflow_values_rejected_at_top_level(self):
        for token in ['1e309', '1e999', '-1e999', '1E+9999', '-9.99e999999']:
            with self.subTest(token=token):
                with self.assertRaisesRegex(ValueError, 'non_finite_json_number'):
                    strict_loads(token)

    def test_overflow_rejected_in_nested_arguments(self):
        for token in ['1e309', '-1e309', '1.4E999999']:
            with self.subTest(token=token):
                msg = '{"jsonrpc":"2.0","method":"tools/call","id":7,"params":{"arguments":{"amount":['+token+']}}}'
                with self.assertRaisesRegex(ValueError, 'non_finite_json_number'):
                    parse_json(msg.encode())

    def test_nonzero_underflow_to_zero_is_rejected(self):
        for token in ['1e-9999', '-1e-999999', '9.99E-9000', '0.00001e-900']:
            with self.subTest(token=token):
                with self.assertRaisesRegex(ValueError, 'json_number_underflow'):
                    strict_loads('{"value":' + token + '}')

    def test_true_zero_exponents_still_accepted(self):
        for token in ['0e-99999', '-0.0000e-999', '0.0', '-0e999']:
            with self.subTest(token=token):
                self.assertEqual(strict_loads('{"value":' + token + '}')['value'], 0.0)

    def test_underflow_does_not_pass_a_zero_amount_boundary(self):
        payload = b'{"amount":1e-10000}'
        with self.assertRaisesRegex(ValueError, 'json_number_underflow'):
            parse_json(payload)

    def test_literal_nan_inf_still_rejected(self):
        for token in ['NaN', 'Infinity', '-Infinity']:
            with self.subTest(token=token):
                with self.assertRaisesRegex(ValueError, 'invalid_constant'):
                    strict_loads('{"x":' + token + '}')

    def test_duplicate_keys_still_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate_json_key'):
            strict_loads('{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError, 'duplicate_json_key'):
            strict_loads('{"x":{"y":1,"y":2}}')

    def test_valid_wire_message_is_unchanged(self):
        msg = {'jsonrpc':'2.0', 'id':9, 'method':'ping', 'params':{'limit':12.5, 'exp':1.1e30}}
        self.assertEqual(parse_json(json.dumps(msg).encode()), msg)

    def test_parse_json_object_only_and_size_bound(self):
        with self.assertRaisesRegex(ValueError, 'expected_object'):
            parse_json(b'[1]')
        with self.assertRaisesRegex(ValueError, 'message_too_large'):
            parse_json(b' ' * (MAX_WIRE_BYTES + 1))

    def test_canonical_and_hmac_determinism_preserved(self):
        a = {'z':1,'a':{'m':[1,2.5],'x':'hello'}}
        b = {'a':{'x':'hello','m':[1,2.5]},'z':1}
        self.assertEqual(canonical(a),canonical(b))
        self.assertEqual(hmac_hex(b'k'*32,a),hmac_hex(b'k'*32,b))

    def test_finite_roundtrip_property(self):
        for exponent in range(-100,301,13):
            value=1.5 * 10.0**exponent
            if not math.isfinite(value):continue
            s=json.dumps({'number':value},allow_nan=False)
            self.assertEqual(strict_loads(s)['number'],value)

    def test_reject_nan_inf_in_all_input_positions(self):
        for value in ['1e309', '-1e309', 'NaN', 'Infinity']:
            for doc in ['['+value+']','{"a":{"b":'+value+'}}','{"a":['+value+']}']:
                with self.subTest(doc=doc),self.assertRaises(ValueError):
                    strict_loads(doc)




if __name__ == '__main__':
    unittest.main()
