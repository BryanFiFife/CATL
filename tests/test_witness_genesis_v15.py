"""Reject impossible witness heads; tests run against actual CATL module when installed.

The first sequence in an anchored CATL ledger has head_mac='GENESIS';
all subsequent snapshots have 64-char hex MACs. Never authenticate a
non-genesis sequence with a GENESIS marker (or vice versa).
"""
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from catl.witness_protocol import (
    DurableWitnessLog, InMemoryWitnessLog, WitnessClient,
    WitnessRejected, witness_sign_head, verify_witness,
)

class TestWitnessGenesisInvariant(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.ledger = 'ledger-genesis-v15'

    def head(self, sequence, head_mac):
        return {'ledger_id': self.ledger, 'sequence': sequence,
                'head_mac': head_mac}

    def test_genesis_zero_is_valid(self):
        head = self.head(0, 'GENESIS')
        self.assertEqual(witness_sign_head(self.key, head)['sequence'], 0)
        client = WitnessClient(self.key.public_key(),
                               InMemoryWitnessLog(self.key).receive)
        self.assertEqual(client.witness(head).head_mac, 'GENESIS')

    def test_positive_sequence_rejects_genesis(self):
        for sequence in (1, 99, 2**63 - 1):
            with self.subTest(sequence=sequence), self.assertRaisesRegex(
                    WitnessRejected, 'head_fields_invalid'):
                witness_sign_head(self.key, self.head(sequence, 'GENESIS'))

    def test_zero_sequence_rejects_non_genesis(self):
        with self.assertRaisesRegex(WitnessRejected, 'head_fields_invalid'):
            witness_sign_head(self.key, self.head(0, 'f'*64))

    def test_non_genesis_sequence_is_valid(self):
        head = self.head(3, 'a'*64)
        receipt = witness_sign_head(self.key, head)
        verified = verify_witness(self.key.public_key(), receipt, expected=head)
        self.assertEqual(verified.sequence, 3)

    def test_inmemory_log_rejects_impossible_heads_without_poisoning(self):
        log = InMemoryWitnessLog(self.key)
        for head in (self.head(20, 'GENESIS'), self.head(0, 'a'*64)):
            with self.assertRaises(WitnessRejected): log.receive(head)
        self.assertEqual(log.receive(self.head(0, 'GENESIS'))['sequence'], 0)
        self.assertEqual(log.receive(self.head(1, 'a'*64))['sequence'], 1)

    def test_durable_log_rejects_impossible_heads_without_poisoning(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'witness.sqlite'
            log = DurableWitnessLog(path, self.key)
            for head in (self.head(20, 'GENESIS'), self.head(0, 'f'*64)):
                with self.assertRaises(WitnessRejected): log.receive(head)
            self.assertEqual(log.receive(self.head(0, 'GENESIS'))['sequence'], 0)
            restarted = DurableWitnessLog(path, self.key)
            self.assertEqual(restarted.receive(self.head(1, 'a'*64))['sequence'], 1)

if __name__ == '__main__': unittest.main()
