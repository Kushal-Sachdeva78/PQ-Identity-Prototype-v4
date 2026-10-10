"""Fail-closed and preservation tests for the isolated native metadata adapter."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('adapter', Path(__file__).with_name('native_adapter.py'))
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pqid37-adapter-test-')
        self.root = Path(self.temp.name)
        self.proof_file = self.root / 'proof.json'
        self.public_file = self.root / 'public.json'
        self.public_file.write_text('["1","2"]')
        self.metadata = self.root / 'metadata.json'
        self.proof = {'pi_a': ['1', '2', '1'], 'pi_b': [['1', '2'], ['3', '4'], ['1', '0']], 'pi_c': ['3', '4', '1'], 'protocol': 'groth16'}

    def tearDown(self):
        self.temp.cleanup()

    def call(self, proof, status=0):
        self.proof_file.write_text(json.dumps(proof))
        argv = ['adapter', 'key', 'witness', str(self.proof_file), str(self.public_file)]
        with patch.dict(os.environ, {'PQID_NATIVE_RAW': 'native', 'PQID_NATIVE_ADAPTER_META': str(self.metadata)}), patch.object(sys, 'argv', argv), patch.object(adapter.subprocess, 'run', return_value=subprocess.CompletedProcess([], status, b'', b'')):
            adapter.main()

    def test_adds_only_curve_and_preserves_coordinates_and_public_bytes(self):
        original_public = self.public_file.read_bytes()
        self.call(self.proof)
        result = json.loads(self.proof_file.read_text())
        self.assertEqual(result.pop('curve'), 'bn128')
        self.assertEqual(result, self.proof)
        self.assertEqual(self.public_file.read_bytes(), original_public)
        self.assertEqual(json.loads(self.metadata.read_text())['action'], 'added curve=bn128')

    def test_existing_correct_curve_remains(self):
        proof = dict(self.proof, curve='bn128')
        self.call(proof)
        self.assertEqual(json.loads(self.proof_file.read_text()), proof)

    def test_wrong_curve_rejected_without_metadata(self):
        with self.assertRaisesRegex(ValueError, 'curve differs'):
            self.call(dict(self.proof, curve='bls12381'))
        self.assertFalse(self.metadata.exists())

    def test_wrong_protocol_rejected(self):
        with self.assertRaisesRegex(ValueError, 'protocol'):
            self.call(dict(self.proof, protocol='plonk'))

    def test_unexpected_field_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unexpected metadata keys'):
            self.call(dict(self.proof, extra='unexpected'))

    def test_native_failure_rejected_without_metadata(self):
        with self.assertRaisesRegex(ValueError, 'status 7'):
            self.call(self.proof, status=7)
        self.assertFalse(self.metadata.exists())


if __name__ == '__main__':
    unittest.main()
