#!/usr/bin/env python3
"""Experimental rapidsnark proof-schema adapter, never a package modification.

Coordinates and public signals are unchanged. The pinned v4 key selects BN254;
the verifier's existing schema names that curve bn128. All adapter process/file
cost is inside the full presentation measurement.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    if len(sys.argv) != 5:
        raise ValueError('native adapter expects zkey witness proof public')
    raw = os.environ['PQID_NATIVE_RAW']
    r = subprocess.run([raw, *sys.argv[1:]], capture_output=True, check=False)
    if r.returncode:
        raise ValueError(f'native prover failed with status {r.returncode}; raw output withheld')
    proof_file = Path(sys.argv[3])
    proof = json.loads(proof_file.read_text())
    expected = {'pi_a', 'pi_b', 'pi_c', 'protocol'}
    keys = set(proof)
    if keys not in (expected, expected | {'curve'}):
        raise ValueError('native proof contains unexpected metadata keys')
    if proof['protocol'] != 'groth16':
        raise ValueError('native proof protocol is not groth16')
    if 'curve' in proof and proof['curve'] != 'bn128':
        raise ValueError('native proof curve differs from pinned BN254 configuration')
    action = 'added curve=bn128' if 'curve' not in proof else 'unchanged, curve already bn128'
    coordinate_before = json.dumps([proof['pi_a'], proof['pi_b'], proof['pi_c']])
    proof['curve'] = 'bn128'
    proof_file.write_text(json.dumps(proof, separators=(',', ':')))
    coordinate_after = json.dumps([proof['pi_a'], proof['pi_b'], proof['pi_c']])
    if coordinate_before != coordinate_after:
        raise ValueError('adapter coordinate invariant failed')
    Path(os.environ['PQID_NATIVE_ADAPTER_META']).write_text(json.dumps({
        'inputKeys': sorted(keys), 'outputKeys': sorted(proof), 'action': action,
        'coordinatesUnchanged': True, 'publicSignalsFileUntouched': True,
        'label': 'experimental native proof metadata adapter; not shipped',
    }) + '\n')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
