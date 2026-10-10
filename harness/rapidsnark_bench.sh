#!/usr/bin/env bash
# rapidsnark timing loop, run INSIDE WSL so each sample is the prover's
# subprocess wall time (process start + file I/O included) without any
# Windows<->WSL interop overhead — the paper's A.2 methodology.
#
# usage: rapidsnark_bench.sh <prover> <zkey> <wtns> <proof_out> <public_out> <N> <warmup> <samples_out>
set -euo pipefail
PROVER="$1"; ZKEY="$2"; WTNS="$3"; PROOF="$4"; PUBLIC="$5"; N="$6"; WARMUP="$7"; OUT="$8"

for ((i = 0; i < WARMUP; i++)); do
  "$PROVER" "$ZKEY" "$WTNS" "$PROOF" "$PUBLIC" > /dev/null
done

: > "$OUT"
for ((i = 0; i < N; i++)); do
  t0=$(date +%s%N)
  "$PROVER" "$ZKEY" "$WTNS" "$PROOF" "$PUBLIC" > /dev/null
  t1=$(date +%s%N)
  echo "$(( (t1 - t0) / 1000 ))" >> "$OUT"   # microseconds
done
