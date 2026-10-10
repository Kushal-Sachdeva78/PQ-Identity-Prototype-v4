#!/usr/bin/env bash
# PQ-Identity Groth16 phase-2 ceremony: make one contribution (macOS / Linux; also Git Bash).
#
# Usage (from the kit folder):
#   bash contribute.sh <input.zkey> "<Your Name>" <output.zkey> \
#        [--r1cs <circuit.r1cs> --ptau <file.ptau>]   verify the output afterwards
#        [--expect-sha256 <hex>]                       stop unless the input has the published sha256
#        [--extra-entropy]                             also type some random text (hidden, never saved)
#        [--no-receipt]
#
# What it does: checks Node.js, then runs contribute_core.mjs (snarkjs zkey contribute through the
# snarkjs library). Randomness comes from the OS generator and stays in memory; nothing secret is
# written to disk, to a log or to the command line. It prints your contribution hash.
set -euo pipefail

usage() {
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
}

if [ "$#" -lt 3 ]; then
  usage
  exit 2
fi
IN="$1"
NAME="$2"
OUT="$3"
shift 3
EXTRA=()
R1CS=""
PTAU=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --r1cs) R1CS="${2:?--r1cs needs a file}"; shift 2 ;;
    --ptau) PTAU="${2:?--ptau needs a file}"; shift 2 ;;
    --expect-sha256) EXTRA+=(--expect-in-sha256 "${2:?--expect-sha256 needs a value}"); shift 2 ;;
    --extra-entropy) EXTRA+=(--extra-entropy); shift ;;
    --no-receipt) EXTRA+=(--no-receipt); shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$HERE/contribute_core.mjs"
if [ ! -f "$CORE" ]; then
  echo "contribute_core.mjs is missing next to this script. Use the complete kit folder." >&2
  exit 2
fi
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js 20 or newer is needed. Install the LTS version from https://nodejs.org" >&2
  exit 2
fi
MAJOR="$(node -p "process.versions.node.split('.')[0]")"
if [ "$MAJOR" -lt 20 ]; then
  echo "Node.js 20 or newer is needed (found major version $MAJOR)." >&2
  exit 2
fi
case "$NAME" in
  *[\"\`\$\\]*) echo 'The name may not contain quotes, backticks, "$" or "\".' >&2; exit 2 ;;
esac
if [ ! -f "$IN" ]; then
  echo "Input zkey not found: $IN" >&2
  exit 2
fi
if [ -e "$OUT" ]; then
  echo "Output already exists (not overwritten): $OUT" >&2
  exit 2
fi
if [ -n "$R1CS" ] || [ -n "$PTAU" ]; then
  if [ -z "$R1CS" ] || [ -z "$PTAU" ]; then
    echo "Give both --r1cs and --ptau, or neither." >&2
    exit 2
  fi
  EXTRA+=(--r1cs "$R1CS" --ptau "$PTAU")
fi

echo "Starting the contribution (this takes from a few seconds to a few minutes)..."
set +e
node "$CORE" --in "$IN" --name "$NAME" --out "$OUT" ${EXTRA[@]+"${EXTRA[@]}"}
CODE=$?
set -e
if [ "$CODE" -ne 0 ]; then
  echo "The contribution did NOT complete (exit code $CODE). Do not send any output file; tell the coordinator." >&2
fi
exit "$CODE"
