#!/usr/bin/env bash
# End-to-end demo: build a synthetic memory image with planted keys, scan it,
# and show the recovered + proven key.  Run from the repository root.
set -euo pipefail

BUILD=${BUILD:-build}
IMG=${IMG:-/tmp/keyhunt-demo.raw}
MAN=${MAN:-/tmp/keyhunt-demo.json}
SAMPLE=${SAMPLE:-/tmp/keyhunt-demo.locked}
MIB=${MIB:-128}

cmake -B "$BUILD" -DOPENSSL_ROOT_DIR="$(brew --prefix 2>/dev/null || echo /usr)" >/dev/null
cmake --build "$BUILD" -j >/dev/null

echo "== generating ${MIB} MiB synthetic memory image"
"$BUILD/keyhunt-genimg" -o "$IMG" -m "$MAN" --mib "$MIB" --sample "$SAMPLE"

echo
echo "== scanning (this is the real tool; progress on stderr)"
"$BUILD/keyhunt" scan "$IMG" \
    --sample "$SAMPLE" \
    --jsonl /tmp/keyhunt-demo.jsonl \
    --outdir /tmp/keyhunt-demo-out \
    --report /tmp/keyhunt-demo-report.txt \
    --threads "$(sysctl -n hw.ncpu 2>/dev/null || nproc)"

echo
echo "== proven keys (decrypt the sample):"
grep -A1 VERIFIED /tmp/keyhunt-demo-report.txt | head -20 || true

echo
echo "== recovered key files:"
ls -l /tmp/keyhunt-demo-out/keys 2>/dev/null | head || true

echo
echo "== evaluation against ground truth:"
python3 "$(dirname "$0")/evaluate.py" --mib "$MIB" --threads "$(sysctl -n hw.ncpu 2>/dev/null || nproc)" \
    --genimg "$BUILD/keyhunt-genimg" --keyhunt "$BUILD/keyhunt" 2>/dev/null || true
